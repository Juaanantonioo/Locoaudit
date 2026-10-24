"use strict";

/** Contexto de los secretos y configuraciones que encuentra Trivy: decide si le piden algo al usuario.
 *  La mayoría de secretos de un home son claves de ejemplo o sesiones de otras aplicaciones. */

/** Almacenes de credenciales, relativos al home: la aplicación guarda ahí la sesión a propósito. */
const CREDENTIAL_STORES = [
  ".ssh/", ".gnupg/", ".aws/", ".azure/", ".kube/", ".docker/", ".codex/",
  ".config/gcloud/", ".config/gh/", ".config/github-copilot/", ".config/hub",
  ".netrc", ".git-credentials", ".npmrc", ".pypirc", ".m2/settings.xml", ".m2/settings-security.xml",
];

/** Segmentos de ruta que delatan software instalado por otros: dependencias, extensiones, cachés de herramientas. */
const THIRD_PARTY_SEGMENTS = new Set([
  "node_modules", "bower_components", "vendor", "site-packages", "dist-packages", ".venv", "venv",
  "extensions", "marketplaces", ".m2", ".gradle", ".cargo", ".rustup", ".nvm", ".pyenv", ".npm", ".yarn",
  "Pods", ".terraform", "go", "Library", ".local",
]);

/** Segmentos de ruta de datos de prueba o de ejemplo. */
const TEST_SEGMENTS = new Set([
  "test", "tests", "__tests__", "spec", "specs", "fixtures", "testdata", "mocks", "__mocks__",
  "samples", "examples", "payloads", "bench", "benches", "benchmarks",
]);

/** Repositorios de pruebas de seguridad que traen credenciales de ejemplo a propósito. */
const SECURITY_CORPORA = new Set([
  "nuclei-templates", "seclists", "payloadsallthethings", "metasploit-framework", "exploitdb",
  "exploit-database", "wordlists",
]);

/** Carpetas que se sincronizan con un servicio en la nube: lo que hay en ellas sale del equipo. */
const SYNCED_RE = /(^|\/)(nextcloud|owncloud|dropbox|onedrive[^/]*|google ?drive|googledrive|icloud ?drive|mobile documents|cloudstorage)(\/|$)/i;

/** Ficheros de código compilado o empaquetado: lo que encuentra Trivy dentro viene de una dependencia. */
const BUNDLE_RE = /\.(min\.js|bundle\.js|bundle|chunk\.js|js\.map|map)$/i;

/** Fichero de test por su nombre. */
const TEST_FILE_RE = /(\.|_)(spec|test)\.[a-z0-9]+$|^test_[^/]+\.[a-z0-9]+$/i;

/** Primer segmento con forma de release descomprimida: grafana-12.3.0, apache-maven-3.8.4, node-v20.1.0. */
const RELEASE_DIR_RE = /^[A-Za-z][\w.]*-v?\d+(\.\d+)+([-.][\w.]+)?$/;

/** Aplicación de macOS (Slack.app): un paquete instalado, aunque esté en el Escritorio. */
const APP_BUNDLE_RE = /\.app$/i;

/** Copia descargada de un repositorio ajeno (el zip de GitHub se llama nombre-main o nombre-master). */
const REPO_SNAPSHOT_RE = /^[\w.-]+-(main|master)$/;

/** Dentro de una imagen, software instalado por paquetes o por el propio producto de la imagen. */
const IMAGE_SOFTWARE_RE = /^(usr|opt)\//;
/** Ficheros de código o de documentación: lo que contienen es del programa, no de quien construyó la imagen. */
const CODE_FILE_RE = /\.(rb|py|pyc|js|mjs|cjs|ts|go|java|kt|scala|php|c|h|cc|cpp|rs|pl|pm|lua|sh|toml|md|txt|html?|erb|haml|rst)$/i;
/** Segmentos de dependencias dentro de una imagen. */
const IMAGE_DEP_SEGMENTS = new Set(["node_modules", "site-packages", "dist-packages", "vendor", "doc", "gems", "jars", "modules"]);
/** Certificado autofirmado de prueba que instala el paquete ssl-cert de Debian y Ubuntu: no se usa para nada real. */
const SNAKEOIL_RE = /(^|\/)ssl-cert-snakeoil\.key$/;

/** Ruta relativa al home con separador "/", o la absoluta si no está dentro. */
function relToHome(p, home) {
  const norm = String(p || "").replace(/\\/g, "/");
  const h = String(home || "").replace(/\\/g, "/").replace(/\/+$/, "");
  if (norm.startsWith("~/")) return norm.slice(2);
  if (h && norm.startsWith(h + "/")) return norm.slice(h.length + 1);
  return norm.replace(/^\/+/, "");
}

/** Contexto de un fichero del equipo: 'store', 'thirdparty', 'testdata' o 'user'.
 *  `synced` (carpeta sincronizada con la nube) solo tiene sentido para 'user'. */
function classifyHostPath(p, home) {
  const rel = relToHome(p, home);
  const segs = rel.split("/").filter(Boolean);
  const name = segs[segs.length - 1] || "";
  const lower = segs.map((s) => s.toLowerCase());

  if (CREDENTIAL_STORES.some((s) => (s.endsWith("/") ? rel.startsWith(s) : rel === s || rel.startsWith(s + "/")))) {
    return { kind: "store", synced: false, rel };
  }
  if (lower.some((s) => SECURITY_CORPORA.has(s))) return { kind: "testdata", synced: false, rel };
  if (segs.slice(0, -1).some((s) => THIRD_PARTY_SEGMENTS.has(s) || APP_BUNDLE_RE.test(s) || REPO_SNAPSHOT_RE.test(s)) ||
      BUNDLE_RE.test(name) ||
      (segs.length > 1 && RELEASE_DIR_RE.test(segs[0])) || /(^|\/)\.claude\/plugins\//.test(rel)) {
    return { kind: "thirdparty", synced: false, rel };
  }
  if (lower.slice(0, -1).some((s) => TEST_SEGMENTS.has(s)) || TEST_FILE_RE.test(name)) {
    return { kind: "testdata", synced: false, rel };
  }
  return { kind: "user", synced: SYNCED_RE.test(rel), rel };
}

/** Contexto de un fichero dentro de una imagen: dependencias y tests son de otros, el resto lo grabó quien la construyó. */
function classifyImagePath(p) {
  const rel = String(p || "").replace(/\\/g, "/").replace(/^\/+/, "");
  const segs = rel.split("/").filter(Boolean);
  const name = segs[segs.length - 1] || "";
  const lower = segs.map((s) => s.toLowerCase());
  if (lower.slice(0, -1).some((s) => TEST_SEGMENTS.has(s)) || TEST_FILE_RE.test(name)) return { kind: "testdata", rel };
  if (segs.slice(0, -1).some((s) => IMAGE_DEP_SEGMENTS.has(s)) || SNAKEOIL_RE.test(rel) ||
      (IMAGE_SOFTWARE_RE.test(rel) && CODE_FILE_RE.test(name))) {
    return { kind: "thirdparty", rel };
  }
  return { kind: "user", rel };
}

/** Severidad propia para controles de Dockerfile: Trivy marca «alto» simples buenas prácticas.
 *  Fuera de la tabla manda Trivy, pero «alto» o «crítico» bajan a «medio» (salvo DS-0031). */
const DOCKERFILE_SEVERITY = {
  "DS-0001": "low",      // :latest — reproducibilidad, entra código nuevo sin control
  "DS-0002": "medium",   // root — el riesgo real lo da el contenedor que corre como root, que se revisa aparte
  "DS-0004": "medium",   // EXPOSE 22 — un servidor SSH dentro del contenedor
  "DS-0009": "info",     // WORKDIR relativo
  "DS-0010": "low",      // sudo en RUN
  "DS-0013": "info",     // RUN cd
  "DS-0015": "info",     // yum clean all
  "DS-0017": "low",      // update aparte — puede instalar versiones antiguas
  "DS-0021": "info",     // apt-get sin -y
  "DS-0022": "info",     // MAINTAINER
  "DS-0025": "info",     // apk add sin --no-cache
  "DS-0026": "info",     // sin HEALTHCHECK
  "DS-0029": "info",     // sin --no-install-recommends
  // DS-0031 (secretos en ENV/ARG) conserva la de Trivy: es una credencial expuesta.
};

function misconfSeverity(id, trivySev) {
  if (DOCKERFILE_SEVERITY[id]) return DOCKERFILE_SEVERITY[id];
  const sev = String(trivySev || "").toLowerCase();
  if (/^DS-/.test(String(id || "")) && id !== "DS-0031" && (sev === "high" || sev === "critical")) return "medium";
  return null;   // sin opinión: manda la de Trivy
}

module.exports = {
  classifyHostPath,
  classifyImagePath,
  misconfSeverity,
  relToHome,
  DOCKERFILE_SEVERITY,
};
