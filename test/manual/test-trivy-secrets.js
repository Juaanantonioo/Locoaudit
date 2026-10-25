"use strict";

/**
 * test-trivy-secrets.js — Secretos y configuraciones inseguras de Trivy.
 *
 * Las dos fixtures son salidas reales de Trivy 0.69.3 (con el nombre del artefacto anonimizado):
 *   fs-secrets-misconfig.json     `trivy fs --scanners secret,misconfig` sobre un home de prueba
 *   image-secrets-misconfig.json  `trivy image --scanners secret --image-config-scanners misconfig,secret`
 *
 * Lo que se fija:
 *   1. Ningún valor de un secreto llega al hallazgo. Trivy enmascara `Match`, pero en las configuraciones copia la
 *      línea del Dockerfile sin enmascarar en CauseMetadata.Code.
 *   2. Una clave privada en ~/.ssh es informativa; fuera de su almacén, y cualquier token, cuenta en el riesgo.
 *   3. En el equipo, las configuraciones de proyectos no suben el riesgo; en una imagen, sí.
 *   4. Una pasada de secretos omitida sale como comprobación no realizada, con su motivo.
 *   5. Las órdenes de Trivy llevan los escáneres pedidos.
 *
 * Uso:
 *   node test/manual/test-trivy-secrets.js
 */

const fs = require("fs");
const path = require("path");

let failed = 0;
let passed = 0;

function ok(cond, label, detail) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}`); if (detail) console.log(`      ${detail}`); }
}

const FIX = path.join(__dirname, "..", "fixtures", "trivy");
const leer = (f) => JSON.parse(fs.readFileSync(path.join(FIX, f), "utf8"));

// Valores en claro que hay en las fixtures. Ninguno puede aparecer en un hallazgo.
const EN_CLARO = [
  "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB",
  "1234567890abcdefghijklmnopqrstuvwxyz",
  "abc123secretvalue",
  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzzQKEY9a",
  "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ",
];

const { normalizarHost, normalizarImagen, desdeSecretosYConfig } = require("../../lib/normalizer");
const { resumir, esAccionable } = require("../../lib/severity-map");

console.log("\n── 1 · Equipo: secretos y configuraciones del home ───────────────\n");

const home = leer("fs-secrets-misconfig.json");
// Así lo deja trivy-fs.js: cada Result con la carpeta escaneada y el modo por hijos.
for (const r of home.Results) r.__root = "/home/ana";
home.scan = { mode: "fs-by-children", target: "/home/ana", scanners: "secret,misconfig" };

const hf = normalizarHost({ trivySecrets: home }, { platform: "linux" });
const hJson = JSON.stringify(hf);
console.log("  " + hf.map((f) => `${f.id}/${f.severity}`).join(" · "));

ok(!EN_CLARO.some((v) => hJson.includes(v)), "ningún valor en claro en los hallazgos del equipo",
   EN_CLARO.filter((v) => hJson.includes(v)).join(", "));

const almacen = hf.find((f) => f.category === "secret" && /guardada por su aplicación/.test(f.title));
ok(almacen && almacen.severity === "info" && /\.ssh\/id_ed25519/.test(almacen.title),
   "clave privada en ~/.ssh: informativa, como credencial guardada por su aplicación", almacen && almacen.title);
ok(almacen && !esAccionable(almacen), "y no cuenta en el riesgo");

const token = hf.find((f) => f.category === "secret" && /\.env$/.test(f.location || ""));
ok(token && token.severity === "critical", "token de GitHub en ~/proyecto/.env: crítico", token && token.severity);
ok(token && esAccionable(token), "y cuenta en el riesgo");
ok(token && token.evidence.includes("*"), "la evidencia enseña el valor enmascarado de Trivy");
ok(token && token.location === "~/proyecto/.env", "la ruta sale relativa al home", token && token.location);

const copia = hf.find((f) => f.category === "secret" && /clave_copia/.test(f.location || ""));
ok(copia && copia.severity === "medium" && esAccionable(copia),
   "una clave privada fuera de su almacén es un hallazgo medio", copia && copia.severity);

const mis = hf.filter((f) => f.category === "misconfig");
ok(mis.length === 1, "las configuraciones de un fichero salen en un solo hallazgo", String(mis.length));
ok(mis[0] && mis[0].severity === "info" && !esAccionable(mis[0]),
   "y no suben el riesgo del equipo: es un fichero de un proyecto");
ok(mis[0] && /13 configuraciones mejorables/.test(mis[0].title), "el título dice cuántas son", mis[0] && mis[0].title);
ok(mis[0] && /DS-0002/.test(mis[0].evidence) && /root/.test(mis[0].evidence),
   "la evidencia nombra los controles, en castellano");

const sum = resumir(hf);
ok(sum.actionable.total === 2, "2 accionables en el equipo: el token y la clave copiada", String(sum.actionable.total));

console.log("\n── 2 · Imagen: secretos en capas y configuración de la imagen ────\n");

const img = leer("image-secrets-misconfig.json");
for (const r of img.Results) r.__image = img.ArtifactName;
const imf = normalizarImagen({ Results: img.Results }, "trivy");
const iJson = JSON.stringify(imf);
console.log("  " + imf.map((f) => `${f.id}/${f.severity}`).join(" · "));

ok(!EN_CLARO.some((v) => iJson.includes(v)),
   "ningún valor en claro: CauseMetadata.Code del DS-0031 no se copia",
   EN_CLARO.filter((v) => iJson.includes(v)).join(", "));
ok(imf.every((f) => f.scope === "image"), "todos llevan scope image");

const sec = imf.find((f) => f.id.startsWith("IMG-SEC"));
ok(sec && sec.severity === "critical" && esAccionable(sec), "el token dentro de la imagen es crítico y accionable");
ok(sec && sec.image === "demo/leaky:1.0", "y queda asociado a su imagen", sec && sec.image);

const ds31 = imf.find((f) => f.id.startsWith("IMG-MIS") && /DS-0031/.test(f.title));
ok(ds31 && ds31.severity === "critical" && esAccionable(ds31), "secretos en ENV (DS-0031): crítico y accionable");
ok(ds31 && ds31.primaryUrl && ds31.primaryUrl.includes("ds-0031"), "con la ficha del control enlazada");
ok(ds31 && /Revoca/.test(ds31.fix), "y la resolución en castellano");

const practicas = imf.find((f) => f.id.startsWith("IMG-MIS") && /DS-0002/.test(f.evidence));
ok(practicas && /root y 1 mala práctica más/.test(practicas.title),
   "root y HEALTHCHECK salen en una sola ficha de la imagen", practicas && practicas.title);
ok(practicas && practicas.severity === "medium",
   "con severidad media: el root de verdad lo da el contenedor en marcha", practicas && practicas.severity);
ok(practicas && /DS-0026, informativo/.test(practicas.evidence), "y sin HEALTHCHECK como informativo");

console.log("\n── 2b · Contexto: rutas reales de un home auditado ───────────────\n");

// Rutas tomadas de una auditoría real (anonimizadas). Cada una con el contexto que le toca.
const { clasificarRutaHost, clasificarRutaImagen, severidadConfig } = require("../../lib/secret-context");
const H = "/Users/ana";
const CASOS = [
  ["~/nuclei-templates/helpers/payloads/cve-2023-34039-keys/id_rsa_vnera_keypair_6.0.0_platform", "testdata"],
  ["~/nuclei-templates/http/cves/2021/CVE-2021-37580.yaml", "testdata"],
  ["~/.vscode/extensions/ms-azuretools.vscode-containers-2.5.2/dist/extension.bundle.js", "thirdparty"],
  ["~/.antigravity/extensions/oracle.oracle-java-25.1.0-universal/nbcode/java/maven/conf/settings.xml", "thirdparty"],
  ["~/.m2/wrapper/dists/apache-maven-3.8.4-bin/x/apache-maven-3.8.4/conf/settings.xml", "thirdparty"],
  ["~/grafana-12.3.0/public/app/features/provisioning/Wizard/fields.ts", "thirdparty"],
  ["~/.claude/plugins/marketplaces/m/crates/core/benches/auth_mode.rs", "thirdparty"],
  ["~/.azure/msal_token_cache.json", "store"],
  ["~/.codex/auth.json", "store"],
  ["~/.config/github-copilot/apps.json", "store"],
  ["~/.ssh/id_rsa", "store"],
  ["~/Nextcloud/UNI/AS/PR1AS/ssh_keys/id_rsa", "user"],
  ["~/docker/mysql-ffm/server-key.pem", "user"],
  ["~/Desktop/proyecto/.env", "user"],
];
for (const [p, esperado] of CASOS) {
  const c = clasificarRutaHost(p, H);
  ok(c.kind === esperado, `${p.slice(0, 70)} → ${esperado}`, c.kind);
}
ok(clasificarRutaHost("~/Nextcloud/UNI/x/id_rsa", H).synced === true, "Nextcloud se reconoce como carpeta sincronizada");
ok(clasificarRutaHost("~/docker/mysql/server-key.pem", H).synced === false, "~/docker no lo es");
ok(clasificarRutaImagen("/juice-shop/frontend/src/app/app.guard.spec.ts").kind === "testdata", "un .spec.ts de una imagen es de test");
ok(clasificarRutaImagen("/etc/ssh/ssh_host_rsa_key").kind === "user", "una clave de /etc/ssh de una imagen va grabada en ella");
// Falsos positivos del tercer escaneo real
for (const [p, kind] of [
  ["~/Desktop/IA/Claude.app/Contents/Resources/ion-dist/assets/v1/index.js", "thirdparty"],
  ["~/Desktop/skills/headroom-main/crates/headroom-core/benches/auth_mode.rs", "thirdparty"],
  ["~/proyecto/benches/auth.rs", "testdata"],
  ["~/Desktop/UNI/EDNL/PRACTICAS/ARBOLES/p2-rep/ej1.cpp", "user"],
]) ok(clasificarRutaHost(p, H).kind === kind, `${p} → ${kind}`);
for (const [p, kind] of [
  ["/opt/gitlab/embedded/lib/ruby/gems/3.2.0/gems/aws-sdk-core-3.1/lib/seahorse/client.rb", "thirdparty"],
  ["/opt/gitlab/embedded/service/gitlab-rails/app/models/personal_access_token.rb", "thirdparty"],
  ["/opt/gitlab/embedded/service/gitlab-rails/config/gitleaks.toml", "thirdparty"],
  ["/opt/msf/modules/exploits/linux/ssh/known_privkey.rb", "thirdparty"],
  ["/usr/local/rvm/gems/ruby-3.1/gems/hrr_rb_ssh-0.4/demo/server.rb", "thirdparty"],
  ["/etc/ssl/private/ssl-cert-snakeoil.key", "thirdparty"],
  ["/opt/app/.env", "user"],
  ["/opt/app/certs/server.key", "user"],
  ["/juice-shop/lib/insecurity.ts", "user"],
]) ok(clasificarRutaImagen(p).kind === kind, `${p} → ${kind}`);
ok(severidadConfig("DS-0029", "HIGH") === "info", "DS-0029 (--no-install-recommends) es higiene: informativo");
ok(severidadConfig("DS-0031", "CRITICAL") === null, "DS-0031 (secretos en ENV) conserva la de Trivy");
ok(severidadConfig("DS-9999", "HIGH") === "medium", "un control de Dockerfile sin revisar baja de alto a medio");

// Lo mismo pasado por el normalizador: terceros y datos de prueba en un solo informativo.
const ruido = desdeSecretosYConfig({
  Results: [
    { Target: "helpers/payloads/k/id_rsa_x", __root: `${H}/nuclei-templates`, Secrets: [{ RuleID: "private-key", Severity: "HIGH", Title: "Asymmetric Private Key", StartLine: 1, Match: "****" }] },
    { Target: "extensions/e/dist/extension.bundle.js", __root: `${H}/.vscode`, Secrets: [{ RuleID: "azure-storage-account-key", Severity: "CRITICAL", Title: "Azure", StartLine: 1, Match: "k=****" }] },
    { Target: "msal_token_cache.json", __root: `${H}/.azure`, Secrets: [{ RuleID: "jwt-token", Severity: "MEDIUM", Title: "JWT token", StartLine: 1, Match: "****" }] },
    { Target: "UNI/x/ssh_keys/id_rsa", __root: `${H}/Nextcloud`, Secrets: [{ RuleID: "private-key", Severity: "HIGH", Title: "Asymmetric Private Key", StartLine: 1, Match: "****" }] },
  ],
  scan: { mode: "fs-by-children", target: H },
}, { context: "host" });
const accionables = ruido.filter((f) => esAccionable({ ...f, scope: "host" }));
ok(accionables.length === 1 && /sincronizada/.test(accionables[0].title) && accionables[0].severity === "high",
   "de cuatro, solo cuenta la clave de la carpeta sincronizada, como alto", JSON.stringify(accionables.map((f) => f.title)));
ok(ruido.some((f) => /2 posibles secretos en software de terceros/.test(f.title) && f.severity === "info"),
   "las de terceros y de prueba van juntas en un informativo", JSON.stringify(ruido.map((f) => f.title)));
ok(ruido.some((f) => /Credencial guardada por su aplicación: ~\/\.azure/.test(f.title)),
   "el token de ~/.azure, como credencial guardada por su aplicación");

const { variablesSensibles } = require("../../nodes/audit-image/modules/config-audit");
const env = variablesSensibles(JSON.stringify([
  "GPG_KEYS=39B6 4135", "MYSQL_ROOT_PASSWORD=x", "MYSQL_ROOT_PASSWORD_FILE=/run/secrets/p", "DB_PASS=", "PATH=/bin",
]));
ok(env.length === 1 && env[0] === "MYSQL_ROOT_PASSWORD",
   "variables de entorno: la contraseña sí; GPG_KEYS, un *_FILE de Docker secrets o una vacía, no", JSON.stringify(env));

console.log("\n── 3 · Defensa: sin asteriscos no se enseña el valor ─────────────\n");

const sinMascara = desdeSecretosYConfig({
  Results: [{ Target: "app/.env", __root: "/home/ana", Secrets: [{
    RuleID: "github-pat", Severity: "CRITICAL", Title: "GitHub Personal Access Token", StartLine: 1,
    Match: "GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyzAB",
  }] }],
  scan: { mode: "fs-by-children", target: "/home/ana" },
}, { context: "host" });
ok(sinMascara.length === 1 && !JSON.stringify(sinMascara).includes("ghp_1234"),
   "un Match sin enmascarar no llega a la evidencia");

const controlDesconocido = desdeSecretosYConfig({
  Results: [{ Target: "demo:1", __image: "demo:1", Misconfigurations: [{
    ID: "DS-9999", Severity: "MEDIUM", Title: "Some new check", Status: "FAIL",
    Resolution: "Do the thing", PrimaryURL: "https://avd.aquasec.com/misconfig/ds-9999",
  }] }],
}, { context: "image" });
ok(controlDesconocido.length === 1 && /Do the thing/.test(controlDesconocido[0].fix),
   "un control sin ficha en castellano sale con la resolución de Trivy");

const parcial = desdeSecretosYConfig({
  Results: [],
  scan: { mode: "fs-by-children", target: "/home/ana", children: {
    scanned: [], skipped: [
      { name: "Proyectos", kind: "error", reason: "timeout" },
      { name: "GoogleDrive", kind: "cloud", reason: "almacenamiento en la nube" },
    ] } },
}, { context: "host" });
ok(parcial.length === 1 && parcial[0].id === "HOST-SEC-PARTIAL" && /Proyectos/.test(parcial[0].evidence),
   "una carpeta que falla deja constancia; una excluida a propósito, no", JSON.stringify(parcial.map((f) => f.evidence)));

console.log("\n── 4 · Pasada omitida: comprobación no realizada ─────────────────\n");

for (const kind of ["disabled", "not-installed", "timeout", "error"]) {
  const f = normalizarHost({ trivySecrets: { skipped: true, kind, reason: `motivo ${kind}` } }, { platform: "linux" });
  ok(f.length === 1 && f[0].id === "HOST-SEC-SKIP" && f[0].skipped === true && f[0].kind === kind,
     `${kind} → HOST-SEC-SKIP con kind ${kind}`, JSON.stringify(f.map((x) => [x.id, x.kind])));
}

console.log("\n── 5 · Las órdenes llevan los escáneres pedidos ──────────────────\n");

(async () => {
  const EXEC_PATH = require.resolve("../../lib/executor");
  const execReal = require(EXEC_PATH);
  const ordenes = [];
  require.cache[EXEC_PATH].exports = Object.assign({}, execReal, {
    existeComando: async () => "/usr/bin/trivy",
    ejecutarAFichero: async (build) => { ordenes.push(build("/tmp/salida.json")); return { Results: [] }; },
    ejecutar: async (cmd) => {
      ordenes.push(cmd);
      if (/--version/.test(cmd)) return "Version: 0.69.3";
      return JSON.stringify({ ArtifactName: "demo:1", Results: [] });
    },
  });
  for (const m of ["../../nodes/audit-host/modules/trivy-fs", "../../nodes/audit-image/modules/cve-checker"]) {
    delete require.cache[require.resolve(m)];
  }
  const { ejecutarTrivyFs, ejecutarTrivySecretos } = require("../../nodes/audit-host/modules/trivy-fs");
  const { ejecutarTrivyImagen } = require("../../nodes/audit-image/modules/cve-checker");

  await ejecutarTrivyFs({ target: "/tmp" });
  await ejecutarTrivySecretos({ target: "/tmp" });
  await ejecutarTrivyImagen([{ id: "demo:1", repository: "", tag: "" }]);

  const fsVuln = ordenes.find((o) => Array.isArray(o) && o.includes("vuln"));
  const fsSec = ordenes.find((o) => Array.isArray(o) && o.includes("secret,misconfig"));
  const imagen = ordenes.find((o) => typeof o === "string" && /trivy image/.test(o));

  ok(fsVuln && !fsVuln.includes("memory"), "la pasada de vulnerabilidades sigue igual", JSON.stringify(fsVuln));
  ok(fsSec && fsSec.includes("--cache-backend") && fsSec.includes("memory"),
     "la de secretos usa caché en memoria y no compite por la de disco", JSON.stringify(fsSec));
  ok(fsSec && fsSec[fsSec.length - 2] === "--" && fsSec[fsSec.length - 1] === "/tmp",
     "y conserva el -- antes de la carpeta", JSON.stringify(fsSec));
  ok(imagen && /--scanners vuln,secret/.test(imagen) && /--image-config-scanners misconfig,secret/.test(imagen),
     "trivy image busca vulnerabilidades, secretos y configuración de la imagen", imagen);

  console.log("\n── 6 · Una carpeta que agota el tiempo se revisa por subcarpetas ─\n");

  // Home de prueba: Desktop no cabe entera en el tiempo; sus dos subcarpetas sí, y una de ellas tampoco.
  const os = require("os");
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "lca-home-"));
  for (const d of ["Desktop/proyecto", "Desktop/enorme", "Documents"]) fs.mkdirSync(path.join(tmpHome, d), { recursive: true });
  const vistos = [];
  require.cache[EXEC_PATH].exports.ejecutarAFichero = async (build) => {
    const args = build("/tmp/salida.json");
    const target = args[args.length - 1];
    vistos.push(path.relative(tmpHome, target));
    if (/Desktop$|enorme$/.test(target)) return { skipped: true, kind: "timeout", reason: "límite superado" };
    return { Results: [{ Target: ".env", Secrets: [] }] };
  };
  delete require.cache[require.resolve("../../nodes/audit-host/modules/trivy-fs")];
  const { ejecutarTrivySecretos: secretosDe } = require("../../nodes/audit-host/modules/trivy-fs");
  const homeAntes = process.env.HOME;
  process.env.HOME = tmpHome;
  const res = await secretosDe({});
  process.env.HOME = homeAntes;
  const sc = res.scan.children;
  ok(vistos.includes("Desktop/proyecto") && vistos.includes("Desktop/enorme"),
     "Desktop se reintenta por sus subcarpetas", JSON.stringify(vistos));
  ok(sc.scanned.some((c) => c.name === "Desktop" && c.bySubfolders === 2), "y cuenta como revisada por partes", JSON.stringify(sc.scanned));
  ok(sc.skipped.some((c) => c.name === "Desktop/enorme" && c.kind === "error") && !sc.skipped.some((c) => c.name === "Desktop"),
     "solo queda sin revisar la subcarpeta que tampoco cupo", JSON.stringify(sc.skipped));
  ok(res.Results.some((r) => r.__root === path.join(tmpHome, "Desktop", "proyecto")),
     "los resultados de la subcarpeta llevan su propia raíz");
  fs.rmSync(tmpHome, { recursive: true, force: true });

  console.log(`\n${passed} pasados · ${failed} fallidos\n`);
  process.exit(failed ? 1 : 0);
})();
