"use strict";

/**
 * Wrapper de Trivy sobre el sistema de ficheros. El ámbito es solo el HOME del usuario en las tres plataformas: escanear
 * territorio del gestor de paquetes daba lockfiles empaquetados de terceros (campo `origin` en lib/finding-schema.js).
 * Los paquetes del SO son otra pregunta y viven en lib/trivy-rootfs.js.
 * Cuando no se puede escanear devuelve { skipped, kind, reason } y quien llama decide por `kind`: 'unsupported' no es un
 * error; 'not-installed' y 'error' sí.
 */

const os = require("os");
const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");
const { execToFile, execCommand, commandExists } = require("../../../lib/executor");
const { classifyDir } = require("./local-fs");

const TIMEOUT_MS = 120000;
// Por hijo: así una carpeta que no responde se lleva su tiempo, no el del escaneo entero.
const CHILD_TIMEOUT_MS = 90000;

/**
 * Exclusiones por defecto, relativas al objetivo (trivy 0.72.0: valen igual relativas y absolutas, separador coma, una ruta
 * inexistente no molesta). El sufijo "/*" excluye los hijos pero no el directorio, por eso ninguna entrada lo lleva.
 * node_modules se queda dentro a propósito: son dependencias reales del usuario.
 */
const DEFAULT_SKIP_DIRS = [
  ".cache",                // cachés de herramientas: nada que parchear
  ".local/share/Trash",    // papelera: ficheros ya descartados
  ".cargo/registry",       // fuentes descargadas de crates, no compiladas ni usadas
  "go/pkg/mod",            // módulos Go en caché, idem
  ".npm",                  // caché de npm (≠ node_modules, que sí se escanea)
];

/** Error de recorrido del sistema de ficheros (montaje que no responde, permisos). */
const WALK_ERROR_RE = /walk dir error|fdopendir|operation timed out|permission denied/i;

/** Prefijos de home por plataforma, para el fallback de homeForUser(). */
const HOME_BASE = { darwin: "/Users", linux: "/home" };

/** Home de un usuario según la base de datos real del sistema; null si no existe el directorio. */
function homeForUser(user) {
  if (!user || process.platform === "win32") return null;

  const probes = process.platform === "darwin"
    ? [`dscl . -read /Users/${user} NFSHomeDirectory`]
    : [`getent passwd ${user}`];

  for (const cmd of probes) {
    try {
      const out = execSync(cmd, { timeout: 5000, stdio: ["ignore", "pipe", "ignore"] })
        .toString().trim();
      // dscl da "NFSHomeDirectory: /Users/ana"; getent, "ana:x:1000:1000::/home/ana:/bin/bash".
      const home = process.platform === "darwin"
        ? (out.split(":")[1] || "").trim()
        : (out.split(":")[5] || "").trim();
      if (home && fs.existsSync(home)) return home;
    } catch (_) { /* usuario inexistente o comando ausente: se prueba la siguiente señal */ }
  }

  const base = HOME_BASE[process.platform];
  const guess = base ? path.join(base, user) : null;
  return guess && fs.existsSync(guess) ? guess : null;
}

/** El home de quien audita, no el del proceso: con Node-RED como servicio (systemd, launchd)
 *  os.homedir() da /root o /var/lib/node-red y se auditaría un directorio vacío. */
function resolveUserHome() {
  // Con sudo el home real es el del usuario original, no el de root.
  const sudoUser = process.env.SUDO_USER;
  if (sudoUser) {
    const h = homeForUser(sudoUser);
    if (h) return { home: h, resolvedFrom: "SUDO_USER" };
  }

  // Del entorno, y solo si el directorio existe de verdad.
  const env = process.env.HOME || process.env.USERPROFILE;
  if (env && fs.existsSync(env)) return { home: env, resolvedFrom: "env" };

  // Último recurso: el registro de usuarios del proceso actual.
  return { home: os.homedir(), resolvedFrom: "os.homedir" };
}

/** Lo configurado en el nodo o, si viene vacío, el home. Expande "~" y "~/sub" contra ese home. */
function resolveScanTarget(configured) {
  const { home, resolvedFrom } = resolveUserHome();
  const raw = String(configured || "").trim();
  if (!raw) return { target: home, resolvedFrom };

  if (raw === "~") return { target: home, resolvedFrom: "config" };
  if (raw.startsWith("~/")) return { target: path.join(home, raw.slice(2)), resolvedFrom: "config" };
  return { target: raw, resolvedFrom: "config" };
}

/** Se guarda en el resultado: si la forma de los hallazgos cambia, dice si fue Trivy o nosotros. */
function trivyVersion() {
  try {
    const out = execSync("trivy --version", { timeout: 5000, stdio: ["ignore", "pipe", "ignore"] }).toString();
    const m = out.match(/Version:\s*(\S+)/i);
    return m ? m[1] : out.split("\n")[0].trim() || null;
  } catch (_) {
    return null;
  }
}

/**
 * Ejecuta un comando de Trivy y devuelve su JSON parseado, o { skipped, kind, reason }.
 * `buildCmd` recibe la ruta de un temporal y devuelve la línea con su `-o`: la salida va a fichero (ver execToFile()).
 */
async function runTrivyCommand(buildCmd, timeoutMs) {
  const parsed = await execToFile(buildCmd, timeoutMs, { prefix: "lcaudit-trivy-fs-" });
  if (!parsed.skipped) return parsed;

  // Un buffer rebasado NO es un JSON corrupto: el fichero está bien y lo que falló es nuestro
  // límite de captura. Confundirlos manda a diagnosticar Trivy, que no tiene nada que ver.
  if (parsed.kind === "output-too-large") {
    return {
      skipped: true,
      kind: "output-too-large",
      reason:
        "La salida de Trivy no cupo en el búfer de captura y el proceso se cortó a mitad. " +
        `El resultado parcial se descarta: no se usa como si fuera un escaneo completo. ${parsed.reason}`,
    };
  }

  if (parsed.kind === "invalid-json") {
    // Trivy escribe sus errores en texto plano en el mismo sitio: el principio del fichero suele
    // ser el mensaje real, y por eso execToFile lo conserva en `reason`.
    const detail = parsed.reason || "";
    if (WALK_ERROR_RE.test(detail)) return walkErrorResult(detail);
    return { skipped: true, kind: "invalid-json", reason: detail };
  }

  // 'error', 'timeout' y 'empty-output' llegan con el motivo real de execToFile. Una carpeta que
  // no responde mata el escaneo entero, y su salida para el usuario no es la de "trivy no está
  // instalado": aquí lo que toca es acotar la carpeta a auditar.
  const detail = parsed.reason || "unknown error";
  if (WALK_ERROR_RE.test(detail)) return walkErrorResult(detail);
  return { skipped: true, kind: parsed.kind || "error", reason: `Trivy terminó con error: ${detail}` };
}

/** Carpeta que no responde: mensaje propio, porque la acción del usuario es distinta. */
function walkErrorResult(stderr) {
  // El primer path absoluto del mensaje. Un "with (\S+)" genérico capturaba "traversal", de
  // "analyze with traversal:", que no dice nada.
  const m = stderr.match(/(\/[^\s:]+)/);
  return {
    skipped: true,
    kind: "error",
    walkError: true,
    path: m ? m[1] : null,
    reason:
      `Trivy no pudo recorrer ${m ? m[1] : "una carpeta del ámbito"}: la carpeta no responde ` +
      "(unidad de red o almacenamiento en la nube montado) o no hay permisos. El escaneo se " +
      "aborta por completo y --skip-dirs no lo evita. Indica una carpeta concreta en el campo " +
      `"Carpeta a auditar" del nodo, o desmonta esa unidad. Detalle: ${stderr}`,
  };
}

/**
 * Escaneo del HOME, y solo del HOME (los paquetes del sistema son lib/trivy-rootfs.js).
 * El commandExists sigue aquí porque audit-image también llama a Trivy y no se puede dar por hecho quién llama.
 */
async function runTrivyFs(opts = {}) {
  const available = await commandExists("trivy");
  if (!available) {
    return { skipped: true, kind: "not-installed", reason: "Trivy no está instalado en este equipo" };
  }

  const { target, resolvedFrom } = resolveScanTarget(opts.target);
  const skipDirs = Array.isArray(opts.skipDirs) && opts.skipDirs.length
    ? opts.skipDirs
    : DEFAULT_SKIP_DIRS;

  // Si la carpeta la eligió el usuario va de una pasada: el ámbito lo acotó él y no hay que
  // protegerlo de sus propias unidades de red.
  return resolvedFrom === "config"
    ? await scanSingle(target, skipDirs, resolvedFrom)
    : await scanHomeByChildren(target, skipDirs, resolvedFrom);
}

/** Orden de Trivy como array, sin shell. El "--" evita que una carpeta que empiece por "-" se lea como opción. */
function trivyFsArgs(file, target, skipArgs) {
  return ["trivy", "fs", "--format", "json", "--quiet", "--scanners", "vuln", ...skipArgs, "-o", file, "--", target];
}

/** Una sola invocación de Trivy sobre `target`. */
async function scanSingle(target, skipDirs, resolvedFrom) {
  const skipArgs = skipDirs.length ? ["--skip-dirs", absSkipDirs(target, skipDirs).join(",")] : [];
  const started = Date.now();
  const parsed = await runTrivyCommand(
    (file) => trivyFsArgs(file, target, skipArgs),
    TIMEOUT_MS
  );
  if (parsed.skipped) return parsed;

  // El dashboard enseña qué carpeta se auditó, así que la procedencia viaja con el resultado.
  parsed.scan = {
    mode: "fs",
    target,
    skipDirs,
    durationMs: Date.now() - started,
    resolvedFrom,
    trivyVersion: trivyVersion(),
  };
  return parsed;
}

/** En absoluto: al escanear por hijos la raíz cambia en cada pasada y "go/pkg/mod" ya no casaría. */
function absSkipDirs(home, skipDirs) {
  return skipDirs.map((d) => (path.isAbsolute(d) ? d : path.join(home, d)));
}

/**
 * Una pasada por hijo de primer nivel. Con una sola invocación, un directorio que no responde (p. ej. CloudStorage/GoogleDrive)
 * aborta todo el escaneo y --skip-dirs no lo evita, porque Trivy recorre antes de filtrar (probado con cuatro variantes).
 * Por hijo, el fallo queda en su carpeta. Los hijos que no son almacenamiento local se descartan antes, vía local-fs.js.
 * A cambio, los ficheros sueltos en la raíz del home no se miran.
 */
async function scanHomeByChildren(home, skipDirs, resolvedFrom) {
  const started = Date.now();
  const absSkip = absSkipDirs(home, skipDirs);
  const skipArgs = absSkip.length ? ["--skip-dirs", absSkip.join(",")] : [];

  let entries;
  try {
    entries = fs.readdirSync(home, { withFileTypes: true });
  } catch (err) {
    return { skipped: true, kind: "error", reason: `no se pudo leer el home ${home}: ${err.message}` };
  }

  const merged = { SchemaVersion: 2, ArtifactName: home, ArtifactType: "filesystem", Results: [] };
  const scanned = [];
  const skippedChildren = [];

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;               // los sueltos se quedan sin mirar
    const child = path.join(home, entry.name);

    // Mismo criterio que --skip-dirs, aplicado aquí porque a un hijo entero ni hace falta entrar.
    if (absSkip.includes(child)) {
      skippedChildren.push({ name: entry.name, kind: "excluded", reason: "en la lista de exclusiones" });
      continue;
    }

    const cls = classifyDir(child);
    if (!cls.local) {
      skippedChildren.push({ name: entry.name, kind: cls.kind, reason: cls.detail });
      continue;
    }

    const t0 = Date.now();
    const res = await runTrivyCommand(
      (file) => trivyFsArgs(file, child, skipArgs),
      CHILD_TIMEOUT_MS
    );
    const ms = Date.now() - t0;

    if (res.skipped) {
      // La ganancia de escanear por hijos: el problemático se anota y se sigue.
      skippedChildren.push({ name: entry.name, kind: "error", reason: res.reason, durationMs: ms });
      continue;
    }
    const results = res.Results || [];
    merged.Results.push(...results);
    scanned.push({ name: entry.name, results: results.length, durationMs: ms });
  }

  merged.scan = {
    mode: "fs-by-children",
    target: home,
    skipDirs,
    durationMs: Date.now() - started,
    resolvedFrom,
    trivyVersion: trivyVersion(),
    children: { scanned, skipped: skippedChildren },
  };
  return merged;
}

module.exports = {
  runTrivyFs,
  resolveUserHome,
  resolveScanTarget,
  DEFAULT_SKIP_DIRS,
};
