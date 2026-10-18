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

/**
 * Exclusiones de la pasada de secretos, además de las de siempre. Son software de otros (extensiones, dependencias,
 * cachés de herramientas) y datos de aplicaciones: medido en un home real, ~/Library, ~/.local y las extensiones se
 * comían el tiempo entero de la pasada sin aportar un solo secreto del usuario. Trivy tampoco busca secretos dentro de
 * node_modules ni .git, pero los recorre igual: con "**\/" no entra. Los patrones con "**" van relativos a cada
 * carpeta escaneada, que es como los entiende Trivy.
 */
const SECRET_SKIP_DIRS = [
  ...DEFAULT_SKIP_DIRS,
  "Library", ".local/share", "Movies", "Music", "Pictures",
  ".vscode/extensions", ".vscode-server", ".antigravity/extensions", ".cursor/extensions", ".windsurf/extensions",
  ".m2/repository", ".m2/wrapper", ".gradle", ".rustup", ".nvm", ".pyenv", ".cargo", ".claude/plugins",
  // Conjuntos de pruebas de seguridad: traen credenciales de ejemplo a propósito y cuestan un minuto de lectura.
  "nuclei-templates", "SecLists", "PayloadsAllTheThings", "metasploit-framework", "exploitdb",
  "**/node_modules", "**/.git", "**/.venv", "**/venv", "**/site-packages", "**/__pycache__",
];

/** Hijos que la pasada de secretos analiza a la vez: usa la caché en memoria, así que no compiten por un bloqueo. */
const SECRET_CONCURRENCY = 3;
/** Por hijo, en la pasada de secretos: lee el contenido de los ficheros y no solo los manifiestos. */
const SECRET_CHILD_TIMEOUT_MS = 180000;

/**
 * Ficheros sueltos de la raíz del home donde se suelen guardar credenciales. La pasada por hijos no mira los
 * ficheros de la raíz, así que en la de secretos estos se analizan uno a uno.
 */
const ROOT_SECRET_FILES = [
  ".netrc", ".git-credentials", ".npmrc", ".pypirc", ".env",
  ".bash_history", ".zsh_history", ".psql_history", ".mysql_history",
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

  const scanners = opts.scanners || "vuln";

  // Si la carpeta la eligió el usuario va de una pasada: el ámbito lo acotó él y no hay que
  // protegerlo de sus propias unidades de red.
  return resolvedFrom === "config"
    ? await scanSingle(target, skipDirs, resolvedFrom, scanners)
    : await scanHomeByChildren(target, skipDirs, resolvedFrom, scanners);
}

/**
 * Secretos (claves, tokens, contraseñas) y configuraciones inseguras (Dockerfile, Kubernetes, Terraform…) en los
 * ficheros del mismo ámbito que runTrivyFs. Es una pasada aparte y no un escáner más en la de vulnerabilidades: si
 * esta se corta por tiempo, la otra no pierde su resultado, y cada una llega al informe con su propio estado.
 */
async function runTrivySecrets(opts = {}) {
  return runTrivyFs({ skipDirs: SECRET_SKIP_DIRS, ...opts, scanners: "secret,misconfig" });
}

/** Orden de Trivy como array, sin shell. El "--" evita que una carpeta que empiece por "-" se lea como opción.
 *  Las pasadas de secretos usan la caché en memoria: así no compiten por el bloqueo de la caché en disco
 *  con la de vulnerabilidades y la de paquetes del sistema, que van en paralelo. */
function trivyFsArgs(file, target, skipArgs, scanners = "vuln") {
  const cache = scanners === "vuln" ? [] : ["--cache-backend", "memory"];
  return ["trivy", "fs", "--format", "json", "--quiet", "--scanners", scanners, ...cache, ...skipArgs, "-o", file, "--", target];
}

/** Una sola invocación de Trivy sobre `target`. */
async function scanSingle(target, skipDirs, resolvedFrom, scanners = "vuln") {
  const skipArgs = skipDirs.length ? ["--skip-dirs", absSkipDirs(target, skipDirs).join(",")] : [];
  const started = Date.now();
  const parsed = await runTrivyCommand(
    (file) => trivyFsArgs(file, target, skipArgs, scanners),
    TIMEOUT_MS
  );
  if (parsed.skipped) return parsed;

  // Las rutas de Trivy son relativas a lo escaneado: con la raíz se puede decir dónde está cada fichero.
  for (const r of parsed.Results || []) r.__root = target;

  // El dashboard enseña qué carpeta se auditó, así que la procedencia viaja con el resultado.
  parsed.scan = {
    mode: "fs",
    scanners,
    target,
    skipDirs,
    durationMs: Date.now() - started,
    resolvedFrom,
    trivyVersion: trivyVersion(),
  };
  return parsed;
}

/** Una pasada de Trivy por carpeta, `n` a la vez. Devuelve nombre → { child, res, ms }. */
async function scanPool(items, skipArgs, scanners, timeout, n) {
  const out = new Map();
  let i = 0;
  const trabajador = async () => {
    while (i < items.length) {
      const { name, child } = items[i++];
      const t0 = Date.now();
      const res = await runTrivyCommand((file) => trivyFsArgs(file, child, skipArgs, scanners), timeout);
      out.set(name, { child, res, ms: Date.now() - t0 });
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, n) }, trabajador));
  return out;
}

/** En absoluto: al escanear por hijos la raíz cambia en cada pasada y "go/pkg/mod" ya no casaría. */
function absSkipDirs(home, skipDirs) {
  return skipDirs.map((d) => (path.isAbsolute(d) || d.includes("*") ? d : path.join(home, d)));
}

/**
 * Una pasada por hijo de primer nivel. Con una sola invocación, un directorio que no responde (p. ej. CloudStorage/GoogleDrive)
 * aborta todo el escaneo y --skip-dirs no lo evita, porque Trivy recorre antes de filtrar (probado con cuatro variantes).
 * Por hijo, el fallo queda en su carpeta. Los hijos que no son almacenamiento local se descartan antes, vía local-fs.js.
 * A cambio, los ficheros sueltos en la raíz del home no se miran.
 */
async function scanHomeByChildren(home, skipDirs, resolvedFrom, scanners = "vuln") {
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

  const pendientes = [];
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
    pendientes.push({ name: entry.name, child });
  }

  // La de vulnerabilidades va de uno en uno (comparte la caché en disco); la de secretos, de tres en tres.
  const isVuln = scanners === "vuln";
  const timeout = isVuln ? CHILD_TIMEOUT_MS : SECRET_CHILD_TIMEOUT_MS;
  const porHijo = await scanPool(pendientes, skipArgs, scanners, timeout, isVuln ? 1 : SECRET_CONCURRENCY);

  // Secretos: una carpeta que agota el tiempo se vuelve a intentar por sus subcarpetas. Medido en un home real:
  // ~/Desktop, justo donde estaban los proyectos del usuario, no cabía entera en 3 minutos y se quedaba sin revisar.
  // Los ficheros sueltos de su raíz se quedan sin mirar, como los del home.
  if (!isVuln) {
    for (const p of pendientes) {
      const hit = porHijo.get(p.name);
      if (!hit.res.skipped || hit.res.kind !== "timeout") continue;
      let subs;
      try { subs = fs.readdirSync(p.child, { withFileTypes: true }); } catch (_) { continue; }
      const subPend = subs
        .filter((e) => e.isDirectory())
        .map((e) => ({ name: `${p.name}/${e.name}`, child: path.join(p.child, e.name) }))
        .filter((x) => !absSkip.includes(x.child) && classifyDir(x.child).local);
      const subRes = await scanPool(subPend, skipArgs, scanners, timeout, SECRET_CONCURRENCY);
      porHijo.set(p.name, { ...hit, split: subPend.map((x) => ({ ...x, ...subRes.get(x.name) })) });
    }
  }

  // En el orden del directorio, no en el de llegada: el informe sale igual en cada ejecución.
  for (const { name } of pendientes) {
    const { child, res, ms, split } = porHijo.get(name);
    if (split) {
      let total = 0;
      for (const sub of split) {
        if (sub.res.skipped) {
          skippedChildren.push({ name: sub.name, kind: "error", reason: sub.res.reason, durationMs: sub.ms });
          continue;
        }
        const rs = sub.res.Results || [];
        for (const r of rs) r.__root = sub.child;
        merged.Results.push(...rs);
        total += rs.length;
      }
      scanned.push({ name, results: total, durationMs: ms, bySubfolders: split.length });
      continue;
    }
    if (res.skipped) {
      // La ganancia de escanear por hijos: el problemático se anota y se sigue.
      skippedChildren.push({ name, kind: "error", reason: res.reason, durationMs: ms });
      continue;
    }
    const results = res.Results || [];
    for (const r of results) r.__root = child;
    merged.Results.push(...results);
    scanned.push({ name, results: results.length, durationMs: ms });
  }

  // Solo en la pasada de secretos: los ficheros de credenciales de la raíz, uno a uno.
  const rootFiles = [];
  if (scanners.includes("secret")) {
    for (const name of ROOT_SECRET_FILES) {
      const file = path.join(home, name);
      let st;
      try { st = fs.statSync(file); } catch (_) { continue; }
      if (!st.isFile()) continue;
      const res = await runTrivyCommand((out) => trivyFsArgs(out, file, [], scanners), CHILD_TIMEOUT_MS);
      if (res.skipped) {
        skippedChildren.push({ name, kind: "error", reason: res.reason });
        continue;
      }
      for (const r of res.Results || []) r.__root = home;
      merged.Results.push(...(res.Results || []));
      rootFiles.push(name);
    }
  }

  merged.scan = {
    mode: "fs-by-children",
    scanners,
    target: home,
    skipDirs,
    durationMs: Date.now() - started,
    resolvedFrom,
    trivyVersion: trivyVersion(),
    children: { scanned, skipped: skippedChildren },
    rootFiles,
  };
  return merged;
}

module.exports = {
  runTrivyFs,
  runTrivySecrets,
  SECRET_SKIP_DIRS,
  resolveUserHome,
  resolveScanTarget,
  DEFAULT_SKIP_DIRS,
};
