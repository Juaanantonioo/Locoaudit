"use strict";

/**
 * Wrapper de Trivy sobre el sistema de ficheros. El ámbito es el HOME del usuario en las tres
 * plataformas. Antes se escaneaba territorio del gestor de paquetes (C:\Program Files, el Cellar
 * de Homebrew, /usr/lib) y en Arch no salía un solo hallazgo accionable; lo que sí aparecían eran
 * lockfiles empaquetados dentro de otros paquetes, o sea dependencias declaradas de terceros y no
 * software del usuario (campo `origin` en lib/finding-schema.js). El software del sistema se
 * audita con el interruptor `systemPackages`, nunca por defecto.
 *
 * Cuando no se puede escanear devuelve { skipped, kind, reason } y quien llama decide por `kind`,
 * no por el texto: 'unsupported' no es un error y la auditoría continúa; 'not-installed' y
 * 'error' sí lo son.
 */

const os = require("os");
const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");
const { execCommand, commandExists } = require("../../../lib/executor");
const { detectPackageManager } = require("../../../lib/pkg-manager");
const { classifyDir } = require("./local-fs");

const TIMEOUT_MS = 120000;
// Por hijo: así una carpeta que no responde se lleva su tiempo, no el del escaneo entero.
const CHILD_TIMEOUT_MS = 90000;
// rootfs recorre el sistema entero: con el timeout de `fs` se cortaba y el JSON parcial
// se leía como un escaneo limpio.
const ROOTFS_TIMEOUT_MS = 600000;

/**
 * Exclusiones por defecto, relativas al objetivo. Comprobado en trivy 0.72.0: relativas y
 * absolutas valen igual, el separador es la coma, y una ruta inexistente no molesta. Ojo con el
 * sufijo "/*", que excluye los hijos pero no el directorio ("junk/*" deja pasar
 * junk/package-lock.json); por eso ninguna entrada lo lleva. node_modules se queda dentro a
 * propósito: son dependencias reales de proyectos del usuario y sus CVEs se pueden accionar.
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

/** Gestores cuya base de datos sabe leer Trivy. Fuera pacman y emerge, que no tienen analizador.
 *  Por gestor y no por nombre de distro: una lista de distros envejece y duplica la verdad. */
const TRIVY_OS_MANAGERS = ["apt", "dnf", "yum", "zypper", "apk"];

/**
 * Estado del análisis de paquetes del sistema. Pura, con plataforma y gestor por parámetro, para
 * que los tests cubran las tres plataformas desde una máquina. Devuelve un hecho y no prosa: la
 * frase la escribe el dashboard, que es quien sabe a quién se la cuenta. `systemScan` es el
 * sub-bloque de mergeScans, no el resultado entero: que falle el del sistema no anula el del home.
 */
function systemPackagesSupport(platform, pkgManager, opts = {}) {
  // rootfs quiere un árbol de paquetes de SO. macOS no lo tiene (Homebrew instala software del
  // usuario) y Windows tampoco, al menos no uno que Trivy entienda.
  if (platform !== "linux") return "not-applicable";
  if (!TRIVY_OS_MANAGERS.includes(pkgManager)) return "unsupported-manager";
  if (!opts.enabled) return "supported-not-run";
  if (!opts.systemScan || opts.systemScan.status !== "scanned") return "failed";
  return "scanned";
}

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

/** Ejecuta un comando de Trivy y devuelve su JSON parseado, o { skipped, reason }. */
async function runTrivyCommand(cmd, timeoutMs) {
  let stdout;
  try {
    stdout = await execCommand(cmd, timeoutMs);
  } catch (err) {
    // Con CVEs encontrados el código de salida no es cero, pero el JSON de stdout sigue valiendo.
    stdout = err.stdout || "";
    if (!stdout.trim()) {
      const stderr = (err.stderr || err.message || "unknown error").trim();
      // Una carpeta que no responde mata el escaneo entero, y la salida para el usuario no es
      // la de "trivy no está instalado": aquí lo que toca es acotar la carpeta a auditar.
      if (WALK_ERROR_RE.test(stderr)) {
        // El primer path absoluto del mensaje. Un "with (\S+)" genérico capturaba "traversal",
        // de "analyze with traversal:", que no dice nada.
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
      return { skipped: true, kind: "error", reason: `trivy failed: ${stderr}` };
    }
  }

  try {
    return JSON.parse(stdout);
  } catch (_) {
    return { skipped: true, kind: "error", reason: "trivy output is not valid JSON" };
  }
}

/** Paquetes del SO con el subcomando `rootfs`. Solo con el interruptor puesto: pide privilegios
 *  y tarda minutos. */
async function runTrivyRootfs(pkgManager) {
  if (process.platform !== "linux") {
    return { skipped: true, kind: "unsupported", reason: "rootfs solo aplica en Linux" };
  }

  // "Hay pacman" cubre Arch y todas sus derivadas, presentes y futuras. El nodo ya detectó el
  // gestor para el bloque de alcance, así que llega por parámetro y no se repite la ronda.
  const mgr = pkgManager || (await detectPackageManager());
  if (mgr === "pacman") {
    return { skipped: true, kind: "unsupported", reason: "Trivy no soporta pacman" };
  }

  const started = Date.now();
  const parsed = await runTrivyCommand(
    "trivy rootfs --format json --quiet --scanners vuln /",
    ROOTFS_TIMEOUT_MS
  );
  if (parsed.skipped) return parsed;

  parsed.scan = {
    mode: "rootfs",
    target: "/",
    skipDirs: [],
    durationMs: Date.now() - started,
    resolvedFrom: "systemPackages",
    trivyVersion: trivyVersion(),
  };
  return parsed;
}

/**
 * Concatenar `Results` basta: los dos lados producen elementos con la misma forma y en la ruta de
 * host nadie lee el envoltorio (ArtifactName, ArtifactType y SchemaVersion solo los usa audit-image).
 */
function mergeScans(home, system) {
  // Si el home falló, la auditoría aborta igual y el resultado del sistema no cambia nada.
  if (home.skipped) return home;

  if (system.skipped) {
    // Los Results del home quedan intactos y del sistema solo se anota el motivo: un límite de
    // la herramienta no puede tirar el trabajo que sí se hizo.
    home.scan.system = {
      attempted: true,
      status: system.kind === "unsupported" ? "unsupported" : "error",
      reason: system.reason || null,
      mode: "rootfs",
      target: "/",
      durationMs: null,
      results: 0,
    };
    return home;
  }

  const results = system.Results || [];
  home.Results.push(...results);
  home.scan.system = {
    attempted: true,
    status: "scanned",
    reason: null,
    mode: "rootfs",
    target: "/",
    durationMs: (system.scan && system.scan.durationMs) || null,
    results: results.length,
  };
  return home;
}

/**
 * Los dos escaneos se suman. Antes `systemPackages` hacía return antes de resolver el objetivo y
 * sustituía el del home: quien marcaba la casilla en Debian dejaba de auditar su carpeta personal
 * y el campo "Carpeta a auditar" quedaba anulado en silencio, con la casilla diciendo "también".
 * El home va primero porque el rootfs puede gastarse sus diez minutos de timeout. Secuencial y no
 * en paralelo: dos procesos de Trivy se pelean por la misma base de datos de vulnerabilidades.
 */
async function runTrivyFs(opts = {}) {
  const available = await commandExists("trivy");
  if (!available) {
    return { skipped: true, kind: "not-installed", reason: "trivy not installed" };
  }

  const { target, resolvedFrom } = resolveScanTarget(opts.target);
  const skipDirs = Array.isArray(opts.skipDirs) && opts.skipDirs.length
    ? opts.skipDirs
    : DEFAULT_SKIP_DIRS;

  // Si la carpeta la eligió el usuario va de una pasada: el ámbito lo acotó él y no hay que
  // protegerlo de sus propias unidades de red.
  const home = resolvedFrom === "config"
    ? await scanSingle(target, skipDirs, resolvedFrom)
    : await scanHomeByChildren(target, skipDirs, resolvedFrom);

  // Los paquetes del sistema solo a petición; el gate de plataforma y gestor vive en runTrivyRootfs.
  if (!opts.systemPackages) return home;

  const system = await runTrivyRootfs(opts.pkgManager);
  return mergeScans(home, system);
}

/** Una sola invocación de Trivy sobre `target`. */
async function scanSingle(target, skipDirs, resolvedFrom) {
  const skipFlag = skipDirs.length ? ` --skip-dirs "${absSkipDirs(target, skipDirs).join(",")}"` : "";
  const started = Date.now();
  const parsed = await runTrivyCommand(
    `trivy fs --format json --quiet --scanners vuln${skipFlag} "${target}"`,
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
 * Una pasada por hijo de primer nivel. Medido: con una sola invocación sobre el home, un
 * directorio que no responde aborta el escaneo completo —"walk dir error: fdopendir
 * …/CloudStorage/GoogleDrive-…: operation timed out"— y --skip-dirs no lo evita porque Trivy
 * recorre antes de filtrar (probado con "Library", "Library/CloudStorage", "…/*" y "…/**": los
 * cuatro fallan igual). Por hijo, el fallo queda en su carpeta y el resto del home sí se audita.
 * Los hijos que no son almacenamiento local se descartan antes, vía local-fs.js.
 * A cambio, los ficheros sueltos en la raíz del home no se miran: los proyectos viven en carpetas.
 */
async function scanHomeByChildren(home, skipDirs, resolvedFrom) {
  const started = Date.now();
  const absSkip = absSkipDirs(home, skipDirs);
  const skipFlag = absSkip.length ? ` --skip-dirs "${absSkip.join(",")}"` : "";

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
      `trivy fs --format json --quiet --scanners vuln${skipFlag} "${child}"`,
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
  mergeScans,
  resolveUserHome,
  resolveScanTarget,
  systemPackagesSupport,
  DEFAULT_SKIP_DIRS,
  TRIVY_OS_MANAGERS,
};
