"use strict";

/**
 * trivy-fs.js — Wrapper para Trivy filesystem scan (herramienta opcional).
 *
 * Sigue el patrón obligatorio de CLAUDE.md para herramientas opcionales:
 *   si trivy no está instalado → { skipped: true, reason: '...' }
 *
 * Comando (ámbito por defecto):
 *   trivy fs --format json --quiet --scanners vuln --skip-dirs <lista> <HOME>
 *
 * Ámbito: el HOME del usuario, IGUAL en las tres plataformas. Antes se
 * escaneaba territorio del gestor de paquetes (C:\Program Files, el Cellar de
 * Homebrew, /usr/lib). Era el mismo error de diseño replicado tres veces:
 *   - Trivy no analiza todos los gestores de SO (pacman, entre otros): en Arch
 *     el escaneo de /usr/lib no producía UN SOLO hallazgo accionable.
 *   - Lo que sí encontraba eran ficheros de bloqueo (Pipfile.lock, poetry.lock)
 *     empaquetados dentro de otros paquetes — dependencias DECLARADAS de
 *     terceros, no software instalado del usuario. Ver el campo `origin` en
 *     lib/finding-schema.js.
 * El software del sistema se audita ahora con el interruptor explícito
 * `systemPackages` (trivy rootfs), no por defecto.
 *
 * Exporta:
 *   runTrivyFs({ target, skipDirs, systemPackages }) → Promise<{
 *     skipped?: boolean,
 *     kind?: 'not-installed'|'unsupported'|'error',
 *     reason?: string,
 *     Results: Array<{ Target, Class, Type, Vulnerabilities: Array }>,
 *     scan: { mode, target, skipDirs, durationMs, resolvedFrom, trivyVersion }
 *   }>
 *   resolveUserHome()          → { home, resolvedFrom }
 *   systemPackagesSupport(...)  → estado del análisis de paquetes del sistema
 *   DEFAULT_SKIP_DIRS          → string[]
 *
 * ── Sobre `kind` ────────────────────────────────────────────────────────────
 * Un `skipped` no siempre es un fallo. Quien llama tiene que distinguir tres
 * naturalezas distintas, y hacerlo por el TEXTO de `reason` no vale: ese texto
 * cambia según la plataforma ("rootfs solo aplica en Linux" en macOS, "Trivy no
 * soporta pacman" en Arch) y ambos casos son lo mismo.
 *
 *   'not-installed' → falta la herramienta. El usuario puede arreglarlo.
 *   'unsupported'   → esta combinación de plataforma/gestor no se puede
 *                     analizar. NO es un error: la auditoría debe continuar y
 *                     el límite se comunica en el bloque de alcance.
 *   'error'         → el escaneo se intentó y se rompió. Sí es un error.
 */

const os = require("os");
const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");
const { execCommand, commandExists } = require("../../../lib/executor");
const { detectPackageManager } = require("../../../lib/pkg-manager");
const { classifyDir } = require("./local-fs");

const TIMEOUT_MS = 120000;
// Timeout POR HIJO al recorrer el home: acota lo que puede costar una carpeta
// que no responde, en vez de gastar el presupuesto entero del escaneo en ella.
const CHILD_TIMEOUT_MS = 90000;
// rootfs recorre TODO el sistema de ficheros: con el timeout de `fs` se cortaba
// a mitad y devolvía un JSON parcial que parecía un escaneo limpio.
const ROOTFS_TIMEOUT_MS = 600000;

/**
 * Directorios excluidos por defecto, relativos al objetivo del escaneo.
 *
 * Sobre la sintaxis de --skip-dirs (verificado con trivy 0.72.0, no supuesto):
 *   - Acepta rutas RELATIVAS al objetivo y ABSOLUTAS: ambas funcionan igual.
 *     Se usan relativas porque no dependen de dónde esté el home.
 *   - Separador: coma dentro de una sola flag, o la flag repetida. Equivalen.
 *   - TRAMPA: el sufijo "/*" excluye los HIJOS del directorio pero NO el
 *     directorio en sí ("junk/*" deja pasar junk/package-lock.json). Por eso
 *     ninguna entrada de esta lista lleva "/*".
 *   - Una ruta inexistente es inocua: no falla ni altera el resultado.
 *
 * node_modules NO se excluye a propósito: son dependencias reales de proyectos
 * del usuario y sus CVEs sí son accionables.
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

/**
 * Gestores de paquetes de sistema cuya base de datos Trivy sabe leer.
 *
 * Fuera quedan pacman (Arch y derivadas) y emerge (Gentoo): Trivy no tiene
 * analizador para ellos. Se gestiona por GESTOR y no por nombre de distribución
 * por el mismo motivo que el gate de runTrivyRootfs(): una lista de nombres de
 * distro envejece y sería una segunda fuente de verdad sobre el mismo hecho.
 */
const TRIVY_OS_MANAGERS = ["apt", "dnf", "yum", "zypper", "apk"];

/**
 * ¿Se han analizado —o se podrían analizar— los paquetes del sistema?
 *
 * Función PURA: recibe plataforma y gestor por parámetro en vez de leer
 * process.platform, para que los tests cubran las tres plataformas desde una
 * sola máquina. Devuelve un HECHO, no prosa: el texto para el usuario lo pone
 * el dashboard, que es quien sabe a quién se lo está contando.
 *
 * @param {string} platform            'linux'|'darwin'|'win32'
 * @param {string|null} pkgManager     salida de detectPackageManager()
 * @param {{enabled?: boolean, systemScan?: Object}} [opts]
 *        enabled    → el interruptor "Analizar paquetes del sistema" del nodo
 *        systemScan → sub-bloque parsed.scan.system que dejó mergeScans().
 *                     Se mira ESE y no el resultado entero: desde que los dos
 *                     escaneos se suman, que falle el del sistema ya no marca
 *                     como `skipped` el resultado global — el del home sigue ahí.
 * @returns {'scanned'|'supported-not-run'|'unsupported-manager'|'not-applicable'|'failed'}
 */
function systemPackagesSupport(platform, pkgManager, opts = {}) {
  // rootfs recorre un árbol de paquetes de SO. macOS (Homebrew instala software
  // del usuario, no del sistema) y Windows no tienen uno que Trivy entienda.
  if (platform !== "linux") return "not-applicable";
  if (!TRIVY_OS_MANAGERS.includes(pkgManager)) return "unsupported-manager";
  if (!opts.enabled) return "supported-not-run";
  if (!opts.systemScan || opts.systemScan.status !== "scanned") return "failed";
  return "scanned";
}

/**
 * Home de un usuario concreto del sistema, consultando la base de datos real
 * de usuarios. Devuelve null si no se puede determinar o el directorio no existe.
 *
 * @param {string} user
 * @returns {string|null}
 */
function homeForUser(user) {
  if (!user || process.platform === "win32") return null;

  const probes = process.platform === "darwin"
    ? [`dscl . -read /Users/${user} NFSHomeDirectory`]
    : [`getent passwd ${user}`];

  for (const cmd of probes) {
    try {
      const out = execSync(cmd, { timeout: 5000, stdio: ["ignore", "pipe", "ignore"] })
        .toString().trim();
      // dscl → "NFSHomeDirectory: /Users/ana" · getent → "ana:x:1000:1000::/home/ana:/bin/bash"
      const home = process.platform === "darwin"
        ? (out.split(":")[1] || "").trim()
        : (out.split(":")[5] || "").trim();
      if (home && fs.existsSync(home)) return home;
    } catch (_) { /* usuario inexistente o comando no disponible → siguiente señal */ }
  }

  const base = HOME_BASE[process.platform];
  const guess = base ? path.join(base, user) : null;
  return guess && fs.existsSync(guess) ? guess : null;
}

/**
 * Resuelve el home de la PERSONA que audita, no el del proceso.
 *
 * Node-RED puede correr como servicio (systemd, launchd) bajo otro usuario: en
 * ese caso os.homedir() devuelve /root o /var/lib/node-red y se auditaría un
 * directorio vacío que no es el del usuario. De ahí el orden explícito.
 *
 * @returns {{ home: string, resolvedFrom: 'SUDO_USER'|'env'|'os.homedir' }}
 */
function resolveUserHome() {
  // 1. Lanzado con sudo: el home real es el del usuario original, no el de root.
  const sudoUser = process.env.SUDO_USER;
  if (sudoUser) {
    const h = homeForUser(sudoUser);
    if (h) return { home: h, resolvedFrom: "SUDO_USER" };
  }

  // 2. Entorno del proceso. Solo se acepta si el directorio existe de verdad.
  const env = process.env.HOME || process.env.USERPROFILE;
  if (env && fs.existsSync(env)) return { home: env, resolvedFrom: "env" };

  // 3. Último recurso: registro de usuarios del proceso actual.
  return { home: os.homedir(), resolvedFrom: "os.homedir" };
}

/**
 * Objetivo final del escaneo: lo configurado en el nodo, o el home del usuario.
 * Expande "~" y "~/sub" contra el home resuelto.
 *
 * @param {string} [configured]  Valor del campo del nodo (puede venir vacío).
 * @returns {{ target: string, resolvedFrom: string }}
 */
function resolveScanTarget(configured) {
  const { home, resolvedFrom } = resolveUserHome();
  const raw = String(configured || "").trim();
  if (!raw) return { target: home, resolvedFrom };

  if (raw === "~") return { target: home, resolvedFrom: "config" };
  if (raw.startsWith("~/")) return { target: path.join(home, raw.slice(2)), resolvedFrom: "config" };
  return { target: raw, resolvedFrom: "config" };
}

/**
 * Versión de Trivy instalada. Se registra en el resultado para poder distinguir,
 * ante un cambio futuro en la forma de los hallazgos, si lo cambió nuestro
 * código o la herramienta.
 *
 * @returns {string|null}
 */
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
    // trivy puede salir con código != 0 si encuentra CVEs — la salida sigue siendo JSON válido
    stdout = err.stdout || "";
    if (!stdout.trim()) {
      const stderr = (err.stderr || err.message || "unknown error").trim();
      // Un directorio que no responde (unidad de red, nube montada, permisos)
      // mata el escaneo ENTERO. Se distingue del "trivy no está instalado"
      // porque la salida para el usuario es otra: acotar la carpeta a auditar.
      if (WALK_ERROR_RE.test(stderr)) {
        // La ruta es el primer path absoluto del mensaje. Un "with (\S+)" genérico
        // capturaba "traversal" de "analyze with traversal:", que no dice nada.
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

/**
 * Escaneo del sistema de ficheros raíz (paquetes del SO). Solo se ejecuta con el
 * interruptor `systemPackages` activo: requiere privilegios y tarda minutos.
 *
 * Se usa `rootfs`, que es el subcomando pensado para un árbol raíz completo.
 *
 * @returns {Promise<Object>}
 */
async function runTrivyRootfs(pkgManager) {
  if (process.platform !== "linux") {
    return { skipped: true, kind: "unsupported", reason: "rootfs solo aplica en Linux" };
  }

  // Gate por GESTOR, no por nombre de distribución: el hecho real es que Trivy
  // no tiene analizador para pacman. Detectar "hay pacman" cubre Arch y todas
  // sus derivadas (CachyOS, Manjaro, EndeavourOS, Garuda, Artix…) presentes y
  // futuras; una lista de nombres de distro envejece y sería una segunda fuente
  // de verdad sobre el mismo hecho.
  // El nodo ya detectó el gestor para el bloque de alcance: se acepta por
  // parámetro para no repetir la ronda de commandExists.
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
 * Fusiona el escaneo del home con el de los paquetes del sistema.
 *
 * Concatenar `Results` es TODO lo que hace falta: los dos lados producen
 * elementos con la misma forma ({ Target, Class, Type, Packages,
 * Vulnerabilities }) y nada de la ruta de host lee el envoltorio
 * (ArtifactName/ArtifactType/SchemaVersion solo los consume audit-image).
 *
 * @param {Object} home    resultado de scanSingle/scanHomeByChildren
 * @param {Object} system  resultado de runTrivyRootfs
 * @returns {Object}
 */
function mergeScans(home, system) {
  // El home ya falló: la auditoría va a abortar igualmente (kind 'error' o
  // 'not-installed') y el resultado del sistema no cambia esa decisión.
  if (home.skipped) return home;

  if (system.skipped) {
    // El punto importante: los Results del home quedan INTACTOS y del sistema
    // solo se anota el motivo. Un límite conocido de la herramienta no puede
    // tirar el trabajo que sí se hizo — mismo principio que el gate del nodo.
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
 * Ejecuta Trivy sobre el home del usuario (o el objetivo configurado) y, si se
 * pide, TAMBIÉN sobre los paquetes del sistema.
 *
 * Los dos escaneos se SUMAN. Antes `systemPackages` hacía `return` antes de
 * resolver el objetivo, así que sustituía el escaneo del home en vez de
 * añadirse: un usuario de Debian que marcaba la casilla dejaba de auditar su
 * carpeta personal, y de paso el campo "Carpeta a auditar" del nodo quedaba
 * anulado en silencio. La casilla dice "analizar TAMBIÉN", y hacía lo contrario.
 *
 * Orden deliberado: el home PRIMERO. El rootfs puede consumir sus diez minutos
 * de timeout, y cuando eso ocurra el resultado del home ya está en la mano.
 * Secuencial y no en paralelo, además, para no poner dos procesos de Trivy a
 * competir por la misma base de datos de vulnerabilidades.
 *
 * @param {{ target?: string, skipDirs?: string[], systemPackages?: boolean,
 *           pkgManager?: string }} [opts]
 * @returns {Promise<Object>}
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

  // 1. El HOME, siempre. Carpeta elegida a mano por el usuario: una sola pasada.
  //    Ha acotado el ámbito él, no hay que protegerlo de sus propias unidades
  //    de red.
  const home = resolvedFrom === "config"
    ? await scanSingle(target, skipDirs, resolvedFrom)
    : await scanHomeByChildren(target, skipDirs, resolvedFrom);

  // 2. Los paquetes del sistema, solo a petición. El gate por plataforma y por
  //    gestor vive dentro de runTrivyRootfs.
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

  // Procedencia del escaneo: el dashboard muestra QUÉ carpeta se auditó, y
  // trivyVersion permite atribuir un cambio de forma en los hallazgos.
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

/**
 * Los --skip-dirs se pasan en ABSOLUTO. Al escanear el home por hijos, la raíz
 * cambia en cada invocación y una ruta relativa como "go/pkg/mod" ya no casaría.
 * Ambas formas son válidas para Trivy (verificado en 0.72.0).
 */
function absSkipDirs(home, skipDirs) {
  return skipDirs.map((d) => (path.isAbsolute(d) ? d : path.join(home, d)));
}

/**
 * Escanea el home recorriendo sus hijos de primer nivel, uno a uno.
 *
 * Motivo (medido, no teórico): con una sola invocación sobre el home, un
 * directorio que no responde aborta el escaneo COMPLETO —
 *   FATAL … walk dir error: fdopendir …/CloudStorage/GoogleDrive-…: operation timed out
 * — y --skip-dirs NO lo evita, porque Trivy recorre antes de filtrar
 * (comprobado con "Library", "Library/CloudStorage", "…/*" y "…/**": los cuatro
 * fallan igual). Con una invocación por hijo, ese fallo queda acotado a su
 * carpeta y el resto del home sí se audita.
 *
 * Además, antes de escanear se descartan los hijos que NO están en
 * almacenamiento local (unidades de red, nube sincronizada), detectados de
 * forma nativa por plataforma en local-fs.js: quedan fuera de ámbito por
 * definición, no por limitación técnica.
 *
 * Limitación conocida: los ficheros SUELTOS en la raíz del home (un
 * package-lock.json en ~/) no se analizan, porque cada pasada arranca en un
 * subdirectorio. En la práctica los proyectos viven en carpetas.
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
    if (!entry.isDirectory()) continue;               // ficheros sueltos: ver limitación
    const child = path.join(home, entry.name);

    // Excluido por configuración (mismo criterio que --skip-dirs, aplicado aquí
    // porque un hijo entero no hace falta ni abrirlo).
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
      // Aquí está la ganancia: el hijo problemático se anota y se sigue.
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
