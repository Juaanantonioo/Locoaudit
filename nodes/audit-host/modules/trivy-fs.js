"use strict";

/** Trivy sobre el HOME del usuario (los paquetes del SO van en lib/trivy-rootfs.js).
 *  Si no puede escanear devuelve { skipped, kind, reason }; 'unsupported' no es un error. */

const os = require("os");
const fs = require("fs");
const path = require("path");
const { execSync, execFileSync } = require("child_process");
const { ejecutarAFichero, ejecutar, existeComando } = require("../../../lib/executor");
const { clasificarCarpeta } = require("./local-fs");

const TIMEOUT_MS = 120000;
// Por hijo: así una carpeta que no responde se lleva su tiempo, no el del escaneo entero.
const CHILD_TIMEOUT_MS = 90000;

/** Exclusiones por defecto, relativas al objetivo. Sin sufijo "/*", que dejaría fuera los hijos pero no el directorio.
 *  node_modules se queda dentro: son dependencias reales del usuario. */
const DEFAULT_SKIP_DIRS = [
  ".cache",                // cachés de herramientas: nada que parchear
  ".local/share/Trash",    // papelera: ficheros ya descartados
  ".cargo/registry",       // fuentes descargadas de crates, no compiladas ni usadas
  "go/pkg/mod",            // módulos Go en caché, idem
  ".npm",                  // caché de npm (≠ node_modules, que sí se escanea)
];

/** Exclusiones extra de la pasada de secretos: software de terceros y datos de aplicaciones que solo gastan tiempo.
 *  Los patrones con "**" son relativos a cada carpeta escaneada. */
const SECRET_SKIP_DIRS = [
  ...DEFAULT_SKIP_DIRS,
  "Library", ".local/share", "Movies", "Music", "Pictures",
  ".vscode/extensions", ".vscode-server", ".antigravity/extensions", ".cursor/extensions", ".windsurf/extensions",
  ".m2/repository", ".m2/wrapper", ".gradle", ".rustup", ".nvm", ".pyenv", ".cargo", ".claude/plugins",
  // Juegos de pruebas de seguridad: traen credenciales de ejemplo a propósito.
  "nuclei-templates", "SecLists", "PayloadsAllTheThings", "metasploit-framework", "exploitdb",
  "**/node_modules", "**/.git", "**/.venv", "**/venv", "**/site-packages", "**/__pycache__",
];

/** Hijos que la pasada de secretos analiza a la vez: usa la caché en memoria, así que no compiten por un bloqueo. */
const SECRET_CONCURRENCY = 3;
/** Por hijo, en la pasada de secretos: lee el contenido de los ficheros y no solo los manifiestos. */
const SECRET_CHILD_TIMEOUT_MS = 180000;

/** Ficheros de la raíz del home donde suele haber credenciales; la pasada por hijos no los ve. */
const ROOT_SECRET_FILES = [
  ".netrc", ".git-credentials", ".npmrc", ".pypirc", ".env",
  ".bash_history", ".zsh_history", ".psql_history", ".mysql_history",
];

/** Error de recorrido del sistema de ficheros (montaje que no responde, permisos). */
const WALK_ERROR_RE = /walk dir error|fdopendir|operation timed out|permission denied/i;

/** Prefijos de home por plataforma, para el fallback de homeDeUsuario(). */
const HOME_BASE = { darwin: "/Users", linux: "/home" };

/** Home de un usuario según la base de datos real del sistema; null si no existe el directorio. */
function homeDeUsuario(user) {
  if (!user || process.platform === "win32") return null;

  // Sin shell: SUDO_USER es un dato del entorno y no puede acabar interpretado.
  let probes;
  if (process.platform === "darwin") {
    probes = [["dscl", [".", "-read", `/Users/${user}`, "NFSHomeDirectory"]]];
  } else {
    probes = [["getent", ["passwd", user]]];
  }

  for (const [file, args] of probes) {
    try {
      const out = execFileSync(file, args, { timeout: 5000, stdio: ["ignore", "pipe", "ignore"] })
        .toString().trim();
      // dscl da "NFSHomeDirectory: /Users/ana"; getent, "ana:x:1000:1000::/home/ana:/bin/bash".
      let home;
      if (process.platform === "darwin") {
        home = (out.split(":")[1] || "").trim();
      } else {
        home = (out.split(":")[5] || "").trim();
      }
      if (home && fs.existsSync(home)) return home;
    } catch (_) { /* usuario inexistente o comando ausente: se prueba la siguiente señal */ }
  }

  const base = HOME_BASE[process.platform];
  let guess;
  if (base) {
    guess = path.join(base, user);
  } else {
    guess = null;
  }
  if (guess && fs.existsSync(guess)) {
    return guess;
  } else {
    return null;
  }
}

/** El home de quien audita, no el del proceso: como servicio, os.homedir() da /root o /var/lib/node-red. */
function resolverHome() {
  // Con sudo el home real es el del usuario original, no el de root.
  const sudoUser = process.env.SUDO_USER;
  if (sudoUser) {
    const h = homeDeUsuario(sudoUser);
    if (h) return { home: h, resolvedFrom: "SUDO_USER" };
  }

  // Del entorno, y solo si el directorio existe de verdad.
  const env = process.env.HOME || process.env.USERPROFILE;
  if (env && fs.existsSync(env)) return { home: env, resolvedFrom: "env" };

  // Último recurso: el registro de usuarios del proceso actual.
  return { home: os.homedir(), resolvedFrom: "os.homedir" };
}

/** Lo configurado en el nodo o, si viene vacío, el home. Expande "~" y "~/sub" contra ese home. */
function resolverObjetivo(configured) {
  const { home, resolvedFrom } = resolverHome();
  const raw = String(configured || "").trim();
  if (!raw) return { target: home, resolvedFrom, home };

  if (raw === "~") return { target: home, resolvedFrom: "config", home };
  if (raw.startsWith("~/")) return { target: path.join(home, raw.slice(2)), resolvedFrom: "config", home };
  return { target: raw, resolvedFrom: "config", home };
}

/** Versión de Trivy, guardada con el resultado para diagnosticar cambios en su salida. */
function versionTrivy() {
  try {
    const out = execSync("trivy --version", { timeout: 5000, stdio: ["ignore", "pipe", "ignore"] }).toString();
    const m = out.match(/Version:\s*(\S+)/i);
    if (m) {
      return m[1];
    } else {
      return out.split("\n")[0].trim() || null;
    }
  } catch (_) {
    return null;
  }
}

/** Ejecuta Trivy vía ejecutarAFichero y devuelve su JSON, o { skipped, kind, reason }. */
async function ejecutarTrivy(buildCmd, timeoutMs) {
  const parsed = await ejecutarAFichero(buildCmd, timeoutMs, { prefix: "lcaudit-trivy-fs-" });
  if (!parsed.skipped) return parsed;

  // Un buffer rebasado es un límite nuestro, no un JSON corrupto de Trivy.
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
    // Trivy escribe sus errores en el mismo fichero: el principio suele ser el mensaje real.
    const detail = parsed.reason || "";
    if (WALK_ERROR_RE.test(detail)) return errorAlRecorrer(detail);
    return { skipped: true, kind: "invalid-json", reason: detail };
  }

  // Una carpeta que no responde tiene mensaje propio: la acción es acotar la carpeta, no reinstalar.
  const detail = parsed.reason || "unknown error";
  if (WALK_ERROR_RE.test(detail)) return errorAlRecorrer(detail);
  return { skipped: true, kind: parsed.kind || "error", reason: `Trivy terminó con error: ${detail}` };
}

/** Carpeta que no responde: mensaje propio, porque la acción del usuario es distinta. */
function errorAlRecorrer(stderr) {
  // El primer path absoluto del mensaje (un patrón genérico capturaba "traversal").
  const m = stderr.match(/(\/[^\s:]+)/);
  let ruta;
  let carpeta;
  if (m) {
    ruta = m[1];
    carpeta = m[1];
  } else {
    ruta = null;
    carpeta = "una carpeta del ámbito";
  }
  // Una ruta que no existe no es una unidad colgada: el consejo sería el equivocado.
  if (/no such file or directory/i.test(stderr)) {
    return {
      skipped: true,
      kind: "error",
      walkError: true,
      path: ruta,
      reason: `Trivy no pudo recorrer ${carpeta}: la carpeta no existe ` +
              `o desapareció durante el análisis. Detalle: ${stderr}`,
    };
  }
  return {
    skipped: true,
    kind: "error",
    walkError: true,
    path: ruta,
    reason:
      `Trivy no pudo recorrer ${carpeta}: la carpeta no responde ` +
      "(unidad de red o almacenamiento en la nube montado) o no hay permisos. El escaneo se " +
      "aborta por completo y --skip-dirs no lo evita. Indica una carpeta concreta en el campo " +
      `"Carpeta a auditar" del nodo, o desmonta esa unidad. Detalle: ${stderr}`,
  };
}

/** Escaneo del HOME. El existeComando va aquí porque audit-image también llama a Trivy. */
async function ejecutarTrivyFs(opts = {}) {
  const available = await existeComando("trivy");
  if (!available) {
    return { skipped: true, kind: "not-installed", reason: "Trivy no está instalado en este equipo" };
  }

  const { target, resolvedFrom, home } = resolverObjetivo(opts.target);
  if (resolvedFrom === "config" && !fs.existsSync(target)) {
    return {
      skipped: true,
      kind: "error",
      reason: `La carpeta indicada en "Carpeta a auditar" no existe: ${target}. ` +
              "Revisa la ruta en las opciones del nodo; recuerda que ~ es tu carpeta personal.",
    };
  }
  let skipDirs;
  if (Array.isArray(opts.skipDirs) && opts.skipDirs.length) {
    skipDirs = opts.skipDirs;
  } else {
    skipDirs = DEFAULT_SKIP_DIRS;
  }

  const scanners = opts.scanners || "vuln";

  // Una carpeta elegida va de una pasada; el home, aunque se escriba a mano, carpeta a carpeta.
  const esHome = path.resolve(target) === path.resolve(home);
  if (resolvedFrom === "config" && !esHome) {
    return await escanearDeUnaVez(target, skipDirs, resolvedFrom, scanners);
  } else {
    return await escanearPorCarpetas(target, skipDirs, resolvedFrom, scanners);
  }
}

/** Secretos y configuraciones inseguras en el mismo ámbito que ejecutarTrivyFs. Pasada aparte: si se corta,
 *  la de vulnerabilidades no pierde su resultado. */
async function ejecutarTrivySecretos(opts = {}) {
  return ejecutarTrivyFs({ skipDirs: SECRET_SKIP_DIRS, ...opts, scanners: "secret,misconfig" });
}

/** Orden de Trivy como array, sin shell; "--" evita que una carpeta que empiece por "-" se lea como opción.
 *  Los secretos usan la caché en memoria para no competir por el bloqueo de la de disco. */
function argumentosTrivyFs(file, target, skipArgs, scanners = "vuln") {
  let cache;
  if (scanners === "vuln") {
    cache = [];
  } else {
    cache = ["--cache-backend", "memory"];
  }
  return ["trivy", "fs", "--format", "json", "--quiet", "--scanners", scanners, ...cache, ...skipArgs, "-o", file, "--", target];
}

/** Una sola invocación de Trivy sobre `target`. */
async function escanearDeUnaVez(target, skipDirs, resolvedFrom, scanners = "vuln") {
  let skipArgs;
  if (skipDirs.length) {
    skipArgs = ["--skip-dirs", carpetasExcluidas(target, skipDirs).join(",")];
  } else {
    skipArgs = [];
  }
  const started = Date.now();
  const parsed = await ejecutarTrivy(
    (file) => argumentosTrivyFs(file, target, skipArgs, scanners),
    TIMEOUT_MS
  );
  if (parsed.skipped) return parsed;

  // Las rutas de Trivy son relativas a lo escaneado: con la raíz se sabe dónde está cada fichero.
  for (const r of parsed.Results || []) r.__root = target;

  // El dashboard muestra qué carpeta se auditó.
  parsed.scan = {
    mode: "fs",
    scanners,
    target,
    skipDirs,
    durationMs: Date.now() - started,
    resolvedFrom,
    trivyVersion: versionTrivy(),
  };
  return parsed;
}

/** Una pasada de Trivy por carpeta, `n` a la vez. Devuelve nombre → { child, res, ms }. */
async function escanearEnParalelo(items, skipArgs, scanners, timeout, n) {
  const out = new Map();
  let i = 0;
  const trabajador = async () => {
    while (i < items.length) {
      const { name, child } = items[i++];
      const t0 = Date.now();
      const res = await ejecutarTrivy((file) => argumentosTrivyFs(file, child, skipArgs, scanners), timeout);
      out.set(name, { child, res, ms: Date.now() - t0 });
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, n) }, trabajador));
  return out;
}

/** En absoluto: al escanear por hijos la raíz cambia en cada pasada. */
function carpetasExcluidas(home, skipDirs) {
  return skipDirs.map((d) => {
    if (path.isAbsolute(d) || d.includes("*")) {
      return d;
    } else {
      return path.join(home, d);
    }
  });
}

/** Una pasada por hijo de primer nivel: así un directorio que no responde solo falla él (--skip-dirs no lo evita).
 *  Los hijos que no son almacenamiento local se descartan antes con local-fs.js. */
async function escanearPorCarpetas(home, skipDirs, resolvedFrom, scanners = "vuln") {
  const started = Date.now();
  const absSkip = carpetasExcluidas(home, skipDirs);
  let skipArgs;
  if (absSkip.length) {
    skipArgs = ["--skip-dirs", absSkip.join(",")];
  } else {
    skipArgs = [];
  }

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

    // Mismo criterio que --skip-dirs, sin llegar a entrar en el hijo.
    if (absSkip.includes(child)) {
      skippedChildren.push({ name: entry.name, kind: "excluded", reason: "en la lista de exclusiones" });
      continue;
    }

    const cls = clasificarCarpeta(child);
    if (!cls.local) {
      skippedChildren.push({ name: entry.name, kind: cls.kind, reason: cls.detail });
      continue;
    }
    pendientes.push({ name: entry.name, child });
  }

  // La de vulnerabilidades va de uno en uno (comparte la caché en disco); la de secretos, de tres en tres.
  const isVuln = scanners === "vuln";
  let timeout;
  if (isVuln) {
    timeout = CHILD_TIMEOUT_MS;
  } else {
    timeout = SECRET_CHILD_TIMEOUT_MS;
  }
  let concurrencia;
  if (isVuln) {
    concurrencia = 1;
  } else {
    concurrencia = SECRET_CONCURRENCY;
  }
  const porHijo = await escanearEnParalelo(pendientes, skipArgs, scanners, timeout, concurrencia);

  // Secretos: una carpeta que agota el tiempo se reintenta por subcarpetas (sus ficheros sueltos no se miran).
  if (!isVuln) {
    for (const p of pendientes) {
      const hit = porHijo.get(p.name);
      if (!hit.res.skipped || hit.res.kind !== "timeout") continue;
      let subs;
      try { subs = fs.readdirSync(p.child, { withFileTypes: true }); } catch (_) { continue; }
      const subPend = subs
        .filter((e) => e.isDirectory())
        .map((e) => ({ name: `${p.name}/${e.name}`, child: path.join(p.child, e.name) }))
        .filter((x) => !absSkip.includes(x.child) && clasificarCarpeta(x.child).local);
      const subRes = await escanearEnParalelo(subPend, skipArgs, scanners, timeout, SECRET_CONCURRENCY);
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
      const res = await ejecutarTrivy((out) => argumentosTrivyFs(out, file, [], scanners), CHILD_TIMEOUT_MS);
      if (res.skipped) {
        skippedChildren.push({ name, kind: "error", reason: res.reason });
        continue;
      }
      for (const r of res.Results || []) r.__root = home;
      merged.Results.push(...(res.Results || []));
      rootFiles.push(name);
    }
  }

  // Si no se pudo analizar nada y hubo fallos, es un escaneo fallido, no un home limpio.
  const fallidas = skippedChildren.filter((c) => c.kind === "error");
  if (scanned.length === 0 && rootFiles.length === 0 && fallidas.length > 0) {
    return {
      skipped: true,
      kind: "error",
      reason:
        `Trivy falló en todas las carpetas del home (${fallidas.length}). ` +
        `Primer error, en ${fallidas[0].name}: ${fallidas[0].reason}`,
    };
  }

  merged.scan = {
    mode: "fs-by-children",
    scanners,
    target: home,
    skipDirs,
    durationMs: Date.now() - started,
    resolvedFrom,
    trivyVersion: versionTrivy(),
    children: { scanned, skipped: skippedChildren },
    rootFiles,
  };
  return merged;
}

module.exports = {
  ejecutarTrivyFs,
  ejecutarTrivySecretos,
  SECRET_SKIP_DIRS,
  resolverHome,
  resolverObjetivo,
  DEFAULT_SKIP_DIRS,
};
