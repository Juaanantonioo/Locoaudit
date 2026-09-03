"use strict";

/**
 * Actualizaciones pendientes del sistema. Solo LISTA: este módulo no instala, no actualiza y no
 * sincroniza bases de datos de paquetes. Nada de lo que ejecuta modifica el equipo auditado.
 *
 * Mismo contrato que lynis.js y trivy-fs.js: si no se puede mirar devuelve
 * { skipped, kind, reason } y quien llama decide por `kind`, nunca por el texto de `reason`.
 * De los cuatro kinds solo 'unsupported' no es un fallo: ahí la plataforma o el gestor quedan
 * fuera de lo que LoCoAudit sabe leer, y la auditoría sigue sin este módulo.
 *
 * "Cero actualizaciones pendientes" es un dato real y sale como resultado normal con total 0.
 * No se confunde con un skip: lo primero significa "miré y no hay", lo segundo "no pude mirar".
 *
 * Marcar cuáles son de seguridad solo se hace donde la plataforma lo indique de forma nativa.
 * `securityDetection` dice hasta dónde llega esa capacidad: 'full' cuando el gestor clasifica
 * todas las actualizaciones, 'none' cuando no clasifica ninguna, y 'partial' en macOS, que sabe
 * de los datos de protección (XProtect, MRT, Gatekeeper) y no de las del propio sistema. Con
 * 'none' el recuento va a null: inventarlo a partir de nombres de paquete sería peor que no darlo.
 */

const fs = require("fs");
const path = require("path");
const { execCommand, commandExists, runPowerShell } = require("../../../lib/executor");

const MACOS_TIMEOUT_MS   = 90000;    // --no-scan no va a la red, pero softwareupdate arranca lento
const LINUX_TIMEOUT_MS   = 60000;
const WINDOWS_TIMEOUT_MS = 180000;   // la búsqueda COM tarda minutos en un equipo con muchas pendientes

/** Ruta de las bases sincronizadas de pacman, para poder decir cuántos días tienen. */
const PACMAN_SYNC_DIR = "/var/lib/pacman/sync";

/**
 * Actualizaciones de DATOS de protección de macOS, que son las únicas que softwareupdate deja
 * identificar como de seguridad. Lista explícita y no un heurístico de formato: la etiqueta de
 * estas entradas no tiene una forma fija en la que confiar.
 *
 * Los tres nombres salen de lo que este sistema registra de verdad, comprobado con
 * `pkgutil --pkgs` (com.apple.pkg.XProtectPlistConfigData_10_15, .XProtectPayloads_10_15,
 * .MRTConfigData_10_15, .GatekeeperCompatibilityData) y con
 * `system_profiler SPInstallHistoryDataType` (que añade XProtectCloudKitUpdate y escribe
 * Gatekeeper con espacios). De ahí que Gatekeeper acepte las dos grafías.
 *
 * Fuera a propósito: RosettaUpdateAuto y CLTools, que llegan por la misma vía silenciosa pero no
 * son actualizaciones de seguridad. Y TCC, que no aparece por ninguna vía en este sistema: sin
 * evidencia de que Apple lo distribuya así, una entrada especulativa en esta lista sobra.
 */
const MACOS_SECURITY_DATA = [
  /^XProtect/i,                              // XProtectPlistConfigData, XProtectPayloads, XProtectCloudKitUpdate
  /^MRT/i,                                   // MRTConfigData
  /^Gatekeeper\s*Compatibility\s*Data/i,     // con y sin espacios
];

/** Solo para enriquecer la entrada del sistema; que falle no invalida el listado. */
const SW_VERS_TIMEOUT_MS = 5000;

/** Gestores de Linux que este módulo sabe consultar. Fuera de la lista, kind 'unsupported'. */
const LINUX_MANAGERS = ["pacman", "apt", "dnf", "yum", "zypper", "apk"];

/** Mismo criterio que lynis.js: child_process mata por timeout con SIGTERM y marca killed. */
function isTimeout(err) {
  return Boolean(err && (err.killed || err.signal === "SIGTERM"));
}

/** Skip a partir de un fallo de exec. El sujeto es LoCoAudit, no el equipo del usuario. */
function execSkip(err, cmd, what, timeoutMs) {
  if (isTimeout(err)) {
    return {
      skipped: true,
      kind: "timeout",
      reason:
        `LoCoAudit no ha podido consultar ${what}: el comando \`${cmd}\` superó el límite de ` +
        `${timeoutMs / 1000} s sin terminar.`,
    };
  }
  return {
    skipped: true,
    kind: "error",
    // Motivo LEGIBLE, sin el volcado. La evidencia que lee el usuario llegó a mostrar
    // "ParserError: ParentContainsErrorRecordException" y ocho líneas de traza de PowerShell:
    // eso no le dice nada a quien audita su portátil, y tapa la única frase que sí le sirve.
    reason: `LoCoAudit no ha podido consultar ${what}: el comando \`${cmd}\` falló.`,
    // El volcado íntegro viaja aparte y llega a la exportación JSON por raw.pendingUpdates.
    // Sin él, el siguiente diagnóstico empieza de cero; dentro de `reason`, es ruido.
    detail: firstLines(err && (err.stderr || err.message), RAW_DETAIL_LINES),
  };
}

/** Cuántas líneas del volcado se guardan: suficientes para diagnosticar, no un log entero. */
const RAW_DETAIL_LINES = 40;

/** Primeras N líneas no vacías de una salida, o null si no hay nada. */
function firstLines(texto, n) {
  const t = String(texto || "").trim();
  if (!t) return null;
  const lineas = t.split("\n").map((l) => l.trimEnd()).filter((l) => l.length);
  const cortado = lineas.slice(0, n);
  if (lineas.length > n) cortado.push(`… (${lineas.length - n} líneas más omitidas)`);
  return cortado.join("\n");
}

/** Una actualización, con la misma forma en las tres plataformas. */
function update(name, fields = {}) {
  return {
    name,
    // La versión instalada solo la dan los gestores que comparan contra el sistema: pacman, apt,
    // zypper y apk. softwareupdate, Windows Update y `dnf check-update` informan de lo que hay
    // disponible y no de lo que hay puesto, así que aquí queda null. Es el campo del que depende
    // que el normalizador pinte "instalada → nueva": sin él no hay comparación que enseñar.
    currentVersion: fields.currentVersion || null,
    newVersion:     fields.newVersion || null,
    // null (y no false) donde no se sabe: "no consta" no es "no lo es". En macOS conviven las
    // dos cosas —los datos de protección salen true y las del sistema null— y esa mezcla es
    // justo lo que securityDetection: 'partial' anuncia.
    security:       fields.security === undefined ? null : fields.security,
    // Solo macOS: 'restart' | 'shut down' | null.
    action:         fields.action || null,
    sizeKiB:        fields.sizeKiB == null ? null : fields.sizeKiB,
    // apt: el sufijo del repositorio, guardado como evidencia aunque no se use para marcar.
    suite:          fields.suite || null,
    label:          fields.label || null,
    // Solo Windows: las señales con las que se clasificó, para que la exportación JSON permita
    // auditar por qué una entrada quedó como `security: null` sin repetir la consulta.
    categories:     Array.isArray(fields.categories) ? fields.categories : null,
    msrcSeverity:   fields.msrcSeverity || null,
  };
}

// ── macOS ────────────────────────────────────────────────────────────────────

/**
 * Dos líneas por actualización: `* Label: <etiqueta>` y una tabulada con pares `Clave: valor,`.
 * Los títulos traen espacios duros (U+00A0), comprobado en la salida real de macOS 26: sin
 * normalizarlos, cualquier `\s` del parseo se comporta distinto según el título.
 */
function parseSoftwareUpdateList(text) {
  const clean = String(text || "").replace(/ /g, " ");
  const lines = clean.split("\n");
  const updates = [];

  for (let i = 0; i < lines.length; i++) {
    const m = /^\s*\*\s*(?:Label:\s*)?(.+?)\s*$/.exec(lines[i]);
    if (!m) continue;
    const label = m[1];

    // La línea de detalle va tabulada justo detrás. Si falta, la entrada vale igual: se conoce
    // la etiqueta y eso ya es una actualización pendiente.
    const detail = (lines[i + 1] || "").startsWith("\t") ? lines[i + 1] : "";
    const pick = (key) => {
      const r = new RegExp(key + ":\\s*([^,]*)").exec(detail);
      return r ? r[1].trim() : null;
    };

    const sizeRaw = pick("Size");
    const sizeKiB = sizeRaw ? parseInt(sizeRaw.replace(/[^0-9]/g, ""), 10) : null;
    const action = (pick("Action") || "").toLowerCase() || null;

    updates.push(
      update(pick("Title") || label, {
        newVersion: pick("Version"),
        // Los datos de protección se identifican por nombre y salen true. Para el resto queda
        // null y no false: `Recommended: YES` NO significa "de seguridad", y softwareupdate no
        // dice si una actualización del sistema trae correcciones de seguridad aunque Apple las
        // publique en su web. Deducirlo sería inventar.
        security: isMacosSecurityData(label, pick("Title")) ? true : null,
        action,
        sizeKiB: Number.isFinite(sizeKiB) ? sizeKiB : null,
        label,
      })
    );
  }

  return updates;
}

/** ¿Esta entrada es una actualización de datos de protección de macOS? */
function isMacosSecurityData(label, title) {
  return MACOS_SECURITY_DATA.some((re) => re.test(label || "") || re.test(title || ""));
}

/** ¿Es la actualización del propio sistema operativo? Es la única con versión instalada consultable. */
function isMacosSystemUpdate(label, title) {
  return /^macOS\b/i.test(title || "") || /^macOS\b/i.test(label || "");
}

/** Versión de macOS instalada ahora mismo. null si no se puede saber: es un extra, no un requisito. */
async function macosInstalledVersion() {
  try {
    const out = await execCommand("sw_vers -productVersion", SW_VERS_TIMEOUT_MS);
    return out.trim() || null;
  } catch (_) {
    return null;
  }
}

/** ¿La salida dice explícitamente que no hay nada pendiente? Es un dato, no un fallo. */
function macosSaysNoUpdates(text) {
  return /No new software available/i.test(String(text || ""));
}

async function fromSoftwareUpdate() {
  if (!(await commandExists("softwareupdate"))) {
    return {
      skipped: true,
      kind: "not-installed",
      reason:
        "LoCoAudit no ha encontrado el comando `softwareupdate`, que es la única fuente de " +
        "actualizaciones pendientes en macOS.",
    };
  }

  // --no-scan reutiliza el último escaneo del sistema: no toca la red y no dispara una descarga.
  // --include-config-data añade las actualizaciones de datos de seguridad (XProtect, MRT,
  // Gatekeeper), que sin esa opción no se listan y quedaban invisibles para la auditoría. Sigue
  // siendo solo listar: ninguna de las dos opciones instala nada.
  // 2>&1 porque softwareupdate reparte su salida entre stdout y stderr según la versión y el
  // estado del escaneo; sin unirlas, la lista se pierde unas veces sí y otras no.
  const cmd = "softwareupdate -l --no-scan --include-config-data 2>&1";
  let stdout;
  try {
    stdout = await execCommand(cmd, MACOS_TIMEOUT_MS);
  } catch (err) {
    // softwareupdate sale con código distinto de cero avisando de escaneos en curso y aun así
    // imprime la lista cacheada. Si hay salida utilizable se interpreta igual.
    stdout = err.stdout || "";
    if (!stdout.trim()) {
      return execSkip(err, "softwareupdate -l --no-scan --include-config-data",
        "las actualizaciones pendientes", MACOS_TIMEOUT_MS);
    }
  }

  const updates = parseSoftwareUpdateList(stdout);

  // Ni lista ni el mensaje de "no hay nada": la salida no se ha entendido, y eso no puede pasar
  // por "cero pendientes". Es el falso verde que la regla de CLAUDE.md prohíbe.
  if (updates.length === 0 && !macosSaysNoUpdates(stdout)) {
    return {
      skipped: true,
      kind: "error",
      reason:
        "LoCoAudit no ha entendido la salida de `softwareupdate -l --no-scan " +
        "--include-config-data`: no trae ninguna " +
        "actualización ni el aviso de que no haya ninguna, así que no se puede afirmar que el " +
        "equipo esté al día.",
    };
  }

  // La versión instalada solo tiene sentido para la actualización del sistema: los datos de
  // protección no tienen una versión instalada consultable, y ahí currentVersion se queda en null
  // para que el normalizador no pinte una flecha que compara con nada.
  const instalada = updates.some((u) => isMacosSystemUpdate(u.label, u.name))
    ? await macosInstalledVersion()
    : null;
  if (instalada) {
    for (const u of updates) {
      if (isMacosSystemUpdate(u.label, u.name)) u.currentVersion = instalada;
    }
  }

  return {
    skipped: false,
    platform: "darwin",
    source: "softwareupdate",
    updates,
    total: updates.length,
    // Mixto: sabe de los datos de protección y no de las del sistema. Ni 'full' ni 'none'.
    securityDetection: "partial",
    securityCount: updates.filter((u) => u.security === true).length,
  };
}

// ── Linux ────────────────────────────────────────────────────────────────────

/** `nombre  version_vieja -> version_nueva`, el formato de checkupdates y de `pacman -Qu`. */
function parsePacmanList(text) {
  return String(text || "")
    .trim()
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((line) => {
      const m = /^(\S+)\s+(\S+)\s+->\s+(\S+)/.exec(line);
      return m ? update(m[1], { currentVersion: m[2], newVersion: m[3] }) : null;
    })
    .filter(Boolean);
}

/** Días desde la sincronización más reciente de las bases de pacman; null si no se puede saber. */
function pacmanDbAgeDays() {
  try {
    const files = fs.readdirSync(PACMAN_SYNC_DIR).filter((f) => f.endsWith(".db"));
    if (files.length === 0) return null;
    const newest = files.reduce((acc, f) => {
      const m = fs.statSync(path.join(PACMAN_SYNC_DIR, f)).mtimeMs;
      return m > acc ? m : acc;
    }, 0);
    if (!newest) return null;
    return Math.floor((Date.now() - newest) / 86400000);
  } catch (_) {
    // Sin permisos o sin la carpeta: no se sabe la antigüedad, y eso se dice, no se inventa.
    return null;
  }
}

/**
 * pacman no tiene un "listar pendientes" que no toque el sistema: `pacman -Sy` sincronizaría la
 * base y dejaría el equipo en estado parcial, así que aquí está prohibido. checkupdates (de
 * pacman-contrib) sincroniza en una copia temporal y es la vía correcta. Sin él queda `pacman -Qu`,
 * que compara contra la base local: lo que devuelve es válido pero puede estar incompleto, y el
 * resultado lleva la antigüedad de esa base para que el finding lo diga.
 */
async function fromPacman() {
  const hasCheckupdates = await commandExists("checkupdates");
  const cmd = hasCheckupdates ? "checkupdates" : "pacman -Qu";

  let stdout;
  try {
    stdout = await execCommand(cmd, LINUX_TIMEOUT_MS);
  } catch (err) {
    // Los dos salen con código distinto de cero cuando no hay nada que actualizar: checkupdates
    // con 2, pacman -Qu con 1. Sin salida y sin stderr, eso es "cero pendientes", no un fallo.
    const out = (err.stdout || "").trim();
    const errTxt = (err.stderr || "").trim();
    if (!out && !errTxt && !isTimeout(err)) {
      stdout = "";
    } else if (!out) {
      return execSkip(err, cmd, "las actualizaciones pendientes", LINUX_TIMEOUT_MS);
    } else {
      stdout = err.stdout;
    }
  }

  const updates = parsePacmanList(stdout);
  const dbAgeDays = hasCheckupdates ? null : pacmanDbAgeDays();

  return {
    skipped: false,
    platform: "linux",
    manager: "pacman",
    source: cmd,
    updates,
    total: updates.length,
    // Arch no clasifica sus actualizaciones: el seguimiento de seguridad vive en el Arch Security
    // Tracker, que es una fuente externa y no se consulta desde aquí.
    securityDetection: "none",
    securityCount: null,
    // Solo en el camino de respaldo: la lista sale de la base local, que puede estar vieja.
    staleDb: !hasCheckupdates,
    dbAgeDays,
  };
}

/** `nombre/suite[,suite2] version arch [upgradable from: vieja]`. */
function parseAptList(text) {
  return String(text || "")
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !/^(Listing|WARNING)/i.test(l))
    .map((line) => {
      const m = /^(\S+?)\/(\S+)\s+(\S+)\s+\S+(?:\s+\[upgradable from:\s*([^\]]+)\])?/.exec(line);
      if (!m) return null;
      return update(m[1], {
        newVersion: m[3],
        currentVersion: m[4] ? m[4].trim() : null,
        suite: m[2],
      });
    })
    .filter(Boolean);
}

async function fromApt() {
  // `apt` avisa por stderr de que su CLI no es estable; la lista sale por stdout igualmente.
  const cmd = "apt list --upgradable";
  let stdout;
  try {
    stdout = await execCommand(cmd, LINUX_TIMEOUT_MS);
  } catch (err) {
    stdout = err.stdout || "";
    if (!stdout.trim()) {
      return execSkip(err, cmd, "las actualizaciones pendientes", LINUX_TIMEOUT_MS);
    }
  }

  const updates = parseAptList(stdout);

  return {
    skipped: false,
    platform: "linux",
    manager: "apt",
    source: cmd,
    updates,
    total: updates.length,
    // El sufijo del repositorio ('-security') es una pista, no un dato: cambia entre Debian y
    // Ubuntu y entre versiones, y un paquete de seguridad puede llegar por otro origen. Se guarda
    // en `suite` de cada entrada como evidencia, pero no se marca ninguna como de seguridad.
    securityDetection: "none",
    securityCount: null,
  };
}

/** `nombre.arch  version  repositorio`, saltando cabecera y la sección de obsoletos. */
function parseDnfCheckUpdate(text) {
  const out = [];
  for (const raw of String(text || "").split("\n")) {
    const line = raw.trim();
    if (!line) continue;
    if (/^(Last metadata|Obsoleting Packages|Security:|Updating)/i.test(line)) {
      if (/^Obsoleting Packages/i.test(line)) break;
      continue;
    }
    const m = /^(\S+)\.(\S+)\s+(\S+)\s+(\S+)$/.exec(line);
    if (!m) continue;
    out.push(update(m[1], { newVersion: m[3] }));
  }
  return out;
}

/** `AVISO Importancia/Sec. nombre-version-release.arch` → nombres de paquete afectados. */
function parseDnfSecurityNames(text) {
  const names = new Set();
  for (const raw of String(text || "").split("\n")) {
    const parts = raw.trim().split(/\s+/);
    if (parts.length < 3) continue;
    const nevra = parts[parts.length - 1];
    // De 'bash-5.1.8-6.fc38.x86_64' se recorta hacia atrás versión, release y arquitectura.
    const m = /^(.+?)-[^-]+-[^-]+$/.exec(nevra.replace(/\.[^.]+$/, ""));
    if (m) names.add(m[1]);
  }
  return names;
}

async function fromDnf(manager) {
  const cmd = `${manager} check-update`;
  let stdout;
  try {
    stdout = await execCommand(cmd, LINUX_TIMEOUT_MS);
  } catch (err) {
    // check-update usa el código de salida como dato: 0 = nada pendiente, 100 = hay pendientes,
    // 1 = error de verdad. Sin distinguirlos, el caso normal se leería como fallo.
    if (err.code === 100) {
      stdout = err.stdout || "";
    } else {
      return execSkip(err, cmd, "las actualizaciones pendientes", LINUX_TIMEOUT_MS);
    }
  }

  const updates = parseDnfCheckUpdate(stdout);

  // Las de seguridad son una consulta aparte. Que falle no invalida la lista: se devuelve el
  // recuento como desconocido en vez de anular todo el módulo.
  let securityNames = null;
  try {
    const secOut = await execCommand(`${manager} updateinfo list security`, LINUX_TIMEOUT_MS);
    securityNames = parseDnfSecurityNames(secOut);
  } catch (err) {
    if (err.stdout) securityNames = parseDnfSecurityNames(err.stdout);
  }

  if (securityNames) {
    for (const u of updates) u.security = securityNames.has(u.name);
  }

  return {
    skipped: false,
    platform: "linux",
    manager,
    source: cmd,
    updates,
    total: updates.length,
    securityDetection: securityNames ? "full" : "none",
    securityCount: securityNames ? updates.filter((u) => u.security).length : null,
  };
}

/** Tabla con `|`: se descartan cabecera, separadores y la columna de estado. */
function parseZypperTable(text, nameCol, curCol, newCol) {
  const out = [];
  for (const raw of String(text || "").split("\n")) {
    if (!raw.includes("|")) continue;
    const cols = raw.split("|").map((c) => c.trim());
    if (cols.length < 3) continue;
    if (/^-+$/.test(cols[0]) || /^S$/i.test(cols[0]) || /^Repository$/i.test(cols[1])) continue;
    const name = cols[nameCol];
    if (!name || /^Name$/i.test(name)) continue;
    out.push(update(name, {
      currentVersion: curCol != null ? cols[curCol] || null : null,
      newVersion: newCol != null ? cols[newCol] || null : null,
    }));
  }
  return out;
}

async function fromZypper() {
  const cmd = "zypper --non-interactive list-updates";
  let stdout;
  try {
    stdout = await execCommand(cmd, LINUX_TIMEOUT_MS);
  } catch (err) {
    stdout = err.stdout || "";
    if (!stdout.trim()) {
      return execSkip(err, cmd, "las actualizaciones pendientes", LINUX_TIMEOUT_MS);
    }
  }

  const updates = parseZypperTable(stdout, 2, 3, 4);

  // list-patches devuelve PARCHES, no paquetes: sus nombres no casan con los de list-updates, así
  // que se cuenta cuántos hay de seguridad y no se marca ninguna actualización una por una.
  let securityCount = null;
  try {
    const patchOut = await execCommand(
      "zypper --non-interactive list-patches --category security",
      LINUX_TIMEOUT_MS
    );
    securityCount = parseZypperTable(patchOut, 1, null, null).length;
  } catch (err) {
    if (err.stdout) securityCount = parseZypperTable(err.stdout, 1, null, null).length;
  }

  return {
    skipped: false,
    platform: "linux",
    manager: "zypper",
    source: cmd,
    updates,
    total: updates.length,
    securityDetection: securityCount != null ? "full" : "none",
    securityCount,
    // El recuento es de parches de seguridad, que no se corresponden uno a uno con los paquetes
    // de la lista. Quien redacte el finding tiene que decirlo así.
    securityCountIsPatches: true,
  };
}

/** `nombre-version < version_disponible`. */
function parseApkVersions(text) {
  return String(text || "")
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && l.includes("<"))
    .map((line) => {
      const m = /^(\S+?)-(\d\S*)\s+<\s+(\S+)/.exec(line);
      return m ? update(m[1], { currentVersion: m[2], newVersion: m[3] }) : null;
    })
    .filter(Boolean);
}

async function fromApk() {
  const cmd = "apk version -l '<'";
  let stdout;
  try {
    stdout = await execCommand(cmd, LINUX_TIMEOUT_MS);
  } catch (err) {
    stdout = err.stdout || "";
    if (!stdout.trim()) {
      return execSkip(err, cmd, "las actualizaciones pendientes", LINUX_TIMEOUT_MS);
    }
  }

  const updates = parseApkVersions(stdout);
  return {
    skipped: false,
    platform: "linux",
    manager: "apk",
    source: cmd,
    updates,
    total: updates.length,
    securityDetection: "none",
    securityCount: null,
  };
}

// ── Windows ──────────────────────────────────────────────────────────────────

/**
 * HRESULT que devuelve Windows Update cuando la consulta exige privilegios. Se compara el código,
 * nunca el mensaje: el texto de la excepción llega traducido al idioma del equipo.
 */
const HRESULT_NOT_ELEVATED = "0x80240044";   // WU_E_NOT_ELEVATED

/**
 * Se une con SALTOS DE LÍNEA, no con espacios.
 *
 * Unido con " " producía `$ErrorActionPreference='Stop' try {`, que PowerShell rechaza con
 * "Token 'try' inesperado": el script no llegaba a compilar y el módulo salía por el camino de
 * error en todas las ejecuciones de Windows. Añadir un `;` habría arreglado ese caso concreto y
 * dejado la trampa puesta para la siguiente línea que alguien añadiera. El salto de línea es
 * separador de sentencias en PowerShell y elimina la clase entera de bug.
 *
 * Para que esos saltos lleguen intactos, el script va por fichero temporal y `-File`
 * (runPowerShell en lib/executor.js): con `-Command` el script viaja dentro del argumento de
 * `cmd.exe /c` y un salto de línea ahí corta el comando. Es el mismo camino que ya usaba
 * security-events.js.
 *
 * REINICIO PENDIENTE. Se consultan dos claves del registro y solo dos:
 *   HKLM\...\Component Based Servicing\RebootPending
 *   HKLM\...\WindowsUpdate\Auto Update\RebootRequired
 * Queda FUERA `PendingFileRenameOperations`, que la deja puesta casi cualquier instalador y
 * produciría un "hay reinicio pendiente" permanente. Un falso positivo constante se aprende a
 * ignorar, y entonces deja de avisar del caso real.
 *
 * El script no deja escapar la excepción: la convierte en un JSON con el HRESULT, igual que
 * security-events.js hace con `denied` para el canal Security. Así el mapeo en Node es sobre un
 * campo estructurado y no sobre el stderr, que viene traducido al idioma del equipo.
 */
const WINDOWS_PS_SCRIPT = [
  "$ErrorActionPreference='Stop'",
  "try {",
  "$s = New-Object -ComObject Microsoft.Update.Session",
  "$r = $s.CreateUpdateSearcher().Search('IsInstalled=0')",
  "$u = @($r.Updates | ForEach-Object { [pscustomobject]@{ Title=$_.Title; Severity=$_.MsrcSeverity; " +
    "Categories=@($_.Categories | ForEach-Object { $_.Name }) } })",
  // Reinicio pendiente. Va DENTRO del mismo try y en su propio try anidado: si la lectura del
  // registro falla, no puede tirar la consulta de actualizaciones, que es el dato principal.
  // `reboot=$null` cuando no se pudo mirar: NO es lo mismo que "no hay reinicio pendiente", y el
  // llamante lo distingue.
  "$reboot = $null",
  "$rebootKeys = @()",
  "try {",
  "  $cbs = Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending'",
  "  $wu  = Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired'",
  "  if ($cbs) { $rebootKeys += 'ComponentBasedServicing' }",
  "  if ($wu)  { $rebootKeys += 'WindowsUpdate' }",
  "  $reboot = [bool]($cbs -or $wu)",
  "} catch {",
  "  $reboot = $null",
  "}",
  "ConvertTo-Json -Compress -Depth 4 @{ ok=$true; count=$u.Count; updates=$u; reboot=$reboot; rebootKeys=@($rebootKeys) }",
  "} catch {",
  "ConvertTo-Json -Compress @{ ok=$false; hresult=('0x{0:X8}' -f $_.Exception.HResult) }",
  "}",
].join("\n");

async function fromWindowsUpdate() {
  let shell = null;
  if (await commandExists("powershell")) shell = "powershell";
  else if (await commandExists("pwsh")) shell = "pwsh";

  if (!shell) {
    return {
      skipped: true,
      kind: "not-installed",
      reason:
        "LoCoAudit no ha encontrado PowerShell (`powershell` ni `pwsh`), que es la única vía " +
        "nativa para consultar las actualizaciones pendientes de Windows.",
    };
  }

  // Etiqueta para los mensajes: la ruta del temporal cambia en cada ejecución y no le dice nada
  // al usuario. El comando real, con su script, va en el volcado de `detail`.
  const cmdLabel = `${shell} -File <consulta a Windows Update>`;
  let stdout;
  try {
    stdout = await runPowerShell(shell, WINDOWS_PS_SCRIPT, WINDOWS_TIMEOUT_MS,
      { prefix: "lcaudit-winupdate-" });
  } catch (err) {
    stdout = err.stdout || "";
    if (!stdout.trim()) {
      return execSkip(err, cmdLabel, "las actualizaciones pendientes", WINDOWS_TIMEOUT_MS);
    }
  }

  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch (parseErr) {
    return {
      skipped: true,
      kind: "error",
      reason:
        "LoCoAudit no ha podido interpretar la respuesta de Windows Update: la salida de " +
        "PowerShell no tiene el formato esperado.",
      // La salida real, recortada, para el JSON exportado. Es lo que permite ver si fue un error
      // de sintaxis del script, un mensaje de la política de ejecución, o basura del perfil.
      detail: firstLines(`${parseErr.message}\n---\n${stdout}`, RAW_DETAIL_LINES),
    };
  }

  if (parsed.ok === false) {
    // LoCoAudit no eleva nunca: Node-RED sirve un panel web en el 1880 y heredar privilegios de
    // administrador ampliaría la superficie de ataque sin necesidad. Si Windows exige elevación,
    // el resultado correcto es un estado explícito y una instrucción para el usuario.
    if (String(parsed.hresult || "").toUpperCase() === HRESULT_NOT_ELEVATED.toUpperCase()) {
      return {
        skipped: true,
        kind: "error",
        reason:
          "Windows no permite consultar las actualizaciones pendientes sin permisos de " +
          "administrador en este equipo. LoCoAudit no se ejecuta elevado por decisión de diseño: " +
          "si quieres ese dato, cierra Node-RED y vuelve a abrirlo como administrador. Que aquí " +
          "no aparezca ninguna actualización no significa que el equipo esté al día.",
      };
    }
    return {
      skipped: true,
      kind: "error",
      reason:
        "LoCoAudit no ha podido consultar las actualizaciones pendientes: Windows Update " +
        `devolvió el error ${parsed.hresult || "sin código"}.`,
    };
  }

  const raw = Array.isArray(parsed.updates) ? parsed.updates : [];
  const updates = raw.map((u) => {
    const cats = (Array.isArray(u.Categories) ? u.Categories : [])
      .map((c) => String(c || "").trim())
      .filter(Boolean);
    const clas = classifyWindowsUpdate(cats, u.Severity);
    return update(u.Title || "actualización sin título", {
      security: clas.security,
      label: u.Severity || null,
      // Se guardan para que el JSON exportado permita rehacer la clasificación sin volver a
      // consultar Windows Update, y para poder auditar por qué una entrada quedó sin clasificar.
      categories: cats,
      msrcSeverity: u.Severity || null,
    });
  });

  const seguras = updates.filter((u) => u.security === true).length;
  const sinClasificar = updates.filter((u) => u.security === null).length;

  // true / false / null, nunca un booleano forzado. Con la lectura del registro caída, `null`
  // significa "no se sabe": dar `false` ahí sería afirmar que no hay reinicio pendiente sin
  // haberlo comprobado, que es exactamente el falso verde que este proyecto persigue.
  const reboot = parsed.reboot === true ? true : parsed.reboot === false ? false : null;

  // Una lista vacía es un dato legítimo, no un fallo: un equipo gestionado por WSUS o Intune puede
  // no tener nada pendiente aprobado. Se devuelve como cero, igual que en macOS.
  return {
    skipped: false,
    platform: "win32",
    source: "Microsoft.Update.Session",
    updates,
    total: updates.length,
    securityDetection: "full",
    securityCount: seguras,
    // Una actualización instalada a la espera de reinicio NO aparece en `IsInstalled=0`: la API
    // COM devuelve cero pendientes y el informe decía "Sistema al día". Falso: la corrección de
    // seguridad no está aplicada hasta que se reinicia.
    rebootPending: reboot,
    rebootKeys: Array.isArray(parsed.rebootKeys) ? parsed.rebootKeys : [],
    // Tercer estado, visible y contado aparte. Sin él, una actualización que llega sin categorías
    // caía en `security: false` y se contaba como "no es de seguridad", que es exactamente la
    // asunción que no se puede hacer: no saberlo no es saber que no.
    unclassifiedCount: sinClasificar,
  };
}

/**
 * ¿Es de seguridad esta actualización de Windows? Tres respuestas, no dos.
 *
 *   true  → consta que sí (categoría de seguridad, o severidad MSRC asignada).
 *   false → consta que no (hay categorías legibles y ninguna es de seguridad).
 *   null  → NO SE SABE: la entrada no trae categorías ni severidad.
 *
 * El tercer caso existe porque el booleano mentía. Windows Update no siempre devuelve
 * `Categories` —una entrada de driver, una actualización retirada, o una respuesta recortada por
 * la política del equipo pueden venir sin ellas—, y con dos estados esas caían en `false`, o sea
 * "no es de seguridad". Contar como segura de menos es el error peligroso de los dos.
 *
 * La CATEGORÍA es la señal principal: una actualización de seguridad sin severidad MSRC asignada
 * sigue siendo de seguridad. La severidad MSRC es la segunda señal, no un requisito: si Microsoft
 * le ha puesto Critical/Important/Moderate/Low, es que la ha evaluado como problema de seguridad.
 */
function classifyWindowsUpdate(categories, msrcSeverity) {
  // El nombre de la categoría llega TRADUCIDO al idioma del equipo: "Security Updates" en un
  // Windows en inglés, "Actualizaciones de seguridad" en uno en español. Por eso se buscan las
  // dos raíces y no una cadena exacta.
  const ES_SEGURIDAD = /security\s+updates?|actualizaciones?\s+de\s+seguridad|definition\s+updates?|actualizaciones?\s+de\s+definiciones/i;
  const sev = String(msrcSeverity || "").trim();

  if (categories.some((c) => ES_SEGURIDAD.test(c))) return { security: true, por: "categoria" };
  if (sev && /^(critical|important|moderate|low)$/i.test(sev)) {
    return { security: true, por: "msrc" };
  }
  // Sin categorías legibles no hay nada sobre lo que decidir. Decir `false` aquí sería inventar.
  if (!categories.length && !sev) return { security: null, por: "sin-datos" };
  return { security: false, por: "categoria" };
}

// ── Despacho ─────────────────────────────────────────────────────────────────

/**
 * `pkgManager` llega por parámetro desde audit-host.js, que ya lo resolvió con pkg-manager.js
 * antes del Promise.allSettled. No se vuelve a detectar aquí: una sola fuente de verdad.
 */
async function getPendingUpdates(options = {}) {
  const platform = process.platform;

  if (platform === "darwin") return fromSoftwareUpdate();
  if (platform === "win32") return fromWindowsUpdate();

  if (platform !== "linux") {
    return {
      skipped: true,
      kind: "unsupported",
      reason:
        `LoCoAudit no sabe consultar las actualizaciones pendientes en ${platform}. No es un ` +
        "fallo de tu equipo: es un límite de LoCoAudit, y el resto de módulos de la auditoría no " +
        "se ve afectado.",
    };
  }

  const manager = options.pkgManager || null;

  if (!manager || !LINUX_MANAGERS.includes(manager)) {
    return {
      skipped: true,
      kind: "unsupported",
      reason:
        "LoCoAudit solo sabe consultar las actualizaciones pendientes con pacman, apt, dnf, yum, " +
        "zypper y apk, y este sistema usa otro gestor de paquetes. No es un fallo de tu equipo " +
        "ni le falta nada: es un límite de LoCoAudit, y el resto de módulos de la auditoría no " +
        "se ve afectado.",
    };
  }

  if (manager === "pacman") return fromPacman();
  if (manager === "apt") return fromApt();
  if (manager === "dnf" || manager === "yum") return fromDnf(manager);
  if (manager === "zypper") return fromZypper();
  return fromApk();
}

module.exports = {
  getPendingUpdates,
  // Sueltos para los tests: parsear salidas reales sin tener el gestor delante.
  parseSoftwareUpdateList,
  parsePacmanList,
  parseAptList,
  parseDnfCheckUpdate,
  parseDnfSecurityNames,
  parseZypperTable,
  parseApkVersions,
};
