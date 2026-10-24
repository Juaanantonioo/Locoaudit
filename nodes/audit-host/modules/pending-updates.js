"use strict";

/** Actualizaciones pendientes del sistema: solo las lista, nunca instala ni sincroniza.
 *  Si no puede mirar devuelve { skipped, kind, reason }; cero pendientes es un dato real, no un skip. */

const fs = require("fs");
const path = require("path");
const { execCommand, commandExists, runPowerShell } = require("../../../lib/executor");

const MACOS_TIMEOUT_MS   = 90000;    // --no-scan no va a la red, pero softwareupdate arranca lento
const LINUX_TIMEOUT_MS   = 60000;
const WINDOWS_TIMEOUT_MS = 180000;   // la búsqueda COM tarda minutos en un equipo con muchas pendientes

/** Ruta de las bases sincronizadas de pacman, para poder decir cuántos días tienen. */
const PACMAN_SYNC_DIR = "/var/lib/pacman/sync";

/** Datos de protección de macOS: lo único que softwareupdate permite identificar como de seguridad. */
const MACOS_SECURITY_DATA = [
  /^XProtect/i,                              // XProtectPlistConfigData, XProtectPayloads, XProtectCloudKitUpdate
  /^MRT/i,                                   // MRTConfigData
  /^Gatekeeper\s*Compatibility\s*Data/i,     // con y sin espacios
];

/** Solo para enriquecer la entrada del sistema; que falle no invalida el listado. */
const SW_VERS_TIMEOUT_MS = 5000;

/** Gestores de Linux que este módulo sabe consultar. Fuera de la lista, kind 'unsupported'. */
const LINUX_MANAGERS = ["pacman", "apt", "dnf", "yum", "zypper", "apk"];

/** child_process mata por timeout con SIGTERM y marca killed. */
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
    // Motivo legible para el usuario, sin la traza.
    reason: `LoCoAudit no ha podido consultar ${what}: el comando \`${cmd}\` falló.`,
    // El volcado va aparte, para la exportación JSON.
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
    // Solo pacman, apt, zypper y apk dan la versión instalada; sin ella no se pinta "instalada → nueva".
    currentVersion: fields.currentVersion || null,
    newVersion:     fields.newVersion || null,
    // null y no false donde no se sabe: "no consta" no es "no lo es".
    security:       fields.security === undefined ? null : fields.security,
    // Solo macOS: 'restart' | 'shut down' | null.
    action:         fields.action || null,
    sizeKiB:        fields.sizeKiB == null ? null : fields.sizeKiB,
    // apt: sufijo del repositorio, solo como evidencia.
    suite:          fields.suite || null,
    label:          fields.label || null,
    // Solo Windows: señales de la clasificación, para revisarla desde el JSON exportado.
    categories:     Array.isArray(fields.categories) ? fields.categories : null,
    msrcSeverity:   fields.msrcSeverity || null,
  };
}

// ── macOS ────────────────────────────────────────────────────────────────────

/** Dos líneas por actualización: `* Label: …` y otra con pares `Clave: valor,`.
 *  Los títulos traen espacios duros (U+00A0) que hay que normalizar. */
function parseSoftwareUpdateList(text) {
  const clean = String(text || "").replace(/ /g, " ");
  const lines = clean.split("\n");
  const updates = [];

  for (let i = 0; i < lines.length; i++) {
    const m = /^\s*\*\s*(?:Label:\s*)?(.+?)\s*$/.exec(lines[i]);
    if (!m) continue;
    const label = m[1];

    // Si falta la línea de detalle, la etiqueta basta.
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
        // Solo los datos de protección son true; `Recommended: YES` no significa "de seguridad".
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

  // --no-scan no toca la red; --include-config-data añade XProtect, MRT y Gatekeeper. Ninguna instala nada.
  // 2>&1 porque según la versión la lista sale por stdout o por stderr.
  const cmd = "softwareupdate -l --no-scan --include-config-data 2>&1";
  let stdout;
  try {
    stdout = await execCommand(cmd, MACOS_TIMEOUT_MS);
  } catch (err) {
    // Puede salir con código distinto de cero y aun así imprimir la lista: se interpreta igual.
    stdout = err.stdout || "";
    if (!stdout.trim()) {
      return execSkip(err, "softwareupdate -l --no-scan --include-config-data",
        "las actualizaciones pendientes", MACOS_TIMEOUT_MS);
    }
  }

  const updates = parseSoftwareUpdateList(stdout);

  // Salida no entendida: no puede pasar por "cero pendientes".
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

  // La versión instalada solo tiene sentido para la actualización del sistema operativo.
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
    // Sin permisos o sin carpeta: no se sabe, y se dice.
    return null;
  }
}

/** Nunca `pacman -Sy` (deja el sistema a medias): checkupdates sincroniza en una copia temporal.
 *  Sin él, `pacman -Qu`, quizá incompleto; el resultado lleva la antigüedad de la base. */
async function fromPacman() {
  const hasCheckupdates = await commandExists("checkupdates");
  const cmd = hasCheckupdates ? "checkupdates" : "pacman -Qu";

  let stdout;
  try {
    stdout = await execCommand(cmd, LINUX_TIMEOUT_MS);
  } catch (err) {
    // Sin pendientes salen con código distinto de cero; sin salida ni stderr, es "cero", no un fallo.
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
    // Arch no clasifica sus actualizaciones (eso está en el Arch Security Tracker, externo).
    securityDetection: "none",
    securityCount: null,
    // Solo con pacman -Qu: la base local puede estar vieja.
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
    // La salida de un comando que falló solo vale si de ella sale al menos un paquete.
    if (!parseAptList(err.stdout).length) {
      return execSkip(err, cmd, "las actualizaciones pendientes", LINUX_TIMEOUT_MS);
    }
    stdout = err.stdout;
  }

  const updates = parseAptList(stdout);

  return {
    skipped: false,
    platform: "linux",
    manager: "apt",
    source: cmd,
    updates,
    total: updates.length,
    // El sufijo '-security' es una pista, no un dato: se guarda pero no se marca nada como de seguridad.
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
    // check-update: 0 = nada, 100 = hay pendientes, 1 = error.
    if (err.code === 100) {
      stdout = err.stdout || "";
    } else {
      return execSkip(err, cmd, "las actualizaciones pendientes", LINUX_TIMEOUT_MS);
    }
  }

  const updates = parseDnfCheckUpdate(stdout);

  // Las de seguridad van aparte: si falla, el recuento queda desconocido sin anular el módulo.
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
    // La salida de un comando que falló solo vale si de ella sale al menos un paquete.
    if (!parseZypperTable(err.stdout, 2, 3, 4).length) {
      return execSkip(err, cmd, "las actualizaciones pendientes", LINUX_TIMEOUT_MS);
    }
    stdout = err.stdout;
  }

  const updates = parseZypperTable(stdout, 2, 3, 4);

  // list-patches cuenta parches, no paquetes: no se marca ninguna actualización una por una.
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
    // Son parches, no paquetes: el finding tiene que decirlo así.
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
    // La salida de un comando que falló solo vale si de ella sale al menos un paquete.
    if (!parseApkVersions(err.stdout).length) {
      return execSkip(err, cmd, "las actualizaciones pendientes", LINUX_TIMEOUT_MS);
    }
    stdout = err.stdout;
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

/** HRESULT de Windows Update cuando hace falta elevación. Se compara el código: el mensaje llega traducido. */
const HRESULT_NOT_ELEVATED = "0x80240044";   // WU_E_NOT_ELEVATED

/** Se une con saltos de línea (con espacios no compila) y va por runPowerShell. El reinicio pendiente mira dos claves;
 *  PendingFileRenameOperations no, porque casi cualquier instalador la deja. Los errores salen como JSON con el HRESULT. */
const WINDOWS_PS_SCRIPT = [
  "$ErrorActionPreference='Stop'",
  "try {",
  "$s = New-Object -ComObject Microsoft.Update.Session",
  "$r = $s.CreateUpdateSearcher().Search('IsInstalled=0')",
  "$u = @($r.Updates | ForEach-Object { [pscustomobject]@{ Title=$_.Title; Severity=$_.MsrcSeverity; " +
    "Categories=@($_.Categories | ForEach-Object { $_.Name }) } })",
  // try anidado: si falla el registro, no tira la consulta. `reboot=$null` es "no se pudo mirar".
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

  // Etiqueta fija para los mensajes; el comando real va en `detail`.
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
      // Salida real recortada, para diagnosticar desde el JSON exportado.
      detail: firstLines(`${parseErr.message}\n---\n${stdout}`, RAW_DETAIL_LINES),
    };
  }

  if (parsed.ok === false) {
    // LoCoAudit nunca eleva privilegios (sirve un panel web): si Windows lo exige, se dice al usuario.
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
      // Para poder revisar la clasificación desde el JSON exportado.
      categories: cats,
      msrcSeverity: u.Severity || null,
    });
  });

  const seguras = updates.filter((u) => u.security === true).length;
  const sinClasificar = updates.filter((u) => u.security === null).length;

  // true / false / null: con el registro caído, false afirmaría algo no comprobado.
  const reboot = parsed.reboot === true ? true : parsed.reboot === false ? false : null;

  // Lista vacía es un dato legítimo (p. ej. equipos con WSUS o Intune).
  return {
    skipped: false,
    platform: "win32",
    source: "Microsoft.Update.Session",
    updates,
    total: updates.length,
    securityDetection: "full",
    securityCount: seguras,
    // Una actualización pendiente de reinicio no sale en `IsInstalled=0` y no está aplicada.
    rebootPending: reboot,
    rebootKeys: Array.isArray(parsed.rebootKeys) ? parsed.rebootKeys : [],
    // Tercer estado contado aparte: no saberlo no es saber que no.
    unclassifiedCount: sinClasificar,
  };
}

/** ¿Es de seguridad? true si consta, false si hay categorías y ninguna lo es, null si no se sabe.
 *  Señal principal: la categoría; secundaria: la severidad MSRC. */
function classifyWindowsUpdate(categories, msrcSeverity) {
  // La categoría llega traducida al idioma del equipo: se buscan las raíces en inglés y español.
  const ES_SEGURIDAD = /security\s+updates?|actualizaciones?\s+de\s+seguridad|definition\s+updates?|actualizaciones?\s+de\s+definiciones/i;
  const sev = String(msrcSeverity || "").trim();

  if (categories.some((c) => ES_SEGURIDAD.test(c))) return { security: true, por: "categoria" };
  if (sev && /^(critical|important|moderate|low)$/i.test(sev)) {
    return { security: true, por: "msrc" };
  }
  // Sin categorías legibles, false sería inventar.
  if (!categories.length && !sev) return { security: null, por: "sin-datos" };
  return { security: false, por: "categoria" };
}

// ── Despacho ─────────────────────────────────────────────────────────────────

/** `pkgManager` llega ya detectado desde audit-host.js: no se vuelve a detectar aquí. */
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
