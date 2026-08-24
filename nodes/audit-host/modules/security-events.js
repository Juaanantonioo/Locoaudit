"use strict";

/**
 * Foto fija de los eventos de seguridad de las últimas N horas: logins, sudo/su y sesiones
 * abiertas. No es un HIDS ni monitorización continua: recoge datos crudos y termina.
 *
 * Reparto con Lynis: Lynis mira la CONFIGURACIÓN de SSH, este módulo los EVENTOS. No duplicar
 * aquí chequeos de configuración. La severidad tampoco es cosa suya: la pone el normalizador con
 * las reglas de severity-map.
 *
 * Si ninguna fuente está disponible devuelve { skipped, reason }; las que fallan sueltas se
 * anotan en `partial` y el resto sigue. Nunca pide sudo ni ejecuta nada destructivo.
 */

const fs = require("fs");
const { execCommand, commandExists } = require("../../../lib/executor");
const {
  isServiceAccount,
  normalizeWinIp,
  correlateWindowsLogons,
} = require("../../../lib/win-logons");
const { withTempFile } = require("../../../lib/utils");

const LOG_TIMEOUT_MS = 60000;   // `log show` en macOS puede tardar
const CMD_TIMEOUT_MS = 15000;   // journalctl / who / last / lastb
const AUTH_LOG = "/var/log/auth.log";

/** Timestamp del principio de la línea, venga en ISO o en syslog. */
function extractTimestamp(line) {
  // `log show --style syslog`: 2026-07-02 10:15:30.123456+0200
  const iso = line.match(/^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})/);
  if (iso) return `${iso[1]} ${iso[2]}`;
  // journalctl -o short-iso: 2026-07-16T12:57:23+0200
  const shortIso = line.match(/^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})/);
  if (shortIso) return `${shortIso[1]} ${shortIso[2]}`;
  // auth.log: "Jul  2 10:15:30", o "jul 16 12:57:23" con locale ES. Las dos capitalizaciones.
  const syslog = line.match(/^([A-Za-z]{3}\s+\d{1,2} \d{2}:\d{2}:\d{2})/);
  if (syslog) return syslog[1];
  return null;
}

/** El PID identifica la sesión, que es como se deduplican las líneas del mismo intento. */
function tagPid(line, tagRe) {
  const m = line.match(tagRe);
  return m ? m[1] : null;
}

/** "sshd-session[5775]:" → "5775"; también sshd y sshd-auth. */
const SSHD_PID_RE = /sshd(?:-session|-auth)?\[(\d+)\]/;

/**
 * Clave de sesión cuando la línea no trae [PID]: el canal OpenSSH/Operational de Windows escribe
 * "sshd: Failed password for ..." sin él, y sin clave cada línea de respaldo contaba como intento
 * propio (3 intentos reales salían como 5). IP:puerto sirve igual, porque el puerto de origen es
 * único por conexión TCP, y aparece en las tres formas de línea. Solo se usa si no hay PID.
 */
function connKey(line) {
  let m = line.match(/\bfrom (\S+) port (\d+)/);
  if (!m) m = line.match(/\buser \S+ (\S+) port (\d+)/);
  return m ? `${m[1]}:${m[2]}` : null;
}

/**
 * Líneas de sshd, iguales en Linux y macOS, más "error: PAM: authentication error" de macOS.
 *
 * Un solo intento fallido emite varias líneas con el mismo PID: la de "Failed password", el
 * resumen de pam_unix, el "N more authentication failures" y el "Connection closed". Solo cuenta
 * la primera, una por intento real de contraseña. "Invalid user" y "Connection closed by ..." se
 * usan de respaldo, uno por sesión, para conexiones que nunca dieron un "Failed password" (los
 * fallos de publickey); contarlas todas inflaba el recuento de fuerza bruta.
 */
function parseSshdLines(text) {
  const accepted = [];
  const failed = [];
  const failedKeys = new Set();        // sesiones con al menos un "Failed password"
  const fallbackByKey = new Map();     // sesión → evento de respaldo (uno por conexión)
  let noKeySeq = 0;                     // clave sintética cuando no hay PID ni IP:puerto

  for (const rawLine of String(text || "").split("\n")) {
    const line = rawLine.trim();
    if (!line) continue;
    // PID cuando lo hay; si no, IP:puerto.
    const sessionKey = tagPid(line, SSHD_PID_RE) || connKey(line);

    let m = line.match(/Accepted (\S+) for (?:invalid user )?(\S+) from (\S+)/);
    if (m) {
      accepted.push({
        method: m[1],
        user: m[2],
        ip: m[3],
        timestamp: extractTimestamp(line),
        line,
      });
      continue;
    }

    // La canónica: un evento por intento fallido de contraseña.
    m = line.match(/Failed \S+ for (?:invalid user )?(\S+) from (\S+)/);
    if (!m) {
      m = line.match(/error: PAM: authentication error for (?:illegal user )?(\S+) from (\S+)/);
    }
    if (m) {
      failed.push({
        user: m[1],
        ip: m[2],
        timestamp: extractTimestamp(line),
        line,
      });
      if (sessionKey) failedKeys.add(sessionKey);
      continue;
    }

    // Resúmenes del mismo intento: ya los cuenta el "Failed password" de arriba.
    if (/authentication failure|more authentication failures/.test(line)) continue;

    // Respaldo, uno por sesión, solo para conexiones sin "Failed password".
    m = line.match(/Connection closed by (?:authenticating|invalid) user (\S+) (\S+) port/);
    if (!m) m = line.match(/\bInvalid user (\S+) from (\S+)/);
    if (m) {
      const key = sessionKey || `nokey:${noKeySeq++}`;
      if (!fallbackByKey.has(key)) {
        fallbackByKey.set(key, {
          key: sessionKey,
          ev: { user: m[1], ip: m[2], timestamp: extractTimestamp(line), line },
        });
      }
    }
  }

  // Los respaldos cuya sesión nunca dio un "Failed password".
  for (const { key, ev } of fallbackByKey.values()) {
    if (key && failedKeys.has(key)) continue;
    failed.push(ev);
  }

  return { accepted, failed };
}

/**
 * Líneas de sudo y su. Un uso correcto de sudo se reconoce por COMMAND=; los fallos, por
 * "N incorrect password attempt(s)", "a password is required" (sudo -n) o el authentication
 * failure de pam_unix. De su: "session opened for user" y el "BAD SU ... to ..." de macOS.
 */
function parseSudoLines(text) {
  const ok = [];
  const failed = [];
  for (const rawLine of String(text || "").split("\n")) {
    const line = rawLine.trim();
    if (!line) continue;

    let m = line.match(/(\S+) : .*?\bCOMMAND=(.+)$/);
    if (m && !/incorrect password|a password is required/.test(line)) {
      ok.push({
        user: m[1],
        command: m[2].trim(),
        timestamp: extractTimestamp(line),
        line,
      });
      continue;
    }

    m = line.match(/(\S+) : \d+ incorrect password attempt/);
    if (!m) m = line.match(/(\S+) : a password is required/);
    if (!m) {
      m = /authentication failure/.test(line) ? line.match(/\buser=(\S+)/) : null;
    }
    if (m) {
      failed.push({
        user: m[1],
        timestamp: extractTimestamp(line),
        line,
      });
      continue;
    }

    // macOS: "BAD SU <user> to <target> on /dev/ttysN"
    m = line.match(/BAD SU (\S+) to (\S+)/);
    if (m) {
      failed.push({
        user: m[1],
        target: m[2],
        timestamp: extractTimestamp(line),
        line,
      });
      continue;
    }

    // Solo el su de verdad: el "pam_unix(sudo:session): session opened" se descarta porque la
    // línea COMMAND= de arriba ya cuenta ese uso. Contar ambas daba el "13 usos" del dashboard.
    m = line.match(/session opened for user ([^\s(]+)(?:\(uid=\d+\))? by ([^\s(]+)/);
    if (m && !/pam_unix\(sudo:/.test(line)) {
      ok.push({
        user: m[2],
        command: `su → ${m[1]}`,
        timestamp: extractTimestamp(line),
        line,
      });
    }
  }
  return { ok, failed };
}

/** `who`: <user> <tty> <fecha> [(origen)], con el origen solo en las sesiones remotas. */
function parseWhoLines(text) {
  const sessions = [];
  for (const rawLine of String(text || "").split("\n")) {
    const line = rawLine.trim();
    if (!line) continue;
    const m = line.match(/^(\S+)\s+(\S+)\s+(.+?)(?:\s+\(([^)]+)\))?$/);
    if (m) {
      sessions.push({
        user: m[1],
        tty: m[2],
        since: m[3].trim(),
        origin: m[4] || null, // sin origen: sesión local
      });
    }
  }
  return sessions;
}

/** Si el comando falla, el motivo va a partial[] y la fuente devuelve cadena vacía. */
async function tryExec(cmd, timeoutMs, sourceName, partial) {
  try {
    return await execCommand(cmd, timeoutMs);
  } catch (err) {
    partial.push({ source: sourceName, reason: err.message || "exec failed" });
    return "";
  }
}

/** Linux: journalctl primero, auth.log de respaldo. */
async function collectLinux(windowHours, sources, partial) {
  let sshText = "";
  let sudoText = "";

  if (await commandExists("journalctl")) {
    // Desde OpenSSH 9.8 el listener sigue siendo `sshd` pero la autenticación la registra
    // `sshd-session`, y `sshd-auth` desde la 9.9: con solo _COMM=sshd salen cero eventos. Los
    // varios _COMM= se combinan con OR y en versiones viejas los nombres extra no casan nada.
    //
    // `-o short-iso` y no `-o cat`, que emite el MESSAGE pelado: hacen falta el timestamp para
    // la columna HORA, sin el lío de "jul"/"Jul", y el [PID] para deduplicar.
    sshText = await tryExec(
      `journalctl _COMM=sshd _COMM=sshd-session _COMM=sshd-auth --since "-${windowHours}h" --no-pager -o short-iso`,
      CMD_TIMEOUT_MS, "journalctl(sshd)", partial
    );
    sudoText = await tryExec(
      `journalctl _COMM=sudo --since "-${windowHours}h" --no-pager -o short-iso`,
      CMD_TIMEOUT_MS, "journalctl(sudo)", partial
    );
    const suText = await tryExec(
      `journalctl _COMM=su --since "-${windowHours}h" --no-pager -o short-iso`,
      CMD_TIMEOUT_MS, "journalctl(su)", partial
    );
    if (suText) sudoText += "\n" + suText;
    sources.push("journalctl");
  } else if (fs.existsSync(AUTH_LOG)) {
    // El auth.log entero filtrado por proceso: sin año en el timestamp no hay filtro temporal
    // fino posible. Rota a diario en la mayoría de distros, así que como foto fija sirve.
    try {
      const content = fs.readFileSync(AUTH_LOG, "utf8");
      sshText = content.split("\n").filter((l) => /sshd/.test(l)).join("\n");
      sudoText = content.split("\n").filter((l) => /\bsudo\b|\bsu[:[]/.test(l)).join("\n");
      sources.push("auth.log");
    } catch (err) {
      partial.push({ source: "auth.log", reason: `no legible: ${err.message}` });
    }
  } else {
    partial.push({
      source: "journalctl/auth.log",
      reason: "ni journalctl ni /var/log/auth.log disponibles",
    });
  }

  const ssh = parseSshdLines(sshText);
  const sudo = parseSudoLines(sudoText);

  // lastb suele pedir root, así que solo se intenta si no hubo fallidos por otra vía y su
  // fracaso es un skip parcial, no un error.
  if (ssh.failed.length === 0 && (await commandExists("lastb"))) {
    try {
      const lastbOut = await execCommand("lastb -20", CMD_TIMEOUT_MS);
      for (const line of lastbOut.split("\n")) {
        const m = line.trim().match(/^(\S+)\s+(\S+)\s+(\S+)/);
        if (m && m[1] !== "btmp") {
          ssh.failed.push({ user: m[1], ip: m[3], timestamp: null, line: line.trim() });
        }
      }
      sources.push("lastb");
    } catch (err) {
      partial.push({ source: "lastb", reason: "requiere permisos (normal sin root)" });
    }
  }

  return { ssh, sudo };
}

/** macOS: todo sale del log unificado. */
async function collectDarwin(windowHours, sources, partial) {
  let sshText = "";
  let sudoText = "";

  if (await commandExists("log")) {
    // Desde OpenSSH 9.8 (Sequoia) cada conexión va a `sshd-session` y los "Accepted" salen a
    // nivel Info: sin --info y sin ese proceso el predicado antiguo no veía nada.
    sshText = await tryExec(
      `log show --style syslog --info --predicate '(process == "sshd") OR (process == "sshd-session")' --last ${windowHours}h`,
      LOG_TIMEOUT_MS, "log(sshd)", partial
    );
    sudoText = await tryExec(
      `log show --style syslog --info --predicate 'process == "sudo"' --last ${windowHours}h`,
      LOG_TIMEOUT_MS, "log(sudo)", partial
    );
    // `su` es otro proceso: sus fallos salen como "BAD SU ..." a nivel Default.
    const suText = await tryExec(
      `log show --style syslog --predicate 'process == "su"' --last ${windowHours}h`,
      LOG_TIMEOUT_MS, "log(su)", partial
    );
    if (suText) sudoText += "\n" + suText;
    sources.push("log");
  } else {
    partial.push({ source: "log", reason: "comando `log` no disponible" });
  }

  return { ssh: parseSshdLines(sshText), sudo: parseSudoLines(sudoText) };
}

const PS_TIMEOUT_MS = 60000; // Get-WinEvent sobre el canal Security puede tardar

/** ConvertTo-Json da objeto con un elemento y array con varios; aquí siempre array. */
function toArray(v) {
  return Array.isArray(v) ? v : v == null ? [] : [v];
}

/**
 * Los dos canales de Windows en una sola invocación de PowerShell, con la salida en JSON.
 *
 * FilterHashtable con StartTime en vez de XPath con fechas en texto, y TimeCreated serializado a
 * yyyy-MM-dd HH:mm:ss: las dos cosas, para no depender del formato regional (y porque en PS 5.1
 * ConvertTo-Json emitiría "/Date(ms)/"). Las Properties se leen por índice, estables por Id desde
 * Windows 7:
 *   4624: 5=TargetUserName, 7=TargetLogonId, 8=LogonType, 18=IpAddress
 *   4625: 5=TargetUserName, 10=LogonType, 19=IpAddress
 *   4672: 1=SubjectUserName, 3=SubjectLogonId
 * El 4672 no trae IP, así que su SubjectLogonId se cruza con el TargetLogonId del 4624. Ese
 * logonId se emite al JSON: es lo que permite atribuir un 4672 a su 4624 fuera de PowerShell y
 * sin heurística, en win-logons.js. Antes se calculaba aquí y se tiraba.
 *
 * Las cuentas de servicio se descartan en `Svc`, un solo sitio para los tres Ids: generan miles
 * de eventos por hora. `sshd_<PID>` va por patrón y no por lista, porque no es un usuario sino la
 * cuenta de separación de privilegios que sshd crea por conexión, con el PID dentro del nombre.
 * Su 4672 salía en el panel como «sesión admin de sshd_13048», y encima como local, que es como
 * lo reporta Windows pero no es el acceso de nadie.
 *
 * "No events found" no significa "no pasó nada": sin permisos sobre Security, Get-WinEvent
 * devuelve NoMatchingEventsFound igual que si la ventana estuviera vacía, y no lanza
 * UnauthorizedAccessException. Medido con 5 eventos 4625 reales: elevado salían los cinco, sin
 * elevar "no se encontraron eventos". Por eso ahí se sondea el canal con -ListLog: si está
 * habilitado, tiene registros y aun así no devuelve ni uno, es permiso y no ausencia. No se
 * mira si el proceso es administrador, porque un usuario de "Event Log Readers" lee el canal sin
 * serlo y suponerlo daría un falso "denegado".
 *
 * El canal OpenSSH/Operational se lee sin elevar y sus mensajes los escribe OpenSSH en inglés
 * sea cual sea el idioma de Windows, con el formato de Linux: se vuelca tal cual a parseSshdLines.
 */
function buildWinEventsScript(windowHours) {
  return `
$ErrorActionPreference = 'Stop'
$start = (Get-Date).AddHours(-${windowHours})
function V($p, $i) { if ($p.Count -gt $i -and $null -ne $p[$i].Value) { [string]$p[$i].Value } else { '' } }
function T($p, $i) { $v = V $p $i; if ($v -match '^[0-9]+$') { [int]$v } else { -1 } }
$out = @{ denied = $false; logons = @(); localLogonCount = 0; failed = @(); privileged = @(); ssh = @(); sshLog = '' }
$events = @()
$noneFound = $false
try {
  $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624, 4625, 4672; StartTime = $start } -ErrorAction Stop)
} catch {
  if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $events = @(); $noneFound = $true }
  elseif ($_.Exception.GetType().Name -eq 'UnauthorizedAccessException' -or $_.Exception.Message -match 'unauthorized|denied|denegad|autoriza') { $out.denied = $true }
  else { throw }
}
if ($noneFound -and -not $out.denied) {
  try {
    $log = Get-WinEvent -ListLog 'Security' -ErrorAction Stop
    if ($log.IsEnabled -and $log.RecordCount -gt 0) {
      $probe = @()
      try { $probe = @(Get-WinEvent -LogName 'Security' -MaxEvents 1 -ErrorAction Stop) }
      catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $probe = @() }
        else { $out.denied = $true }
      }
      if ($probe.Count -eq 0) { $out.denied = $true }
    }
  } catch { $out.denied = $true }
}
try {
  $sshEv = @(Get-WinEvent -FilterHashtable @{ LogName = 'OpenSSH/Operational'; StartTime = $start } -ErrorAction Stop)
  foreach ($e in $sshEv) {
    $msg = ($e.Message -split '\\r?\\n')[0]
    $out.ssh += ($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') + ' ' + $msg)
  }
} catch {
  if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $out.ssh = @() }
  else { $out.sshLog = $_.Exception.GetType().Name }
}
$byLogonId = @{}
foreach ($e in $events) {
  if ($e.Id -eq 4624) { $p = $e.Properties; $byLogonId[(V $p 7)] = @{ type = (T $p 8); ip = (V $p 18) } }
}
$svc = @('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'ANONYMOUS LOGON', 'SERVICIO LOCAL', 'SERVICIO DE RED')
function Svc($u) { return ($svc -contains $u.ToUpper() -or $u.EndsWith('$') -or $u -match '^sshd_\\d+$') }
foreach ($e in $events) {
  $p = $e.Properties
  $t = $e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
  if ($e.Id -eq 4624) {
    $user = V $p 5
    if (Svc $user) { continue }
    $lt = T $p 8
    if ($lt -eq 10 -or $lt -eq 3) {
      $out.logons += @{ t = $t; user = $user; type = $lt; ip = (V $p 18); logonId = (V $p 7) }
    } else {
      $out.localLogonCount++
    }
  } elseif ($e.Id -eq 4625) {
    $failedUser = V $p 5
    if (Svc $failedUser) { continue }
    $out.failed += @{ t = $t; user = $failedUser; type = (T $p 10); ip = (V $p 19) }
  } elseif ($e.Id -eq 4672) {
    $user = V $p 1
    if (Svc $user) { continue }
    $logonId = V $p 3
    $info = $byLogonId[$logonId]
    $remote = ($null -ne $info -and ($info.type -eq 10 -or $info.type -eq 3))
    $ip = ''; if ($remote) { $ip = $info.ip }
    $out.privileged += @{ t = $t; user = $user; remote = $remote; ip = $ip; logonId = $logonId }
  }
}
$out | ConvertTo-Json -Depth 4 -Compress
`.trim();
}

/**
 * El JSON del script a la estructura `windows` del módulo. `logonId` se conserva tal cual
 * ("0x3E7"): es la clave de correlación 4624↔4672. La IP pasa por normalizeWinIp porque Windows
 * escribe un guion literal en IpAddress cuando el logon no lleva dirección —el 4624 de tipo 3 que
 * crea sshd, por ejemplo— y como "-" es truthy llegaba entero a la columna ORIGEN del panel. El
 * filtro de cuentas de servicio se repite aquí como red para datos de una versión anterior, y
 * porque es la mitad de la regla que se puede probar sin Windows.
 */
function parseWinEventsJson(jsonText) {
  const data = JSON.parse(String(jsonText).trim());
  return {
    securityLogDenied: data.denied === true,
    // Del canal OpenSSH, el tipo .NET de la excepción y no su mensaje, que viene traducido.
    sshLines: toArray(data.ssh).map((l) => String(l)),
    sshLogError: data.sshLog ? String(data.sshLog) : "",
    logons: {
      remote: toArray(data.logons)
        .filter((l) => !isServiceAccount(l.user))
        .map((l) => ({
          user: l.user || "",
          ip: normalizeWinIp(l.ip),
          logonType: typeof l.type === "number" ? l.type : parseInt(l.type, 10) || -1,
          logonId: l.logonId ? String(l.logonId) : null,
          timestamp: l.t || null,
        })),
      localCount: parseInt(data.localLogonCount, 10) || 0,
    },
    failed: toArray(data.failed)
      .filter((f) => !isServiceAccount(f.user))
      .map((f) => ({
        user: f.user || "",
        ip: normalizeWinIp(f.ip),
        logonType: typeof f.type === "number" ? f.type : parseInt(f.type, 10) || -1,
        timestamp: f.t || null,
      })),
    privileged: toArray(data.privileged)
      .filter((p) => !isServiceAccount(p.user))
      .map((p) => ({
        user: p.user || "",
        remote: p.remote === true,
        ip: normalizeWinIp(p.ip),
        logonId: p.logonId ? String(p.logonId) : null,
        timestamp: p.t || null,
      })),
  };
}

/**
 * `query user`, en la forma que devuelve `who`. Cabecera en la primera línea y '>' marcando la
 * sesión propia. Se lee por posición y no por cabecera, que cambia con el idioma del SO; ojo con
 * las sesiones desconectadas, que vienen sin SESSIONNAME y desplazan las columnas.
 */
function parseQueryUserLines(text) {
  const sessions = [];
  const lines = String(text || "").split("\n");
  for (const rawLine of lines.slice(1)) {
    const line = rawLine.replace(/^[\s>]+/, " ").trim();
    if (!line) continue;
    const tokens = line.split(/\s+/);
    if (tokens.length < 4) continue;
    let tty, rest;
    if (/^\d+$/.test(tokens[1])) {
      // Desconectada: user, id, state, idle, fecha…
      tty = null;
      rest = tokens.slice(3);
    } else {
      tty = tokens[1];
      rest = tokens.slice(4);
    }
    sessions.push({
      user: tokens[0],
      tty,
      since: rest.slice(1).join(" ") || null, // rest[0] es el idle; el resto, la hora de entrada
      origin: tty && /^rdp-/i.test(tty) ? "RDP" : null,
    });
  }
  return sessions;
}

/** `qwinsta`, el respaldo: SESSIONNAME USERNAME ID STATE. Sin hora de entrada, y solo valen las
 *  filas con usuario, o sea las que no traen un número en el segundo token. */
function parseQwinstaLines(text) {
  const sessions = [];
  const lines = String(text || "").split("\n");
  for (const rawLine of lines.slice(1)) {
    const line = rawLine.replace(/^[\s>]+/, " ").trim();
    if (!line) continue;
    const tokens = line.split(/\s+/);
    if (tokens.length < 3 || /^\d+$/.test(tokens[1])) continue;
    sessions.push({
      user: tokens[1],
      tty: tokens[0],
      since: null,
      origin: /^rdp-/i.test(tokens[0]) ? "RDP" : null,
    });
  }
  return sessions;
}

/** Windows: canal Security más sesiones activas, con powershell o pwsh. Si no hay permisos sobre
 *  Security se marca securityLogDenied y se sigue, como con lastb en Linux. */
async function collectWin32(windowHours, sources, partial) {
  const windows = {
    securityLogDenied: false,
    logons: { remote: [], localCount: 0 },
    failed: [],
    privileged: [],
  };
  let sessions = [];
  // Misma forma que en Linux y macOS: ni el normalizador ni el dashboard preguntan de dónde vino.
  let ssh = { accepted: [], failed: [] };

  let psCmd = null;
  if (await commandExists("powershell")) psCmd = "powershell";
  else if (await commandExists("pwsh")) psCmd = "pwsh";

  if (!psCmd) {
    partial.push({
      source: "Get-WinEvent",
      reason: "ni powershell ni pwsh disponibles en el PATH",
    });
  } else {
    // Fichero temporal y no -EncodedCommand: así el script iba entero en la línea de comandos,
    // que Windows limita a 8191 caracteres, y UTF-16LE más base64 multiplican por 2,67, o sea
    // unos 3070 caracteres de margen real. Medido cuando dejó de funcionar: 3109 de script →
    // 8292 de base64. El fallo fue silencioso y total, porque los dos canales se leen en la misma
    // invocación: no salía ni un evento, elevado o no. Con -File el límite no aplica. No volver a
    // -EncodedCommand ni a -Command; el guardarraíl es test/manual/test-security-events-win32.js.
    //
    // Con BOM porque PowerShell 5.1 lee un .ps1 sin él usando la página de códigos ANSI. Hoy el
    // script es ASCII y daría igual, pero una tilde en un mensaje futuro sería mojibake.
    const script = buildWinEventsScript(windowHours);
    let out = "";
    try {
      out = await withTempFile(
        script,
        { prefix: "lcaudit-winevents-", ext: ".ps1", bom: true },
        (scriptPath) =>
          tryExec(
            `${psCmd} -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "${scriptPath}"`,
            PS_TIMEOUT_MS,
            "Get-WinEvent(Security)",
            partial
          )
      );
    } catch (err) {
      // Ni el fichero se pudo crear: fuente no disponible, nunca un dato de auditoría.
      partial.push({
        source: "Get-WinEvent(Security)",
        reason: `no se pudo escribir el script temporal: ${err.message || err}`,
      });
    }
    if (out) {
      try {
        const parsed = parseWinEventsJson(out);

        // Independiente de Security, se lea ese o no. Que falte es lo normal, porque Windows no
        // trae OpenSSH Server de fábrica: skip parcial, nunca un hallazgo.
        if (parsed.sshLogError) {
          partial.push({
            source: "Get-WinEvent(OpenSSH/Operational)",
            reason: parsed.sshLogError === "EventLogNotFoundException"
              ? "el canal no existe: OpenSSH Server no está instalado"
              : `no se pudo leer (${parsed.sshLogError})`,
          });
        } else {
          ssh = parseSshdLines(parsed.sshLines.join("\n"));
          sources.push("Get-WinEvent(OpenSSH)");
        }

        if (parsed.securityLogDenied) {
          windows.securityLogDenied = true;
          partial.push({
            source: "Get-WinEvent(Security)",
            reason: "sin permisos de lectura sobre el canal Security: no se ha " +
                    "podido comprobar si hubo accesos, fallos de login o elevaciones",
          });
        } else {
          Object.assign(windows, {
            securityLogDenied: parsed.securityLogDenied,
            logons: parsed.logons,
            failed: parsed.failed,
            privileged: parsed.privileged,
          });
          sources.push("Get-WinEvent(Security)");
        }
      } catch (err) {
        partial.push({
          source: "Get-WinEvent(Security)",
          reason: `salida no parseable: ${err.message}`,
        });
      }
    }
  }

  // query user, y qwinsta de respaldo. Los dos son herramientas de Escritorio Remoto y no vienen
  // en Windows Home, así que sin comprobarlo antes el usuario leía «Command failed: query user —
  // 'query' no se reconoce como un comando», que suena a avería y no a edición sin la herramienta.
  const SIN_RDS = "no disponible en esta edición de Windows " +
                  "(herramientas de Servicios de Escritorio Remoto no instaladas)";
  let sessionsChecked = false;

  if (await commandExists("query")) {
    const quOut = await tryExec("query user", CMD_TIMEOUT_MS, "query user", partial);
    if (quOut) {
      sessions = parseQueryUserLines(quOut);
      sources.push("query user");
      sessionsChecked = true;
    }
  } else if (await commandExists("qwinsta")) {
    const qwOut = await tryExec("qwinsta", CMD_TIMEOUT_MS, "qwinsta", partial);
    if (qwOut) {
      sessions = parseQwinstaLines(qwOut);
      sources.push("qwinsta");
      sessionsChecked = true;
    }
  } else {
    partial.push({ source: "query user / qwinsta", reason: SIN_RDS });
  }

  return { windows, sessions, ssh, sessionsChecked };
}

const MAX_EVENT_LIST = 200; // tope de eventos en payload.securityEvents.events

/** Timestamp a epoch, 0 si no se entiende. Solo para ordenar: el ts se muestra tal como vino. */
function tsToEpoch(ts) {
  if (!ts) return 0;
  const s = String(ts).trim();
  let t = Date.parse(s.replace(" ", "T"));           // ISO con espacio
  if (!Number.isNaN(t)) return t;
  t = Date.parse(s);                                  // formatos que Date entiende
  if (!Number.isNaN(t)) return t;
  const syslog = s.match(/^([A-Z][a-z]{2})\s+(\d{1,2}) (\d{2}:\d{2}:\d{2})/);
  if (syslog) {
    // syslog no lleva año; se asume el actual, que para una ventana de horas vale.
    t = Date.parse(`${syslog[1]} ${syslog[2]} ${new Date().getFullYear()} ${syslog[3]}`);
    if (!Number.isNaN(t)) return t;
  }
  return 0;
}

/**
 * El resultado aplanado como lo consume el dashboard: eventos ya parseados, ts descendente, tope
 * MAX_EVENT_LIST. Con skipped devuelve la lista vacía, que el finding informativo ya lo cuenta.
 *
 * En Windows, una fila por acceso y no una por fuente. Con Node-RED elevado se leen dos canales
 * que describen el mismo hecho y un único login SSH daba cuatro filas: la de SSH, el 4624 remoto,
 * el 4672 de esa sesión y el 4672 de sshd_<PID>. Sobrevive la de SSH porque trae la IP de origen
 * real, que el 4624 de sshd no lleva, y el método de autenticación; lo que aporta el 4672
 * absorbido, con qué cuenta se entró, se anota en `detail` y en el campo `privileged`.
 *
 * Un 4672 no dice que la sesión estuviera elevada: Windows lo emite cuando la CUENTA pertenece al
 * grupo Administradores, se eleve algo o no. Entrar por SSH con una cuenta administradora lo
 * dispara igual, así que los textos hablan de la cuenta.
 *
 * La regla de correlación vive en win-logons.js, compartida con el normalizador, que tiene que
 * decidir lo mismo para los findings. Tener dos copias era justo el fallo que se arregló.
 */
function buildEventList(result) {
  const windowHours = (result && result.windowHours) || 24;
  if (!result || result.skipped) {
    return { windowHours, events: [], truncated: false, sessionsChecked: false };
  }

  const events = [];
  const push = (ts, type, user, origin, detail, extra) =>
    events.push({
      ts: ts || null,
      type,
      user: user || null,
      origin: origin || null,
      detail: detail || null,
      ...(extra || {}),
    });

  const ssh = result.ssh || { accepted: [], failed: [] };
  const sudo = result.sudo || { ok: [], failed: [] };
  const sessions = Array.isArray(result.sessions) ? result.sessions : [];

  // En Linux y macOS no hay segunda fuente: la correlación sale vacía y los bucles no cambian.
  const corr = correlateWindowsLogons(result);

  for (const a of ssh.accepted) {
    const priv = corr.hasPrivilege(a);
    push(
      a.timestamp, "ssh-accepted", a.user, a.ip,
      `Login SSH correcto (${a.method || "?"})` +
        (priv ? " · con una cuenta que tiene privilegios de administrador (4672)" : ""),
      priv ? { privileged: true } : null
    );
  }
  for (const f of ssh.failed) push(f.timestamp, "ssh-failed", f.user, f.ip, "Intento de login SSH fallido");
  for (const s of sudo.ok) push(s.timestamp, "sudo", s.user, null, s.command || "sudo");
  for (const f of sudo.failed)
    push(f.timestamp, "sudo-failed", f.user, null,
      f.target ? `Fallo de autenticación su → ${f.target}` : "Fallo de autenticación sudo");

  if (result.windows) {
    const win = result.windows;
    // Los `absorbed*` ya están contados en una fila de SSH: emitirlos sería pintar dos veces
    // la misma sesión.
    for (const [i, l] of (((win.logons && win.logons.remote) || [])).entries()) {
      if (corr.absorbedRemote.has(i)) continue;
      push(l.timestamp, "logon-remote", l.user, l.ip,
        l.logonType === 10 ? "Login remoto RDP (4624)" : "Login remoto de red (4624)");
    }
    for (const [i, f] of ((win.failed || [])).entries()) {
      if (corr.absorbedFailed.has(i)) continue;
      push(f.timestamp, "logon-failed", f.user, f.ip, `Login fallido (4625, tipo ${f.logonType})`);
    }
    for (const [i, p] of ((win.privileged || [])).entries()) {
      if (corr.absorbedPriv.has(i)) continue;
      push(p.timestamp, "logon-privileged", p.user, p.ip,
        p.remote
          ? "Acceso remoto con una cuenta que tiene privilegios de administrador (4672)"
          : "Acceso local con una cuenta que tiene privilegios de administrador (4672)");
    }
  }

  for (const s of sessions) {
    push(s.since, "session", s.user, s.origin,
      `Sesión activa en ${s.tty || "?"}${s.origin ? " (remota)" : " (local)"}`);
  }

  events.sort((a, b) => tsToEpoch(b.ts) - tsToEpoch(a.ts));

  const truncated = events.length > MAX_EVENT_LIST;
  return {
    windowHours,
    events: truncated ? events.slice(0, MAX_EVENT_LIST) : events,
    truncated,
    // Para que el dashboard no diga "sin sesiones remotas activas" cuando no se pudo preguntar.
    sessionsChecked: result.sessionsChecked === true,
  };
}

/** Eventos de las últimas `windowHours` horas, entre 1 y 168, en crudo. */
async function runSecurityEvents(windowHours = 24) {
  const hours = Math.min(168, Math.max(1, parseInt(windowHours, 10) || 24));
  const platform = process.platform;
  const sources = [];
  const partial = [];

  if (platform !== "linux" && platform !== "darwin" && platform !== "win32") {
    return {
      skipped: true,
      reason: `plataforma ${platform} no soportada (los eventos de seguridad requieren Linux, macOS o Windows)`,
      windowHours: hours,
      platform,
    };
  }

  let ssh = { accepted: [], failed: [] };
  let sudo = { ok: [], failed: [] };
  let windows = null;
  let sessions = [];
  // Una lista de sesiones vacía no es "no hay nadie" si no se llegó a preguntar.
  let sessionsChecked = false;

  if (platform === "win32") {
    ({ windows, sessions, ssh, sessionsChecked } = await collectWin32(hours, sources, partial));
  } else {
    ({ ssh, sudo } =
      platform === "linux"
        ? await collectLinux(hours, sources, partial)
        : await collectDarwin(hours, sources, partial));

    if (await commandExists("who")) {
      const whoOut = await tryExec("who", CMD_TIMEOUT_MS, "who", partial);
      sessions = parseWhoLines(whoOut);
      if (whoOut) {
        sources.push("who");
        sessionsChecked = true;
      }
    } else {
      partial.push({ source: "who", reason: "comando `who` no disponible" });
    }
  }

  // Sin una sola fuente utilizable no hay auditoría que reportar, solo un skipped.
  if (sources.length === 0) {
    return {
      skipped: true,
      reason:
        "ninguna fuente de eventos disponible: " +
        partial.map((p) => `${p.source} (${p.reason})`).join("; "),
      windowHours: hours,
      platform,
      partial,
    };
  }

  const result = {
    windowHours: hours,
    platform,
    sources,
    partial,
    ssh,
    sudo,
    sessions,
    sessionsChecked,
  };
  if (windows) result.windows = windows;
  return result;
}

module.exports = {
  runSecurityEvents,
  buildEventList,
  parseSshdLines,
  parseSudoLines,
  parseWhoLines,
  // Expuestos para los tests de win32.
  parseWinEventsJson,
  parseQueryUserLines,
  parseQwinstaLines,
  buildWinEventsScript,
};
