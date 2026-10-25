"use strict";

/** Foto fija de los eventos de seguridad de las últimas N horas (logins, sudo/su, sesiones). No es un HIDS y nunca pide sudo.
 *  Sin fuentes devuelve { skipped, reason }; las que fallan sueltas van en `partial`. */

const fs = require("fs");
const { ejecutar, existeComando } = require("../../../lib/executor");
const {
  esCuentaDeServicio,
  normalizarIpWindows,
  correlacionarInicios,
} = require("../../../lib/win-logons");
const { conFicheroTemporal } = require("../../../lib/utils");

const LOG_TIMEOUT_MS = 60000;   // `log show` en macOS puede tardar
const CMD_TIMEOUT_MS = 15000;   // journalctl / who / last / lastb
const AUTH_LOG = "/var/log/auth.log";

/** Timestamp del principio de la línea, venga en ISO o en syslog. */
function extraerFecha(line) {
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

/** El PID identifica la sesión y sirve para deduplicar las líneas de un mismo intento. */
function pidDeEtiqueta(line, tagRe) {
  const m = line.match(tagRe);
  if (m) {
    return m[1];
  } else {
    return null;
  }
}

/** "sshd-session[5775]:" → "5775"; también sshd y sshd-auth. */
const SSHD_PID_RE = /sshd(?:-session|-auth)?\[(\d+)\]/;

/** Clave de sesión sin [PID] (OpenSSH de Windows): IP:puerto, único por conexión TCP. */
function claveConexion(line) {
  let m = line.match(/\bfrom (\S+) port (\d+)/);
  if (!m) m = line.match(/\buser \S+ (\S+) port (\d+)/);
  if (m) {
    return `${m[1]}:${m[2]}`;
  } else {
    return null;
  }
}

/** Líneas de sshd y el error PAM de macOS. Solo cuenta "Failed password"; "Invalid user" y "Connection closed"
 *  son respaldo, uno por sesión, para los fallos de publickey. */
function leerSshd(text) {
  const accepted = [];
  const failed = [];
  const failedKeys = new Set();        // sesiones con al menos un "Failed password"
  const fallbackByKey = new Map();     // sesión → evento de respaldo (uno por conexión)
  let noKeySeq = 0;                     // clave sintética cuando no hay PID ni IP:puerto

  for (const rawLine of String(text || "").split("\n")) {
    const line = rawLine.trim();
    if (!line) continue;
    // PID cuando lo hay; si no, IP:puerto.
    const sessionKey = pidDeEtiqueta(line, SSHD_PID_RE) || claveConexion(line);

    let m = line.match(/Accepted (\S+) for (?:invalid user )?(\S+) from (\S+)/);
    if (m) {
      accepted.push({
        method: m[1],
        user: m[2],
        ip: m[3],
        timestamp: extraerFecha(line),
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
        timestamp: extraerFecha(line),
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
          ev: { user: m[1], ip: m[2], timestamp: extraerFecha(line), line },
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

/** Líneas de sudo y su: un sudo correcto lleva COMMAND=; los fallos, los mensajes de contraseña de sudo o pam_unix. */
function leerSudo(text) {
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
        timestamp: extraerFecha(line),
        line,
      });
      continue;
    }

    m = line.match(/(\S+) : \d+ incorrect password attempt/);
    if (!m) m = line.match(/(\S+) : a password is required/);
    if (!m) {
      if (/authentication failure/.test(line)) {
        m = line.match(/\buser=(\S+)/);
      } else {
        m = null;
      }
    }
    if (m) {
      failed.push({
        user: m[1],
        timestamp: extraerFecha(line),
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
        timestamp: extraerFecha(line),
        line,
      });
      continue;
    }

    // Solo el su real: la sesión pam de sudo ya la cuenta la línea COMMAND=.
    m = line.match(/session opened for user ([^\s(]+)(?:\(uid=\d+\))? by ([^\s(]+)/);
    if (m && !/pam_unix\(sudo:/.test(line)) {
      ok.push({
        user: m[2],
        command: `su → ${m[1]}`,
        timestamp: extraerFecha(line),
        line,
      });
    }
  }
  return { ok, failed };
}

/** `who`: <user> <tty> <fecha> [(origen)], con el origen solo en las sesiones remotas. */
function leerWho(text) {
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

// Aviso de journalctl cuando el usuario no puede leer el journal del sistema.
const JOURNAL_DENIED_RE = /not seeing messages from other users|insufficient permissions|permission denied/i;

/** Si el comando falla, el motivo va a partial[] y devuelve null, para no confundirlo con una salida vacía. */
async function intentarEjecutar(cmd, timeoutMs, sourceName, partial) {
  try {
    return await ejecutar(cmd, timeoutMs);
  } catch (err) {
    partial.push({ source: sourceName, reason: err.message || "exec failed" });
    return null;
  }
}

/** journalctl con stderr: { text, denied }, o null si falló. Un fallo por permisos lleva kind propio. */
async function intentarJournal(cmd, sourceName, partial) {
  try {
    const { stdout, stderr } = await ejecutar(cmd, CMD_TIMEOUT_MS, { withStderr: true });
    return { text: stdout, denied: JOURNAL_DENIED_RE.test(stderr || "") };
  } catch (err) {
    const denied = JOURNAL_DENIED_RE.test(`${err.stderr || ""} ${err.message || ""}`);
    let permiso;
    if (denied) {
      permiso = { kind: "no-permission" };
    } else {
      permiso = {};
    }
    partial.push({
      source: sourceName,
      reason: err.message || "exec failed",
      ...permiso,
    });
    return null;
  }
}

/** Linux: journalctl primero, auth.log de respaldo. */
async function recogerLinux(windowHours, sources, partial) {
  let sshText = "";
  let sudoText = "";
  let logsChecked = false;

  if (await existeComando("journalctl")) {
    // Desde OpenSSH 9.8 autentica `sshd-session` (y `sshd-auth`): hace falta más de un _COMM=.
    // `-o short-iso` porque para deduplicar hacen falta timestamp y [PID].
    const sshRes = await intentarJournal(
      `journalctl _COMM=sshd _COMM=sshd-session _COMM=sshd-auth --since "-${windowHours}h" --no-pager -o short-iso`,
      "journalctl(sshd)", partial
    );
    const sudoRes = await intentarJournal(
      `journalctl _COMM=sudo --since "-${windowHours}h" --no-pager -o short-iso`,
      "journalctl(sudo)", partial
    );
    const suRes = await intentarJournal(
      `journalctl _COMM=su --since "-${windowHours}h" --no-pager -o short-iso`,
      "journalctl(su)", partial
    );
    sshText = (sshRes && sshRes.text) || "";
    sudoText = (sudoRes && sudoRes.text) || "";
    if (suRes && suRes.text) sudoText += "\n" + suRes.text;
    const hechas = [sshRes, sudoRes, suRes].filter(Boolean);
    // Sin permisos journalctl sale con 0 pero solo enseña los mensajes propios: no se ven sshd ni sudo.
    const vistas = hechas.filter((r) => !r.denied);
    if (hechas.length > vistas.length) {
      partial.push({
        source: "journalctl",
        kind: "no-permission",
        reason: "journalctl avisa de que no se ven los mensajes de otros usuarios ni del sistema: " +
                "faltan permisos de lectura del journal (grupos adm o systemd-journal)",
      });
    }
    // Solo cuenta como fuente si alguna consulta llegó a ver el journal completo.
    if (vistas.length) {
      sources.push("journalctl");
      logsChecked = true;
    }
  } else if (fs.existsSync(AUTH_LOG)) {
    // auth.log no lleva año: se filtra por proceso y no por hora (rota a diario).
    try {
      const content = fs.readFileSync(AUTH_LOG, "utf8");
      sshText = content.split("\n").filter((l) => /sshd/.test(l)).join("\n");
      sudoText = content.split("\n").filter((l) => /\bsudo\b|\bsu[:[]/.test(l)).join("\n");
      sources.push("auth.log");
      logsChecked = true;
    } catch (err) {
      let permiso;
      if (err.code === "EACCES" || err.code === "EPERM") {
        permiso = { kind: "no-permission" };
      } else {
        permiso = {};
      }
      partial.push({
        source: "auth.log",
        reason: `no legible: ${err.message}`,
        ...permiso,
      });
    }
  } else {
    partial.push({
      source: "journalctl/auth.log",
      reason: "ni journalctl ni /var/log/auth.log disponibles",
    });
  }

  const ssh = leerSshd(sshText);
  const sudo = leerSudo(sudoText);

  // lastb suele pedir root: solo se intenta si no hubo fallidos por otra vía, y su fallo es un skip parcial.
  if (ssh.failed.length === 0 && (await existeComando("lastb"))) {
    try {
      const lastbOut = await ejecutar("lastb -20", CMD_TIMEOUT_MS);
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

  return { ssh, sudo, logsChecked };
}

/** macOS: todo sale del log unificado. */
async function recogerMac(windowHours, sources, partial) {
  let sshText = "";
  let sudoText = "";
  let logsChecked = false;

  if (await existeComando("log")) {
    // Desde OpenSSH 9.8 los "Accepted" salen de `sshd-session` a nivel Info: hace falta --info.
    const sshOut = await intentarEjecutar(
      `log show --style syslog --info --predicate '(process == "sshd") OR (process == "sshd-session")' --last ${windowHours}h`,
      LOG_TIMEOUT_MS, "log(sshd)", partial
    );
    const sudoOut = await intentarEjecutar(
      `log show --style syslog --info --predicate 'process == "sudo"' --last ${windowHours}h`,
      LOG_TIMEOUT_MS, "log(sudo)", partial
    );
    sshText = sshOut || "";
    sudoText = sudoOut || "";
    // `su` es otro proceso: sus fallos salen como "BAD SU ..." a nivel Default.
    const suText = await intentarEjecutar(
      `log show --style syslog --predicate 'process == "su"' --last ${windowHours}h`,
      LOG_TIMEOUT_MS, "log(su)", partial
    );
    if (suText) sudoText += "\n" + suText;
    // Solo cuenta como fuente si alguna de las tres consultas funcionó.
    if (sshOut !== null || sudoOut !== null || suText !== null) {
      sources.push("log");
      logsChecked = true;
    }
  } else {
    partial.push({ source: "log", reason: "comando `log` no disponible" });
  }

  return { ssh: leerSshd(sshText), sudo: leerSudo(sudoText), logsChecked };
}

const PS_TIMEOUT_MS = 60000; // Get-WinEvent sobre el canal Security puede tardar

/** ConvertTo-Json da objeto con un elemento y array con varios; aquí siempre array. */
function comoLista(v) {
  if (Array.isArray(v)) {
    return v;
  } else if (v == null) {
    return [];
  } else {
    return [v];
  }
}

/** Canales Security y OpenSSH/Operational en una sola invocación de PowerShell, con fechas yyyy-MM-dd HH:mm:ss.
 *  Properties por índice: 4624 5=user 7=logonId 8=tipo 18=IP; 4625 5=user 10=tipo 19=IP; 4672 1=user 3=logonId.
 *  Sin permisos, Get-WinEvent responde como con la ventana vacía: por eso se sondea el canal con -ListLog. */
function scriptEventosWindows(windowHours) {
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

/** JSON del script a la estructura `windows`. `logonId` se conserva tal cual: es la clave de correlación 4624↔4672. */
function leerEventosWindows(jsonText) {
  const data = JSON.parse(String(jsonText).trim());
  const denegado = data.denied === true;
  const lineasSsh = comoLista(data.ssh).map((l) => String(l));
  // El tipo .NET de la excepción, no su mensaje, que llega traducido.
  let errorSsh;
  if (data.sshLog) {
    errorSsh = String(data.sshLog);
  } else {
    errorSsh = "";
  }
  return {
    securityLogDenied: denegado,
    sshLines: lineasSsh,
    sshLogError: errorSsh,
    logons: {
      remote: comoLista(data.logons)
        .filter((l) => !esCuentaDeServicio(l.user))
        .map((l) => {
          let tipo;
          if (typeof l.type === "number") {
            tipo = l.type;
          } else {
            tipo = parseInt(l.type, 10) || -1;
          }
          let sesion;
          if (l.logonId) {
            sesion = String(l.logonId);
          } else {
            sesion = null;
          }
          return {
            user: l.user || "",
            ip: normalizarIpWindows(l.ip),
            logonType: tipo,
            logonId: sesion,
            timestamp: l.t || null,
          };
        }),
      localCount: parseInt(data.localLogonCount, 10) || 0,
    },
    failed: comoLista(data.failed)
      .filter((f) => !esCuentaDeServicio(f.user))
      .map((f) => {
        let tipo;
        if (typeof f.type === "number") {
          tipo = f.type;
        } else {
          tipo = parseInt(f.type, 10) || -1;
        }
        return {
          user: f.user || "",
          ip: normalizarIpWindows(f.ip),
          logonType: tipo,
          timestamp: f.t || null,
        };
      }),
    privileged: comoLista(data.privileged)
      .filter((p) => !esCuentaDeServicio(p.user))
      .map((p) => {
        let sesion;
        if (p.logonId) {
          sesion = String(p.logonId);
        } else {
          sesion = null;
        }
        return {
          user: p.user || "",
          remote: p.remote === true,
          ip: normalizarIpWindows(p.ip),
          logonId: sesion,
          timestamp: p.t || null,
        };
      }),
  };
}

/** `query user` en la forma de `who`. Se lee por posición (la cabecera cambia con el idioma); las sesiones
 *  desconectadas no traen SESSIONNAME y desplazan las columnas. */
function leerQueryUser(text) {
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
    let origen;
    if (tty && /^rdp-/i.test(tty)) {
      origen = "RDP";
    } else {
      origen = null;
    }
    sessions.push({
      user: tokens[0],
      tty,
      since: rest.slice(1).join(" ") || null, // rest[0] es el idle; el resto, la hora de entrada
      origin: origen,
    });
  }
  return sessions;
}

/** `qwinsta`, de respaldo: sin hora de entrada; solo valen las filas con usuario. */
function leerQwinsta(text) {
  const sessions = [];
  const lines = String(text || "").split("\n");
  for (const rawLine of lines.slice(1)) {
    const line = rawLine.replace(/^[\s>]+/, " ").trim();
    if (!line) continue;
    const tokens = line.split(/\s+/);
    if (tokens.length < 3 || /^\d+$/.test(tokens[1])) continue;
    let origen;
    if (/^rdp-/i.test(tokens[0])) {
      origen = "RDP";
    } else {
      origen = null;
    }
    sessions.push({
      user: tokens[1],
      tty: tokens[0],
      since: null,
      origin: origen,
    });
  }
  return sessions;
}

/** Windows: canal Security y sesiones activas. Sin permisos sobre Security se marca securityLogDenied y se sigue. */
async function recogerWindows(windowHours, sources, partial) {
  const windows = {
    securityLogDenied: false,
    logons: { remote: [], localCount: 0 },
    failed: [],
    privileged: [],
  };
  let sessions = [];
  // Misma forma que en Linux y macOS.
  let ssh = { accepted: [], failed: [] };

  let psCmd = null;
  if (await existeComando("powershell")) psCmd = "powershell";
  else if (await existeComando("pwsh")) psCmd = "pwsh";

  if (!psCmd) {
    partial.push({
      source: "Get-WinEvent",
      reason: "ni powershell ni pwsh disponibles en el PATH",
    });
  } else {
    // Fichero temporal y no -EncodedCommand ni -Command: el límite de 8191 caracteres falla en silencio.
    // Lo guarda test/manual/test-security-events-win32.js.
    const script = scriptEventosWindows(windowHours);
    let out = "";
    try {
      out = await conFicheroTemporal(
        script,
        { prefix: "lcaudit-winevents-", ext: ".ps1", bom: true },
        (scriptPath) =>
          intentarEjecutar(
            `${psCmd} -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "${scriptPath}"`,
            PS_TIMEOUT_MS,
            "Get-WinEvent(Security)",
            partial
          )
      );
    } catch (err) {
      // Ni se pudo crear el fichero: fuente no disponible, no un dato de auditoría.
      partial.push({
        source: "Get-WinEvent(Security)",
        reason: `no se pudo escribir el script temporal: ${err.message || err}`,
      });
    }
    if (out) {
      try {
        const parsed = leerEventosWindows(out);

        // OpenSSH Server no viene de fábrica en Windows: que falte es un skip parcial, nunca un hallazgo.
        if (parsed.sshLogError) {
          let motivo;
          if (parsed.sshLogError === "EventLogNotFoundException") {
            motivo = "el canal no existe: OpenSSH Server no está instalado";
          } else {
            motivo = `no se pudo leer (${parsed.sshLogError})`;
          }
          partial.push({
            source: "Get-WinEvent(OpenSSH/Operational)",
            reason: motivo,
          });
        } else {
          ssh = leerSshd(parsed.sshLines.join("\n"));
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

  // query user y qwinsta no vienen en Windows Home: se comprueban antes para no mostrar un error que parezca una avería.
  const SIN_RDS = "no disponible en esta edición de Windows " +
                  "(herramientas de Servicios de Escritorio Remoto no instaladas)";
  let sessionsChecked = false;

  if (await existeComando("query")) {
    const quOut = await intentarEjecutar("query user", CMD_TIMEOUT_MS, "query user", partial);
    if (quOut) {
      sessions = leerQueryUser(quOut);
      sources.push("query user");
      sessionsChecked = true;
    }
  } else if (await existeComando("qwinsta")) {
    const qwOut = await intentarEjecutar("qwinsta", CMD_TIMEOUT_MS, "qwinsta", partial);
    if (qwOut) {
      sessions = leerQwinsta(qwOut);
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
function fechaAEpoch(ts) {
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

/** Lista plana para el dashboard, ts descendente. En Windows, una fila por acceso: queda la de SSH y lo del 4672
 *  va en `detail` y `privileged` (cuenta administradora, no sesión elevada). Correlación en win-logons.js. */
function listaDeEventos(result) {
  const windowHours = (result && result.windowHours) || 24;
  if (!result || result.skipped) {
    return { windowHours, events: [], truncated: false, sessionsChecked: false };
  }

  const events = [];
  const agregar = (ts, type, user, origin, detail, extra) =>
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
  let sessions;
  if (Array.isArray(result.sessions)) {
    sessions = result.sessions;
  } else {
    sessions = [];
  }

  // En Linux y macOS no hay segunda fuente: la correlación sale vacía y los bucles no cambian.
  const corr = correlacionarInicios(result);

  for (const a of ssh.accepted) {
    const priv = corr.tienePrivilegio(a);
    let sufijo;
    let marca;
    if (priv) {
      sufijo = " · con una cuenta que tiene privilegios de administrador (4672)";
      marca = { privileged: true };
    } else {
      sufijo = "";
      marca = null;
    }
    agregar(
      a.timestamp, "ssh-accepted", a.user, a.ip,
      `Login SSH correcto (${a.method || "?"})` + sufijo,
      marca
    );
  }
  for (const f of ssh.failed) agregar(f.timestamp, "ssh-failed", f.user, f.ip, "Intento de login SSH fallido");
  for (const s of sudo.ok) agregar(s.timestamp, "sudo", s.user, null, s.command || "sudo");
  for (const f of sudo.failed) {
    let texto;
    if (f.target) {
      texto = `Fallo de autenticación su → ${f.target}`;
    } else {
      texto = "Fallo de autenticación sudo";
    }
    agregar(f.timestamp, "sudo-failed", f.user, null, texto);
  }

  if (result.windows) {
    const win = result.windows;
    // Los `absorbed*` ya salen en una fila de SSH.
    for (const [i, l] of (((win.logons && win.logons.remote) || [])).entries()) {
      if (corr.absorbedRemote.has(i)) continue;
      let texto;
      if (l.logonType === 10) {
        texto = "Login remoto RDP (4624)";
      } else {
        texto = "Login remoto de red (4624)";
      }
      agregar(l.timestamp, "logon-remote", l.user, l.ip, texto);
    }
    for (const [i, f] of ((win.failed || [])).entries()) {
      if (corr.absorbedFailed.has(i)) continue;
      agregar(f.timestamp, "logon-failed", f.user, f.ip, `Login fallido (4625, tipo ${f.logonType})`);
    }
    for (const [i, p] of ((win.privileged || [])).entries()) {
      if (corr.absorbedPriv.has(i)) continue;
      let texto;
      if (p.remote) {
        texto = "Acceso remoto con una cuenta que tiene privilegios de administrador (4672)";
      } else {
        texto = "Acceso local con una cuenta que tiene privilegios de administrador (4672)";
      }
      agregar(p.timestamp, "logon-privileged", p.user, p.ip, texto);
    }
  }

  for (const s of sessions) {
    let sufijo;
    if (s.origin) {
      sufijo = " (remota)";
    } else {
      sufijo = " (local)";
    }
    agregar(s.since, "session", s.user, s.origin,
      `Sesión activa en ${s.tty || "?"}${sufijo}`);
  }

  events.sort((a, b) => fechaAEpoch(b.ts) - fechaAEpoch(a.ts));

  const truncated = events.length > MAX_EVENT_LIST;
  let lista;
  if (truncated) {
    lista = events.slice(0, MAX_EVENT_LIST);
  } else {
    lista = events;
  }
  return {
    windowHours,
    events: lista,
    truncated,
    // Para que el dashboard no diga "sin sesiones remotas activas" cuando no se pudo preguntar.
    sessionsChecked: result.sessionsChecked === true,
  };
}

/** Eventos de las últimas `windowHours` horas, entre 1 y 168, en crudo. */
async function ejecutarEventos(windowHours = 24) {
  const hours = Math.min(168, Math.max(1, parseInt(windowHours, 10) || 24));
  const platform = process.platform;
  const sources = [];
  const partial = [];

  if (platform !== "linux" && platform !== "darwin" && platform !== "win32") {
    return {
      skipped: true,
      kind: "unsupported",
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
  // Linux y macOS: si no se pudo leer ningún log, `who` solo no basta para decir "sin eventos".
  let logsChecked = true;

  if (platform === "win32") {
    ({ windows, sessions, ssh, sessionsChecked } = await recogerWindows(hours, sources, partial));
  } else {
    if (platform === "linux") {
      ({ ssh, sudo, logsChecked } = await recogerLinux(hours, sources, partial));
    } else {
      ({ ssh, sudo, logsChecked } = await recogerMac(hours, sources, partial));
    }

    if (await existeComando("who")) {
      const whoOut = await intentarEjecutar("who", CMD_TIMEOUT_MS, "who", partial);
      sessions = leerWho(whoOut);
      if (whoOut) {
        sources.push("who");
        sessionsChecked = true;
      }
    } else {
      partial.push({ source: "who", reason: "comando `who` no disponible" });
    }
  }

  // Sin una sola fuente utilizable no hay auditoría que reportar, solo un skipped.
  if (sources.length === 0 || !logsChecked) {
    // Por permisos solo si todo lo que falló fue por permisos.
    const fallos = partial.filter((p) => p.source !== "lastb");
    const sinPermiso = fallos.length > 0 && fallos.every((p) => p.kind === "no-permission");
    let tipo;
    if (sinPermiso) {
      tipo = "no-permission";
    } else {
      tipo = "error";
    }
    let prefijo;
    if (sources.length) {
      prefijo = "no se ha podido leer ningún log de autenticación: ";
    } else {
      prefijo = "ninguna fuente de eventos disponible: ";
    }
    return {
      skipped: true,
      kind: tipo,
      reason:
        prefijo +
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
  ejecutarEventos,
  listaDeEventos,
  leerSshd,
  leerSudo,
  leerWho,
  // Expuestos para los tests de win32.
  leerEventosWindows,
  leerQueryUser,
  leerQwinsta,
  scriptEventosWindows,
};
