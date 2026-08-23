"use strict";

/**
 * security-events.js — Auditoría puntual (foto fija) de eventos de seguridad.
 *
 * Recoge, en una ventana temporal configurable (horas):
 *   A) Logins correctos y fallidos:
 *        - Linux/macOS: SSH (journalctl / auth.log en Linux, `log show` en macOS)
 *        - Windows: eventos 4624/4625/4672 del canal Security vía Get-WinEvent
 *   B) Escalada de privilegios: usos de sudo/su, correctos y fallidos
 *      (en Windows la auditoría UAC/4688 requiere política no activa por
 *      defecto — se documenta como limitación v1, ver normalizer)
 *   C) Sesiones activas ahora mismo (`who` en Unix, `query user` en Windows)
 *
 * NO es un HIDS ni monitorización continua: se ejecuta, recoge eventos
 * recientes, devuelve datos crudos y termina — igual que el resto de
 * submódulos de audit-host.
 *
 * ── Delimitación con Lynis ──────────────────────────────────────────────────
 * Lynis audita la CONFIGURACIÓN de SSH (hardening: PermitRootLogin, versión
 * de protocolo...). Este submódulo audita los EVENTOS (quién entró, cuándo,
 * desde dónde). No duplicar aquí chequeos de configuración.
 *
 * Patrón obligatorio del proyecto: si ninguna fuente de logs está disponible
 * (sin journalctl ni auth.log legible en Linux; sin `log` en macOS; permisos
 * insuficientes) → { skipped: true, reason }. Las fuentes que fallan
 * individualmente se registran en `partial` sin romper el flujo. NUNCA se
 * pide sudo ni se ejecuta nada destructivo.
 *
 * Este módulo solo recolecta datos crudos. La severidad la asigna
 * lib/normalizer.js con las reglas SECURITY_EVENT_RULES de lib/severity-map.js.
 *
 * Exporta:
 *   runSecurityEvents(windowHours = 24) → Promise<{
 *     skipped?: boolean, reason?: string,
 *     windowHours: number, platform: string,
 *     sources: string[],                       // fuentes que sí se leyeron
 *     partial: Array<{ source, reason }>,      // fuentes no disponibles
 *     ssh:  { accepted: Array<{user, ip, method, timestamp, line}>,
 *             failed:   Array<{user, ip, timestamp, line}> },
 *     sudo: { ok:     Array<{user, command, timestamp, line}>,
 *             failed: Array<{user, timestamp, line}> },
 *     sessions: Array<{user, tty, since, origin}>,  // origin null si es local
 *     windows?: {                                   // solo en win32
 *       securityLogDenied: boolean,                 // canal Security sin permisos
 *       logons: { remote: Array<{user, ip, logonType, timestamp}>,  // 4624 tipo 3/10
 *                 localCount: number },             // 4624 locales, solo recuento
 *       failed: Array<{user, ip, logonType, timestamp}>,            // 4625
 *       privileged: Array<{user, remote, ip, timestamp}>            // 4672
 *     }
 *   }>
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

// ── Parsers de líneas de log ────────────────────────────────────────────────

/** Extrae un timestamp legible del inicio de una línea de log (syslog o ISO). */
function extractTimestamp(line) {
  // `log show --style syslog`: 2026-07-02 10:15:30.123456+0200
  const iso = line.match(/^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})/);
  if (iso) return `${iso[1]} ${iso[2]}`;
  // journalctl -o short-iso: 2026-07-16T12:57:23+0200 (sin locale, con año)
  const shortIso = line.match(/^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})/);
  if (shortIso) return `${shortIso[1]} ${shortIso[2]}`;
  // syslog clásico (auth.log): "Jul  2 10:15:30" — o "jul 16 12:57:23" en
  // locales que emiten el mes en minúscula (ES): aceptar ambas capitalizaciones.
  const syslog = line.match(/^([A-Za-z]{3}\s+\d{1,2} \d{2}:\d{2}:\d{2})/);
  if (syslog) return syslog[1];
  return null;
}

/** PID de la línea de journal/syslog: "sshd-session[5775]:" → "5775".
 *  Identifica la sesión/proceso para deduplicar eventos redundantes. */
function tagPid(line, tagRe) {
  const m = line.match(tagRe);
  return m ? m[1] : null;
}

/** PID de una línea sshd/sshd-session/sshd-auth: "sshd-session[5775]:" → "5775". */
const SSHD_PID_RE = /sshd(?:-session|-auth)?\[(\d+)\]/;

/**
 * Identificador de conexión cuando la línea no trae [PID].
 *
 * El canal OpenSSH/Operational de Windows emite "sshd: Failed password for ..."
 * sin el PID que sí lleva journalctl. Sin una clave de sesión, cada línea de
 * respaldo ("Invalid user ...", "Connection closed by authenticating user ...")
 * se contaba como un intento propio: 3 intentos reales salían como 5.
 *
 * El par IP+puerto identifica la conexión igual de bien que el PID — el puerto
 * de origen es único por conexión TCP — y aparece en las tres formas de línea:
 *   ... for <user> from <ip> port <n> ssh2
 *   Invalid user <user> from <ip> port <n>
 *   Connection closed by authenticating user <user> <ip> port <n> [preauth]
 *
 * Solo se usa como respaldo del PID, así que Linux y macOS no cambian.
 */
function connKey(line) {
  let m = line.match(/\bfrom (\S+) port (\d+)/);
  if (!m) m = line.match(/\buser \S+ (\S+) port (\d+)/);
  return m ? `${m[1]}:${m[2]}` : null;
}

/**
 * Parsea líneas de sshd → logins aceptados y fallidos.
 * Formatos cubiertos (Linux y macOS comparten OpenSSH):
 *   Accepted password|publickey|keyboard-interactive/pam for [invalid user] <user> from <ip> port ...
 *   Failed password|... for [invalid user] <user> from <ip> port ...
 *   error: PAM: authentication error for [illegal user] <user> from <host>  (macOS)
 *
 * ── Deduplicación (fuente canónica: "Failed password") ──────────────────────
 * Un solo intento fallido emite varias líneas en la MISMA sesión (mismo PID):
 *   "Failed password for root from ::1 port N ssh2"          ← canónica (1/intento)
 *   "pam_unix(sshd:auth): authentication failure; ... user=root"   ← resumen, se descarta
 *   "PAM N more authentication failures; ... user=root"            ← resumen, se descarta
 *   "Connection closed by authenticating user root ::1 [preauth]"  ← desconexión, se descarta
 * Solo se cuenta "Failed password" (un evento por intento real de contraseña).
 * Las líneas "Connection closed by (authenticating|invalid) user ..." e
 * "Invalid user ..." se usan SOLO como respaldo para conexiones que nunca
 * emitieron un "Failed password" (p.ej. fallos de publickey), a razón de un
 * único evento por PID, para no inflar el conteo de fuerza bruta.
 *
 * El [PID] procede del prefijo de `-o short-iso`. Cuando no lo hay — `-o cat`,
 * o el canal OpenSSH/Operational de Windows — se usa IP:puerto como clave de
 * sesión (ver connKey()); si tampoco hubiera, el respaldo se añade sin
 * correlación, en modo best-effort.
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
    // PID cuando lo hay (journalctl, log de macOS); si no, IP:puerto — ver connKey().
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

    // Canónica: un evento por intento fallido de contraseña.
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

    // Resúmenes redundantes del mismo intento → descartar (el "Failed password"
    // ya lo cuenta; contarlos duplicaría el evento).
    if (/authentication failure|more authentication failures/.test(line)) continue;

    // Respaldo (solo para conexiones sin "Failed password"): un evento por PID.
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

  // Añadir respaldos cuya sesión nunca produjo un "Failed password".
  for (const { key, ev } of fallbackByKey.values()) {
    if (key && failedKeys.has(key)) continue;
    failed.push(ev);
  }

  return { accepted, failed };
}

/**
 * Parsea líneas de sudo/su → usos correctos y fallos de autenticación.
 * Formatos cubiertos:
 *   <user> : TTY=... ; PWD=... ; USER=root ; COMMAND=/usr/bin/...   (sudo OK)
 *   <user> : N incorrect password attempt(s) ; TTY=...              (sudo fail)
 *   <user> : a password is required ; PWD=... ; COMMAND=...         (sudo fail, -n)
 *   pam_unix(sudo:auth): authentication failure; ... user=<user>    (sudo fail)
 *   pam_unix(su:session): session opened for user root by <user>    (su OK)
 *   BAD SU <user> to <target> on /dev/ttysN                         (su fail, macOS)
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

    // su fallido en macOS: "BAD SU <user> to <target> on /dev/ttysN"
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

    // su REAL → "pam_unix(su:session): session opened for user root(uid=0) by X(uid=1000)".
    // El equivalente de sudo — "pam_unix(sudo:session): session opened ..." — se
    // DESCARTA: la línea COMMAND= de arriba ya cuenta ese uso de sudo. Contar
    // ambas duplicaría cada invocación (el "13 usos" inflado del dashboard).
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

/**
 * Parsea la salida de `who` → sesiones activas ahora.
 * Formato: <user> <tty> <fecha> [(origen)]  — origen solo en sesiones remotas.
 */
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
        origin: m[4] || null, // null → sesión local
      });
    }
  }
  return sessions;
}

// ── Recolección por plataforma ──────────────────────────────────────────────

/** Ejecuta cmd; si falla, registra el motivo en partial[] y devuelve "". */
async function tryExec(cmd, timeoutMs, sourceName, partial) {
  try {
    return await execCommand(cmd, timeoutMs);
  } catch (err) {
    partial.push({ source: sourceName, reason: err.message || "exec failed" });
    return "";
  }
}

/** Lee sshd y sudo/su en Linux: journalctl primero, auth.log como fallback. */
async function collectLinux(windowHours, sources, partial) {
  let sshText = "";
  let sudoText = "";

  if (await commandExists("journalctl")) {
    // OpenSSH >= 9.8 divide el binario: el listener sigue siendo `sshd`, pero
    // TODOS los eventos de autenticación los registra `sshd-session` (y
    // `sshd-auth` en >= 9.9). Filtrar solo _COMM=sshd devuelve cero en esas
    // versiones. Varios _COMM= del mismo campo se combinan con OR; en OpenSSH
    // <9.8 los nombres extra no matchean nada, así que es retrocompatible.
    //
    // `-o short-iso` (NO `-o cat`): `cat` emite solo el MESSAGE, sin timestamp
    // ni el prefijo `sshd-session[PID]:`. Necesitamos ambos: el ISO para la
    // columna HORA (locale-independiente, sin el problema de "jul"/"Jul") y el
    // [PID] para deduplicar líneas redundantes del mismo intento/sesión.
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
    // Fallback: auth.log completo filtrado por proceso. El filtro temporal
    // fino no es viable con syslog clásico (sin año); el normalizador trata
    // el contenido como "reciente" — el log rota a diario en la mayoría de
    // distros, así que la aproximación es aceptable para una foto fija.
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

  // lastb (logins fallidos de cualquier tipo) suele requerir root: solo se
  // usa como fuente de fallidos si las anteriores no dieron nada, y su fallo
  // es un skip parcial silencioso.
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

/** Lee sshd y sudo en macOS con el log unificado. */
async function collectDarwin(windowHours, sources, partial) {
  let sshText = "";
  let sudoText = "";

  if (await commandExists("log")) {
    // OpenSSH >= 9.8 (macOS Sequoia+) delega cada conexión en el proceso
    // `sshd-session`: los "Accepted ..." se emiten ahí a nivel Info, así que
    // sin --info y sin ese proceso el predicado antiguo no veía nada.
    sshText = await tryExec(
      `log show --style syslog --info --predicate '(process == "sshd") OR (process == "sshd-session")' --last ${windowHours}h`,
      LOG_TIMEOUT_MS, "log(sshd)", partial
    );
    sudoText = await tryExec(
      `log show --style syslog --info --predicate 'process == "sudo"' --last ${windowHours}h`,
      LOG_TIMEOUT_MS, "log(sudo)", partial
    );
    // `su` es un proceso distinto de sudo: sus fallos se registran como
    // "BAD SU <user> to <target> on <tty>" a nivel Default.
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

// ── Windows: eventos 4624/4625/4672 vía PowerShell + Get-WinEvent ───────────

const PS_TIMEOUT_MS = 60000; // Get-WinEvent sobre el canal Security puede tardar

/** ConvertTo-Json devuelve objeto si hay 1 elemento y array si hay varios:
 *  normalizar SIEMPRE a array antes de iterar. */
function toArray(v) {
  return Array.isArray(v) ? v : v == null ? [] : [v];
}

/**
 * Script PowerShell que recoge, en una sola invocación, los eventos del canal
 * Security de las últimas `windowHours` horas y los emite como JSON compacto.
 *
 * Decisiones (ver memoria del TFG):
 *  - FilterHashtable con StartTime=(Get-Date).AddHours(-N), no XPath con fechas
 *    en texto: evita problemas de formato regional (locale) en las fechas.
 *  - TimeCreated se serializa con formato fijo yyyy-MM-dd HH:mm:ss por el mismo
 *    motivo (ConvertTo-Json en PS 5.1 emitiría "/Date(ms)/").
 *  - Las Properties de los eventos se leen por índice (posiciones estables por
 *    Id de evento desde Windows 7/Server 2008 R2):
 *      4624: 5=TargetUserName, 7=TargetLogonId, 8=LogonType, 18=IpAddress
 *      4625: 5=TargetUserName, 10=LogonType, 19=IpAddress
 *      4672: 1=SubjectUserName, 3=SubjectLogonId
 *  - 4672 no incluye IP: se correlaciona SubjectLogonId con el TargetLogonId
 *    de los 4624 para saber si la sesión privilegiada es remota (tipo 3/10).
 *  - Ese LogonId se EMITE al JSON (`logonId`), no solo se usa aquí dentro. Es
 *    el identificador exacto que permite atribuir un 4672 a su 4624 fuera de
 *    PowerShell, sin heurística, en lib/win-logons.js. Antes se calculaba y se
 *    tiraba, y el consumidor tenía que adivinar.
 *  - Cuentas de servicio (SYSTEM, LOCAL/NETWORK SERVICE, cuentas de máquina $)
 *    se excluyen: generan miles de 4624/4672 por hora y son ruido puro. La
 *    decisión vive en la función `Svc`, un solo sitio para los tres Ids.
 *    `sshd_<PID>` entra por PATRÓN, no por la lista literal: no es un usuario
 *    sino la cuenta de separación de privilegios que sshd crea POR CONEXIÓN,
 *    con el PID en el nombre, así que ninguna entrada fija puede casarla. Su
 *    4672 salía en el panel como «sesión admin de sshd_13048», y encima como
 *    local, que es como lo reporta Windows (el token lo crea sshd en la propia
 *    máquina) pero no es un acceso de nadie.
 *  - "No events found" NO significa "no pasó nada": sin permisos sobre el canal
 *    Security, Get-WinEvent devuelve NoMatchingEventsFound igual que si la
 *    ventana estuviera vacía, y NO lanza UnauthorizedAccessException. Medido en
 *    Windows con 5 eventos 4625 reales: como administrador salían los 5; sin
 *    elevar, "No se encontraron eventos que coincidan con los criterios".
 *    Por eso, ante NoMatchingEventsFound se SONDEA el canal antes de concluir
 *    nada (ver el bloque `$probeDenied`): si el canal está habilitado y tiene
 *    registros pero no devuelve ni uno, es permiso, no ausencia → denied=true.
 *    No se comprueba si el proceso es administrador: un usuario del grupo
 *    "Event Log Readers" lee el canal sin serlo, y suponerlo daría un falso
 *    "denegado".
 *  - Canal OpenSSH/Operational: legible SIN elevar, y sus mensajes los escribe
 *    OpenSSH (inglés siempre, sea cual sea el idioma de Windows), con el mismo
 *    formato que Linux/macOS. Se vuelca tal cual para parseSshdLines().
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
 * Parsea el JSON emitido por buildWinEventsScript → estructura `windows` del
 * resultado del módulo. Tolera objeto-en-vez-de-array (ConvertTo-Json).
 *
 * Tres cosas se resuelven aquí y no en el consumidor:
 *  - `logonId` se conserva tal cual (cadena tipo "0x3E7"): es la clave de
 *    correlación 4624↔4672 (ver lib/win-logons.js).
 *  - La IP pasa por normalizeWinIp(): Windows escribe el guion literal "-" en
 *    IpAddress cuando el logon no lleva dirección de red —lo que hace el 4624
 *    de tipo 3 que crea sshd—, y como "-" es truthy viajaba intacto hasta la
 *    columna ORIGEN del panel, que pintaba "-" donde el resto de celdas vacías
 *    pintan "—". Es null: ese evento no trae origen.
 *  - Las cuentas de servicio se vuelven a filtrar aquí. El filtro de verdad
 *    está en el script PowerShell (`Svc`), que las descarta en origen; este es
 *    la red de seguridad para datos recogidos por una versión anterior y, de
 *    paso, la única mitad de la regla que se puede probar sin Windows.
 */
function parseWinEventsJson(jsonText) {
  const data = JSON.parse(String(jsonText).trim());
  return {
    securityLogDenied: data.denied === true,
    // Líneas crudas del canal OpenSSH/Operational y, si no se pudo leer, el
    // nombre del tipo .NET de la excepción (no su mensaje: viene traducido).
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
 * Parsea la salida de `query user` → sesiones activas (misma forma que who).
 * Formato (cabecera en la primera línea, '>' marca la sesión propia):
 *   >admin    console     1  Active   none  07/07/2026 9:00
 *    bob      rdp-tcp#55  2  Active   .     07/07/2026 8:30
 *    carol                3  Disc     1+02:15  06/07/2026 22:00   (sin SESSIONNAME)
 * Columnas posicionales — las cabeceras cambian con el idioma del SO.
 */
function parseQueryUserLines(text) {
  const sessions = [];
  const lines = String(text || "").split("\n");
  for (const rawLine of lines.slice(1)) { // slice(1): salta la cabecera
    const line = rawLine.replace(/^[\s>]+/, " ").trim();
    if (!line) continue;
    const tokens = line.split(/\s+/);
    if (tokens.length < 4) continue;
    let tty, rest;
    if (/^\d+$/.test(tokens[1])) {
      // Sesión desconectada: sin SESSIONNAME, tokens = user, id, state, idle, fecha...
      tty = null;
      rest = tokens.slice(3);
    } else {
      tty = tokens[1];
      rest = tokens.slice(4);
    }
    sessions.push({
      user: tokens[0],
      tty,
      since: rest.slice(1).join(" ") || null, // rest[0] = idle time, el resto = logon time
      origin: tty && /^rdp-/i.test(tty) ? "RDP" : null,
    });
  }
  return sessions;
}

/**
 * Parsea la salida de `qwinsta` (fallback de query user).
 * Formato: SESSIONNAME  USERNAME  ID  STATE ... — solo interesan las filas
 * con usuario (2º token no numérico). No incluye hora de inicio de sesión.
 */
function parseQwinstaLines(text) {
  const sessions = [];
  const lines = String(text || "").split("\n");
  for (const rawLine of lines.slice(1)) {
    const line = rawLine.replace(/^[\s>]+/, " ").trim();
    if (!line) continue;
    const tokens = line.split(/\s+/);
    if (tokens.length < 3 || /^\d+$/.test(tokens[1])) continue; // fila sin usuario
    sessions.push({
      user: tokens[1],
      tty: tokens[0],
      since: null,
      origin: /^rdp-/i.test(tokens[0]) ? "RDP" : null,
    });
  }
  return sessions;
}

/**
 * Recolector win32: eventos del canal Security + sesiones activas.
 * Gate: powershell (o pwsh como fallback). El canal Security requiere
 * administrador: si Get-WinEvent devuelve acceso denegado se marca
 * securityLogDenied (finding info en el normalizador) sin romper — mismo
 * patrón que lastb/root en Linux.
 */
async function collectWin32(windowHours, sources, partial) {
  const windows = {
    securityLogDenied: false,
    logons: { remote: [], localCount: 0 },
    failed: [],
    privileged: [],
  };
  let sessions = [];
  // Misma estructura que Linux/macOS: el normalizador y el dashboard no
  // necesitan saber de qué plataforma vino.
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
    // ── Por qué un fichero temporal y no -EncodedCommand ────────────────────
    //
    // El script se pasaba con `-EncodedCommand <base64>`, o sea ENTERO dentro de
    // la línea de comandos, y Windows la limita a 8191 caracteres. La
    // codificación UTF-16LE + base64 multiplica el tamaño por ~2,67, así que el
    // margen real eran unos 3070 caracteres de script. Medido en Windows cuando
    // dejó de funcionar: script 3109 → base64 8292, o sea 101 de más. El script
    // había crecido (logonId en 4624/4672, la función Svc, el sondeo -ListLog y
    // la lectura de OpenSSH/Operational) y cruzó el umbral.
    //
    // El fallo fue del peor tipo: silencioso y TOTAL. Como los dos canales se
    // leen en una sola invocación, al no ejecutarse nada se perdían a la vez el
    // canal Security y el de OpenSSH, y no salía ni un evento SSH, ni elevado ni
    // sin elevar. Lo único que funcionó fue la degradación honesta: el nodo dijo
    // "fuentes de log no disponibles", no "sin eventos relevantes".
    //
    // Con -File el script no pasa por la línea de comandos y el límite deja de
    // aplicar. NO volver a -EncodedCommand ni a -Command: el guardarraíl está en
    // test/manual/test-security-events-win32.js.
    //
    // BOM de UTF-8: Windows PowerShell 5.1 lee un .ps1 SIN BOM con la página de
    // códigos ANSI del sistema, no como UTF-8. Hoy el script es ASCII puro y
    // daría igual, pero el día que alguien meta una tilde en un mensaje o en un
    // nombre de grupo localizado, sin BOM se convierte en mojibake dentro de una
    // cadena o de un patrón. Con BOM lo leen bien tanto 5.1 como PowerShell 7.
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
      // No se pudo ni crear el fichero (tmp lleno, sin permisos, ruta ocupada).
      // Misma regla que el resto: fuente no disponible, nunca un dato de auditoría.
      partial.push({
        source: "Get-WinEvent(Security)",
        reason: `no se pudo escribir el script temporal: ${err.message || err}`,
      });
    }
    if (out) {
      try {
        const parsed = parseWinEventsJson(out);

        // Canal OpenSSH/Operational: independiente del canal Security, se lea
        // este o no. Su ausencia es lo normal (Windows no trae OpenSSH Server
        // instalado por defecto): skip parcial, nunca un hallazgo.
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

  // C) Sesiones activas: query user, con qwinsta como fallback.
  //
  // Ambos pertenecen a las herramientas de Servicios de Escritorio Remoto y NO
  // vienen en Windows Home: `where.exe query` y `where.exe qwinsta` no
  // encuentran nada. Sin comprobarlo antes, la ejecución fallaba y el motivo
  // que llegaba al usuario era «Command failed: query user — 'query' no se
  // reconoce como un comando interno o externo», que suena a avería cuando lo
  // que pasa es que esa edición de Windows no trae la herramienta.
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

// ── Lista plana de eventos para el dashboard ────────────────────────────────

const MAX_EVENT_LIST = 200; // tope de eventos en payload.securityEvents.events

/** Convierte un timestamp de log a epoch ms para ordenar (0 si no parseable).
 *  Formatos: ISO "2026-07-02 10:15:30", syslog sin año "Jul  2 10:15:30",
 *  query user "07/07/2026 8:30". Solo se usa para ORDENAR: ts se muestra tal cual. */
function tsToEpoch(ts) {
  if (!ts) return 0;
  const s = String(ts).trim();
  let t = Date.parse(s.replace(" ", "T"));           // ISO con espacio
  if (!Number.isNaN(t)) return t;
  t = Date.parse(s);                                  // formatos que Date entiende
  if (!Number.isNaN(t)) return t;
  const syslog = s.match(/^([A-Z][a-z]{2})\s+(\d{1,2}) (\d{2}:\d{2}:\d{2})/);
  if (syslog) {
    // syslog clásico no lleva año → asumir el actual (foto fija de horas recientes)
    t = Date.parse(`${syslog[1]} ${syslog[2]} ${new Date().getFullYear()} ${syslog[3]}`);
    if (!Number.isNaN(t)) return t;
  }
  return 0;
}

/**
 * Aplana el resultado de runSecurityEvents a la forma que consume el dashboard:
 *   { windowHours, events: [{ ts, type, user, origin, detail }], truncated }
 * Eventos PARSEADOS (no log crudo), orden ts descendente, tope MAX_EVENT_LIST.
 * Con skipped devuelve events: [] (el finding informativo ya lo cubre).
 *
 * ── Windows: una fila por acceso, no una por fuente ─────────────────────────
 * Con Node-RED elevado se leen DOS canales que describen el mismo hecho, y sin
 * correlacionarlos un único login SSH producía cuatro filas: la de SSH, el 4624
 * remoto, el 4672 de esa sesión y el 4672 de la cuenta sshd_<PID>. La cuenta de
 * separación de privilegios ya no llega hasta aquí (la filtra el script y, por
 * si acaso, parseWinEventsJson); las otras tres se colapsan en una.
 *
 * Sobrevive la fila de SSH porque es la que más información trae: la IP de
 * origen REAL —el 4624 de sshd no la lleva— y el método de autenticación. Lo
 * único que aporta el 4672 absorbido es CON QUÉ CUENTA se entró, y eso no se
 * pierde: se anota en la propia fila superviviente, en `detail` (lo que lee la
 * persona) y en el campo `privileged` (lo que leen el chat con el LLM y
 * cualquier consumidor programático).
 *
 * Ojo con lo que significa el 4672: NO es "la sesión estaba elevada". Windows lo
 * emite al iniciar sesión cuando la CUENTA pertenece al grupo Administradores,
 * se ejecute algo con permisos elevados o no. Entrar por SSH con una cuenta
 * administradora lo dispara aunque no se eleve nada, así que el texto habla de
 * la cuenta, no de la sesión.
 *
 * La regla de correlación NO está aquí: vive en lib/win-logons.js y la comparte
 * con lib/normalizer.js, que tiene que tomar exactamente la misma decisión para
 * los findings. Dos copias de esta regla es el fallo que se estaba corrigiendo.
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

  // En Linux/macOS no hay segunda fuente y la correlación sale vacía: estos
  // bucles se comportan exactamente igual que antes.
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
    // `absorbed*`: ese evento del canal Security ya está contado en una fila de
    // SSH de arriba. Emitirlo otra vez sería la misma sesión pintada dos veces.
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
    // El dashboard lo necesita para no pintar "Sin sesiones remotas activas"
    // cuando lo cierto es que no se pudo consultar.
    sessionsChecked: result.sessionsChecked === true,
  };
}

// ── API pública ─────────────────────────────────────────────────────────────

/**
 * Recoge los eventos de seguridad de las últimas `windowHours` horas.
 * @param {number} [windowHours=24]  Ventana temporal (1–168).
 * @returns {Promise<Object>} datos crudos (ver cabecera del fichero)
 */
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
  // ¿Se llegó a consultar quién tiene sesión abierta? Una lista vacía no
  // significa "no hay nadie" si no se pudo preguntar.
  let sessionsChecked = false;

  if (platform === "win32") {
    ({ windows, sessions, ssh, sessionsChecked } = await collectWin32(hours, sources, partial));
  } else {
    ({ ssh, sudo } =
      platform === "linux"
        ? await collectLinux(hours, sources, partial)
        : await collectDarwin(hours, sources, partial));

    // C) Sesiones activas ahora — `who` existe en Linux y macOS
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

  // Ninguna fuente utilizable → skipped (patrón obligatorio del proyecto)
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
  // win32 — expuestos para tests unitarios
  parseWinEventsJson,
  parseQueryUserLines,
  parseQwinstaLines,
  buildWinEventsScript,
};
