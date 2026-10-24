"use strict";

/** Correlación de logons de Windows entre OpenSSH/Operational y Security (4624/4625/4672), para que un acceso
 *  no salga repetido. 4624↔4672 por LogonId; SSH↔4624/4625 por usuario + IP (si ambas la traen) + ventana de 10 s. */

// Ventana de tolerancia entre las dos fuentes.
const CORRELATION_WINDOW_MS = 10000;

/** Cuentas de servicio: generan miles de logons que no son de nadie. Copia de la lista $svc del script PowerShell. */
const SERVICE_ACCOUNTS = new Set([
  "SYSTEM",
  "LOCAL SERVICE",
  "NETWORK SERVICE",
  "ANONYMOUS LOGON",
  "SERVICIO LOCAL",
  "SERVICIO DE RED",
]);

// `sshd_<PID>` es la cuenta de separación de privilegios que sshd crea por conexión, no un usuario.
const SERVICE_ACCOUNT_PATTERNS = [/^sshd_\d+$/i];

/** ¿Es una cuenta de servicio o de máquina, y por tanto ruido y no un acceso? */
function isServiceAccount(user) {
  const u = String(user == null ? "" : user).trim();
  if (!u) return false;
  if (u.endsWith("$")) return true;                       // cuenta de máquina
  if (SERVICE_ACCOUNTS.has(u.toUpperCase())) return true;
  return SERVICE_ACCOUNT_PATTERNS.some((re) => re.test(u));
}

/** IP del canal Security, o null. Windows escribe "-" cuando el logon no trae dirección. */
function normalizeWinIp(ip) {
  const s = String(ip == null ? "" : ip).trim();
  if (!s || s === "-") return null;
  return s;
}

/** Compara IPs tolerando la forma IPv4-mapeada en IPv6 (::ffff:192.168.0.25). */
function sameIp(a, b) {
  const norm = (v) => String(v || "").trim().toLowerCase().replace(/^::ffff:/, "");
  return norm(a) === norm(b);
}

/** Nombres de cuenta de Windows: no distinguen mayúsculas. */
function sameUser(a, b) {
  const ua = String(a == null ? "" : a).trim().toLowerCase();
  const ub = String(b == null ? "" : b).trim().toLowerCase();
  return ua !== "" && ua === ub;
}

/** Epoch en ms de un `yyyy-MM-dd HH:mm:ss`. Se lee como UTC porque solo se restan horas de la misma máquina.
 *  Devuelve null, nunca 0: un 0 colaría correlaciones falsas. */
const WIN_TS_RE = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})/;
function winTsToEpoch(ts) {
  const m = WIN_TS_RE.exec(String(ts == null ? "" : ts).trim());
  if (!m) return null;
  return Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
}

function asArray(v) {
  return Array.isArray(v) ? v : [];
}

/** ¿El evento SSH y el del canal Security son el mismo acceso? */
function describesSameAccess(sshEvent, winEvent) {
  if (!sameUser(sshEvent.user, winEvent.user)) return false;

  const sshIp = normalizeWinIp(sshEvent.ip);
  const winIp = normalizeWinIp(winEvent.ip);
  if (sshIp && winIp && !sameIp(sshIp, winIp)) return false;

  const tSsh = winTsToEpoch(sshEvent.timestamp);
  const tWin = winTsToEpoch(winEvent.timestamp);
  if (tSsh == null || tWin == null) {
    // Sin hora hace falta la prueba fuerte: mejor una fila de más que juntar dos accesos reales.
    return Boolean(sshIp && winIp && sameIp(sshIp, winIp));
  }
  return Math.abs(tSsh - tWin) <= CORRELATION_WINDOW_MS;
}

/** Empareja cada evento SSH con un evento de Security como mucho: gana el más cercano en el
 *  tiempo, y sin hora el primero libre. Cada evento de Security se absorbe una sola vez. */
function pairUp(sshEvents, winEvents, absorbed, matchOut) {
  for (const sshEvent of sshEvents) {
    let bestIdx = -1;
    let bestDelta = Infinity;
    for (const [i, winEvent] of winEvents.entries()) {
      if (absorbed.has(i)) continue;
      if (!describesSameAccess(sshEvent, winEvent)) continue;
      const tSsh = winTsToEpoch(sshEvent.timestamp);
      const tWin = winTsToEpoch(winEvent.timestamp);
      const delta = tSsh == null || tWin == null ? Infinity : Math.abs(tSsh - tWin);
      if (delta < bestDelta || bestIdx === -1) {
        bestIdx = i;
        bestDelta = delta;
      }
    }
    if (bestIdx === -1) continue;
    absorbed.add(bestIdx);
    if (matchOut) matchOut.set(sshEvent, winEvents[bestIdx]);
  }
}

/** ¿Este 4672 es de la sesión de este 4624? Por LogonId; si falta, por usuario y ventana. */
function belongsToLogon(priv, logon) {
  const pid = String(priv.logonId || "").trim();
  const lid = String(logon.logonId || "").trim();
  if (pid && lid) return pid === lid;

  if (!sameUser(priv.user, logon.user)) return false;
  const tPriv = winTsToEpoch(priv.timestamp);
  const tLogon = winTsToEpoch(logon.timestamp);
  if (tPriv == null || tLogon == null) return false;
  return Math.abs(tPriv - tLogon) <= CORRELATION_WINDOW_MS;
}

/** Correlaciona las dos fuentes sin tocar `raw`: qué eventos de Security ya cubre una fila SSH y sus 4672. */
function correlateWindowsLogons(raw) {
  const correlation = {
    absorbedRemote: new Set(),
    absorbedFailed: new Set(),
    absorbedPriv: new Set(),
    _privBySsh: new Map(),
    privilegedFor(sshEvent) {
      return this._privBySsh.get(sshEvent) || [];
    },
    hasPrivilege(sshEvent) {
      return this.privilegedFor(sshEvent).length > 0;
    },
  };

  const win = raw && raw.windows;
  if (!win) return correlation;   // Linux/macOS: no hay segunda fuente, nada que hacer

  const ssh = (raw && raw.ssh) || { accepted: [], failed: [] };
  const remote = asArray(win.logons && win.logons.remote);
  const failed = asArray(win.failed);
  const privileged = asArray(win.privileged);

  // Acceso SSH correcto ↔ 4624 remoto (tipo 3/10).
  const logonBySsh = new Map();
  pairUp(asArray(ssh.accepted), remote, correlation.absorbedRemote, logonBySsh);

  // Intento SSH fallido ↔ 4625.
  pairUp(asArray(ssh.failed), failed, correlation.absorbedFailed, null);

  // El 4672 se cuelga del 4624 ya emparejado: es la misma sesión, no otro acceso.
  for (const [sshEvent, logon] of logonBySsh) {
    for (const [i, priv] of privileged.entries()) {
      if (correlation.absorbedPriv.has(i)) continue;
      if (!belongsToLogon(priv, logon)) continue;
      correlation.absorbedPriv.add(i);
      const list = correlation._privBySsh.get(sshEvent) || [];
      list.push(priv);
      correlation._privBySsh.set(sshEvent, list);
    }
  }

  return correlation;
}

module.exports = {
  CORRELATION_WINDOW_MS,
  isServiceAccount,
  normalizeWinIp,
  correlateWindowsLogons,
  // Exportados para los tests: son la parte con reglas, no detalles de formato.
  describesSameAccess,
  belongsToLogon,
  winTsToEpoch,
};
