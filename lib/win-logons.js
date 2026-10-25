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
function esCuentaDeServicio(user) {
  let texto;
  if (user == null) {
    texto = "";
  } else {
    texto = user;
  }
  const u = String(texto).trim();
  if (!u) return false;
  if (u.endsWith("$")) return true;                       // cuenta de máquina
  if (SERVICE_ACCOUNTS.has(u.toUpperCase())) return true;
  return SERVICE_ACCOUNT_PATTERNS.some((re) => re.test(u));
}

/** IP del canal Security, o null. Windows escribe "-" cuando el logon no trae dirección. */
function normalizarIpWindows(ip) {
  let texto;
  if (ip == null) {
    texto = "";
  } else {
    texto = ip;
  }
  const s = String(texto).trim();
  if (!s || s === "-") return null;
  return s;
}

/** Compara IPs tolerando la forma IPv4-mapeada en IPv6 (::ffff:192.168.0.25). */
function mismaIp(a, b) {
  const normalizar = (v) => String(v || "").trim().toLowerCase().replace(/^::ffff:/, "");
  return normalizar(a) === normalizar(b);
}

/** Nombres de cuenta de Windows: no distinguen mayúsculas. */
function mismoUsuario(a, b) {
  let textoA;
  if (a == null) {
    textoA = "";
  } else {
    textoA = a;
  }
  const ua = String(textoA).trim().toLowerCase();
  let textoB;
  if (b == null) {
    textoB = "";
  } else {
    textoB = b;
  }
  const ub = String(textoB).trim().toLowerCase();
  return ua !== "" && ua === ub;
}

/** Epoch en ms de un `yyyy-MM-dd HH:mm:ss`. Se lee como UTC porque solo se restan horas de la misma máquina.
 *  Devuelve null, nunca 0: un 0 colaría correlaciones falsas. */
const WIN_TS_RE = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})/;
function fechaWindowsAEpoch(ts) {
  let texto;
  if (ts == null) {
    texto = "";
  } else {
    texto = ts;
  }
  const m = WIN_TS_RE.exec(String(texto).trim());
  if (!m) return null;
  return Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
}

function comoLista(v) {
  if (Array.isArray(v)) {
    return v;
  } else {
    return [];
  }
}

/** ¿El evento SSH y el del canal Security son el mismo acceso? */
function mismoAcceso(sshEvent, winEvent) {
  if (!mismoUsuario(sshEvent.user, winEvent.user)) return false;

  const sshIp = normalizarIpWindows(sshEvent.ip);
  const winIp = normalizarIpWindows(winEvent.ip);
  if (sshIp && winIp && !mismaIp(sshIp, winIp)) return false;

  const tSsh = fechaWindowsAEpoch(sshEvent.timestamp);
  const tWin = fechaWindowsAEpoch(winEvent.timestamp);
  if (tSsh == null || tWin == null) {
    // Sin hora hace falta la prueba fuerte: mejor una fila de más que juntar dos accesos reales.
    return Boolean(sshIp && winIp && mismaIp(sshIp, winIp));
  }
  return Math.abs(tSsh - tWin) <= CORRELATION_WINDOW_MS;
}

/** Empareja cada evento SSH con un evento de Security como mucho: gana el más cercano en el
 *  tiempo, y sin hora el primero libre. Cada evento de Security se absorbe una sola vez. */
function emparejar(sshEvents, winEvents, absorbed, matchOut) {
  for (const sshEvent of sshEvents) {
    let bestIdx = -1;
    let bestDelta = Infinity;
    for (const [i, winEvent] of winEvents.entries()) {
      if (absorbed.has(i)) continue;
      if (!mismoAcceso(sshEvent, winEvent)) continue;
      const tSsh = fechaWindowsAEpoch(sshEvent.timestamp);
      const tWin = fechaWindowsAEpoch(winEvent.timestamp);
      let delta;
      if (tSsh == null || tWin == null) {
        delta = Infinity;
      } else {
        delta = Math.abs(tSsh - tWin);
      }
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
function perteneceAlInicio(priv, logon) {
  const pid = String(priv.logonId || "").trim();
  const lid = String(logon.logonId || "").trim();
  if (pid && lid) return pid === lid;

  if (!mismoUsuario(priv.user, logon.user)) return false;
  const tPriv = fechaWindowsAEpoch(priv.timestamp);
  const tLogon = fechaWindowsAEpoch(logon.timestamp);
  if (tPriv == null || tLogon == null) return false;
  return Math.abs(tPriv - tLogon) <= CORRELATION_WINDOW_MS;
}

/** Correlaciona las dos fuentes sin tocar `raw`: qué eventos de Security ya cubre una fila SSH y sus 4672. */
function correlacionarInicios(raw) {
  const correlation = {
    absorbedRemote: new Set(),
    absorbedFailed: new Set(),
    absorbedPriv: new Set(),
    _privBySsh: new Map(),
    privilegiosDe(sshEvent) {
      return this._privBySsh.get(sshEvent) || [];
    },
    tienePrivilegio(sshEvent) {
      return this.privilegiosDe(sshEvent).length > 0;
    },
  };

  const win = raw && raw.windows;
  if (!win) return correlation;   // Linux/macOS: no hay segunda fuente, nada que hacer

  const ssh = (raw && raw.ssh) || { accepted: [], failed: [] };
  const remote = comoLista(win.logons && win.logons.remote);
  const failed = comoLista(win.failed);
  const privileged = comoLista(win.privileged);

  // Acceso SSH correcto ↔ 4624 remoto (tipo 3/10).
  const logonBySsh = new Map();
  emparejar(comoLista(ssh.accepted), remote, correlation.absorbedRemote, logonBySsh);

  // Intento SSH fallido ↔ 4625.
  emparejar(comoLista(ssh.failed), failed, correlation.absorbedFailed, null);

  // El 4672 se cuelga del 4624 ya emparejado: es la misma sesión, no otro acceso.
  for (const [sshEvent, logon] of logonBySsh) {
    for (const [i, priv] of privileged.entries()) {
      if (correlation.absorbedPriv.has(i)) continue;
      if (!perteneceAlInicio(priv, logon)) continue;
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
  esCuentaDeServicio,
  normalizarIpWindows,
  correlacionarInicios,
  // Exportados para los tests: son la parte con reglas, no detalles de formato.
  mismoAcceso,
  perteneceAlInicio,
  fechaWindowsAEpoch,
};
