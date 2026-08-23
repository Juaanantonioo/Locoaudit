"use strict";

/**
 * win-logons.js — Correlación y filtrado de los eventos de logon de Windows.
 *
 * FUENTE ÚNICA de la correlación entre las dos fuentes que describen el MISMO
 * acceso en Windows:
 *
 *   - canal OpenSSH/Operational  → `raw.ssh.accepted` / `raw.ssh.failed`
 *   - canal Security (4624/4625/4672) → `raw.windows.logons.remote`,
 *     `raw.windows.failed`, `raw.windows.privileged`
 *
 * Con Node-RED sin elevar solo se lee el primero y no hay nada que correlacionar.
 * Con Node-RED elevado se leen los dos, y un ÚNICO login SSH producía cuatro
 * filas en el panel y tres findings (uno de sshFindings, HOST-SEC-WIN-RDP-001 y
 * HOST-SEC-WIN-PRIV-001, este último de severidad ALTA). Medido en Windows:
 *
 *   18:51:07  SSH OK        inesg        192.168.0.25   (OpenSSH/Operational)
 *   18:51:02  LOGIN REMOTO  inesg        -              (4624 tipo 3)
 *   18:51:02  ADMIN remota  inesg        -              (4672)
 *   18:51:01  ADMIN local   sshd_13048   -              (4672 de la cuenta privsep)
 *
 * Este módulo vive en lib/ y NO en el submódulo del nodo a propósito: lo
 * consumen los dos caminos —la lista de eventos del panel
 * (nodes/audit-host/modules/security-events.js: buildEventList) y los findings
 * (lib/normalizer.js: fromSecurityEvents)— y dos implementaciones de la misma
 * regla es exactamente el fallo que se está corrigiendo.
 *
 * ── Claves de correlación ───────────────────────────────────────────────────
 *
 * 4624 ↔ 4672: EXACTA, por LogonId. El TargetLogonId del 4624 y el
 * SubjectLogonId del 4672 ya se leían en PowerShell (para decidir si la sesión
 * privilegiada era remota) pero no se emitían al JSON. Ahora sí, así que aquí
 * no hay heurística ninguna.
 *
 * SSH ↔ 4624/4625: NO hay identificador común. sshd no publica el LogonId en
 * OpenSSH/Operational, ni el 4624 trae el puerto de origen de la conexión SSH.
 * La clave es `usuario + IP + ventana temporal`, con estas tres reglas:
 *
 *   - Usuario: obligatorio, comparado sin distinguir mayúsculas (los nombres de
 *     cuenta de Windows no las distinguen).
 *   - IP: si las dos fuentes la traen, tiene que coincidir (normalizando el
 *     prefijo IPv4-mapeada ::ffff:). Si el 4624 NO la trae, no se exige: es el
 *     caso normal con sshd, que crea el logon sin dirección de red y Windows
 *     escribe "-" en IpAddress.
 *   - Tiempo: 10 s. Los timestamps NO coinciden y no pueden coincidir — el
 *     4624/4672 marca la creación del token y el evento de OpenSSH el momento
 *     en que sshd escribe en su canal, después de la sesión PAM/perfil. En la
 *     medición real el reparto fue :01 / :02 / :07, o sea 6 s entre extremos:
 *     una ventana de 5 s habría fallado sobre datos reales. 10 s deja margen
 *     para un equipo cargado sin llegar a solapar dos accesos distintos del
 *     mismo usuario desde la misma IP, que a esa distancia son indistinguibles
 *     por cualquier criterio.
 *
 * Si a alguno de los dos lados le falta la hora, la ventana no se puede aplicar
 * y se exige entonces que AMBAS IPs existan y coincidan: sin hora ni IP, el
 * usuario solo no basta para afirmar que son el mismo hecho, y ante la duda se
 * prefiere una fila de más (ruido) a colapsar dos accesos reales en uno
 * (pérdida de señal). Ver CLAUDE.md, "Fallo de la herramienta ≠ dato negativo":
 * el falso "todo bien" es el único peligroso.
 *
 * Exporta:
 *   CORRELATION_WINDOW_MS
 *   isServiceAccount(user)        → boolean
 *   normalizeWinIp(ip)            → string|null   ("-" y "" → null)
 *   correlateWindowsLogons(raw)   → Correlation
 *
 * Correlation = {
 *   absorbedRemote: Set<number>,  // índices de windows.logons.remote ya contados por SSH
 *   absorbedFailed: Set<number>,  // ídem windows.failed (4625)
 *   absorbedPriv:   Set<number>,  // ídem windows.privileged (4672)
 *   privilegedFor(sshEvent) → Array<priv>,   // 4672 de ESE acceso SSH
 *   hasPrivilege(sshEvent)  → boolean,
 * }
 */

/** Ventana de tolerancia entre las dos fuentes. Ver cabecera para el porqué. */
const CORRELATION_WINDOW_MS = 10000;

/**
 * Cuentas de servicio: generan miles de 4624/4672 por hora y no son accesos de
 * nadie. Espejo exacto de la lista `$svc` del script PowerShell
 * (nodes/audit-host/modules/security-events.js), que es quien filtra en origen.
 * Aquí se repite como red de seguridad para lo que llegue ya recogido —datos de
 * una ejecución anterior, un Windows con otros nombres localizados— y porque es
 * la única de las dos que se puede probar sin una máquina Windows delante.
 */
const SERVICE_ACCOUNTS = new Set([
  "SYSTEM",
  "LOCAL SERVICE",
  "NETWORK SERVICE",
  "ANONYMOUS LOGON",
  "SERVICIO LOCAL",
  "SERVICIO DE RED",
]);

/**
 * Patrones de cuenta de servicio. `sshd_<PID>` NO es un usuario: es la cuenta
 * de separación de privilegios que sshd crea por conexión, con el PID en el
 * nombre. Por eso hace falta un patrón y no una entrada literal en la lista.
 * Windows la reporta con un 4672 propio de sesión LOCAL, que es correcto desde
 * su punto de vista (el token lo crea sshd en la máquina), pero en el panel se
 * leía como "un administrador llamado sshd_13048 entró en el equipo".
 */
const SERVICE_ACCOUNT_PATTERNS = [/^sshd_\d+$/i];

/** ¿Es una cuenta de servicio o de máquina, y por tanto ruido y no un acceso? */
function isServiceAccount(user) {
  const u = String(user == null ? "" : user).trim();
  if (!u) return false;
  if (u.endsWith("$")) return true;                       // cuenta de máquina
  if (SERVICE_ACCOUNTS.has(u.toUpperCase())) return true;
  return SERVICE_ACCOUNT_PATTERNS.some((re) => re.test(u));
}

/**
 * Normaliza una IP del canal Security.
 *
 * Windows escribe el guion literal "-" en IpAddress cuando el logon no lleva
 * dirección de red (es lo que hace el 4624 de tipo 3 que crea sshd). Como "-"
 * es truthy, viajaba intacto hasta la tabla y la columna ORIGEN pintaba "-"
 * mientras el resto de celdas vacías pintaban "—". Aquí se convierte en null,
 * que es lo que significa: "este evento no trae origen".
 */
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

/**
 * Epoch en ms de un timestamp `yyyy-MM-dd HH:mm:ss`.
 *
 * Es el ÚNICO formato que se maneja en la rama Windows: el script PowerShell lo
 * fija con ToString('yyyy-MM-dd HH:mm:ss') tanto para los eventos del canal
 * Security como para el prefijo que antepone a cada línea de OpenSSH, así que
 * las dos fuentes llegan aquí con la misma forma y no hay locale de por medio.
 * Se interpreta como UTC a propósito: los dos valores son hora local de la MISMA
 * máquina y aquí solo se usan diferencias, así que el desfase se cancela y de
 * paso no hay saltos por cambio de hora.
 *
 * @returns {number|null} null si no se puede interpretar (nunca 0: un 0 se
 *          confundiría con una hora válida y colaría correlaciones falsas).
 */
const WIN_TS_RE = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})/;
function winTsToEpoch(ts) {
  const m = WIN_TS_RE.exec(String(ts == null ? "" : ts).trim());
  if (!m) return null;
  return Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
}

function asArray(v) {
  return Array.isArray(v) ? v : [];
}

/**
 * ¿El evento SSH y el evento del canal Security describen el mismo acceso?
 * Reglas y motivos en la cabecera del fichero.
 */
function describesSameAccess(sshEvent, winEvent) {
  if (!sameUser(sshEvent.user, winEvent.user)) return false;

  const sshIp = normalizeWinIp(sshEvent.ip);
  const winIp = normalizeWinIp(winEvent.ip);
  if (sshIp && winIp && !sameIp(sshIp, winIp)) return false;

  const tSsh = winTsToEpoch(sshEvent.timestamp);
  const tWin = winTsToEpoch(winEvent.timestamp);
  if (tSsh == null || tWin == null) {
    // Sin ventana aplicable: hace falta la prueba fuerte, dos IPs iguales.
    return Boolean(sshIp && winIp && sameIp(sshIp, winIp));
  }
  return Math.abs(tSsh - tWin) <= CORRELATION_WINDOW_MS;
}

/**
 * Empareja cada evento SSH con, como mucho, UN evento del canal Security.
 * Entre varios candidatos gana el más cercano en el tiempo; sin hora, el
 * primero libre. Cada evento de Security se absorbe una sola vez.
 */
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

/**
 * ¿Este 4672 pertenece a la sesión de este 4624?
 * Vía preferente y exacta: LogonId. El respaldo por usuario+ventana solo actúa
 * si a alguno de los dos le falta el LogonId (datos recogidos por una versión
 * anterior del script, que no lo emitía).
 */
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

/**
 * Correlaciona las dos fuentes de un mismo resultado de runSecurityEvents.
 * No modifica `raw`: devuelve qué índices del canal Security ya están contados
 * por una fila/finding de SSH, y qué 4672 corresponden a cada acceso SSH.
 *
 * @param {Object} raw  resultado de runSecurityEvents (cualquier plataforma)
 * @returns {Object} Correlation (ver cabecera)
 */
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

  // 1) Acceso SSH correcto ↔ 4624 remoto (tipo 3/10).
  const logonBySsh = new Map();
  pairUp(asArray(ssh.accepted), remote, correlation.absorbedRemote, logonBySsh);

  // 2) Intento SSH fallido ↔ 4625.
  pairUp(asArray(ssh.failed), failed, correlation.absorbedFailed, null);

  // 3) 4672 ↔ el 4624 que ya absorbió una fila de SSH: el privilegio pertenece
  //    a esa misma sesión, así que se cuelga de ella en vez de salir aparte.
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
