"use strict";

/**
 * Ajustes con los que el launcher arranca Node-RED (`node-red --settings <este fichero>`).
 *
 * Carga el settings.js del usuario tal cual y solo añade tres cosas. El fichero del usuario no se
 * modifica: el mismo criterio que con el PATH, LoCoAudit no reescribe configuración ajena.
 *
 *  1. uiHost 127.0.0.1 si el usuario no ha elegido otro. Con el settings.js de fábrica Node-RED
 *     escucha en 0.0.0.0 y sin adminAuth: cualquier equipo de la red llegaba al editor.
 *
 *  2. Un guardián delante de toda la API. @node-red/editor-api monta `cors({ origin: "*" })` sin
 *     condiciones, así que escuchar solo en loopback no basta: cualquier web abierta en el
 *     navegador del usuario podía leer /flows y lanzar POST contra el editor (medido: GET /flows
 *     desde Origin ajeno, 200 con Access-Control-Allow-Origin: *). Se rechaza lo que traiga un
 *     Origin de otro sitio y, con escucha en loopback, lo que llegue con un Host que no sea
 *     loopback, que es la huella del DNS rebinding. Va en httpAdminMiddleware y también en
 *     httpNodeMiddleware: hoy httpAdminRoot es "/" y el primero ya cubre el dashboard y
 *     /locoaudit/chat, pero eso deja de ser cierto en cuanto alguien cambie esa raíz.
 *
 *  3. El mismo control de Host en el socket.io del dashboard, que no pasa por ningún middleware
 *     HTTP. El de fábrica (ui_base.js de @flowfuse/node-red-dashboard 1.31) solo comprueba que
 *     Origin y Host coincidan, y en un DNS rebinding coinciden: la web de rebinding podía pedir
 *     con widget-load el último informe de cada dashboard. Al definir ioMiddleware, el dashboard
 *     deja de montar el suyo, así que se reproduce aquí detrás del control de Host.
 *
 * El guardián no sustituye a adminAuth: el websocket /comms del editor no pasa por ningún
 * middleware configurable. Quien vaya a exponer Node-RED necesita adminAuth.
 */

const fs = require("fs");
const os = require("os");
const path = require("path");

const userDir = process.env.LCAUDIT_NODE_RED_DIR || path.join(os.homedir(), ".node-red");
const userSettingsFile = path.join(userDir, "settings.js");

// Sin settings.js propio (primer arranque) Node-RED tomaría flows_<hostname>.json; el launcher
// copia los flujos de demo a flows.json, así que ese es el que tiene que leer.
const base = fs.existsSync(userSettingsFile) ? require(userSettingsFile) : { flowFile: "flows.json" };

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "::1"]);
const uiHost = base.uiHost || "127.0.0.1";
const listensOnLoopback = LOOPBACK_HOSTS.has(uiHost);

/** "127.0.0.1:1880" → "127.0.0.1"; "[::1]:1880" → "::1". */
function hostnameOf(hostHeader) {
  const h = String(hostHeader || "").trim().toLowerCase();
  if (h.startsWith("[")) return h.slice(1, h.indexOf("]"));
  return h.replace(/:\d+$/, "");
}

function sameOriginOnly(req, res, next) {
  if (listensOnLoopback && !LOOPBACK_HOSTS.has(hostnameOf(req.headers.host))) {
    res.status(403).end();
    return;
  }
  const origin = req.headers.origin;
  if (origin !== undefined) {
    let originHost = null;
    try { originHost = new URL(origin).host.toLowerCase(); } catch (_) { /* "null" o basura */ }
    if (originHost !== String(req.headers.host || "").toLowerCase()) {
      res.status(403).end();
      return;
    }
  }
  next();
}

/** socket.io del dashboard: Host de loopback cuando se escucha en loopback. */
function dashboardHostOnly(socket, next) {
  const host = socket.request && socket.request.headers && socket.request.headers.host;
  if (listensOnLoopback && !LOOPBACK_HOSTS.has(hostnameOf(host))) {
    next(new Error("Host no permitido"));
    return;
  }
  next();
}

/** Copia del middleware por defecto del dashboard (ui_base.js), que deja de montarse en cuanto
 *  hay un ioMiddleware: sin websocket directo sin polling previo y solo mismo origen. */
function dashboardDefault(socket, next) {
  if (socket.client.conn.request.url.indexOf("transport=websocket") !== -1) {
    socket.client.conn.close();
    return;
  }
  if (socket.handshake.xdomain === false) return next();
  socket.disconnect(true);
}

const asList = (v) => (v ? (Array.isArray(v) ? v : [v]) : []);

// Si el usuario ya tenía su propio middleware, va detrás del guardián, no se pierde.
const ownAdmin = asList(base.httpAdminMiddleware);
const ownNode = asList(base.httpNodeMiddleware);

// El dashboard lee base.dashboard, o base.ui en versiones antiguas. Un ioMiddleware propio
// sustituye al de fábrica, como haría el dashboard sin LoCoAudit.
const baseDashboard = base.dashboard || base.ui || {};
const ownIo = asList(baseDashboard.ioMiddleware);

module.exports = Object.assign({}, base, {
  uiHost,
  httpAdminMiddleware: [sameOriginOnly, ...ownAdmin],
  httpNodeMiddleware: [sameOriginOnly, ...ownNode],
  dashboard: Object.assign({}, baseDashboard, {
    ioMiddleware: [dashboardHostOnly, ...(ownIo.length ? ownIo : [dashboardDefault])],
  }),
});
