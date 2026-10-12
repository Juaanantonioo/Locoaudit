"use strict";

/**
 * Ajustes con los que el launcher arranca Node-RED (`node-red --settings <este fichero>`).
 * Carga el settings.js del usuario sin modificarlo y añade:
 *  1. uiHost 127.0.0.1 si el usuario no eligió otro.
 *  2. Un guardián de Origin y Host (CORS abierto y DNS rebinding) en httpAdminMiddleware y httpNodeMiddleware.
 *  3. El mismo control de Host en el socket.io del dashboard (ioMiddleware).
 * No sustituye a adminAuth: el websocket /comms del editor no pasa por ningún middleware.
 */

const fs = require("fs");
const os = require("os");
const path = require("path");

const userDir = process.env.LCAUDIT_NODE_RED_DIR || path.join(os.homedir(), ".node-red");
const userSettingsFile = path.join(userDir, "settings.js");

// Sin settings.js propio Node-RED leería flows_<hostname>.json, y el launcher copia flows.json.
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

/** Copia del middleware de fábrica del dashboard, que deja de montarse al definir ioMiddleware. */
function dashboardDefault(socket, next) {
  if (socket.client.conn.request.url.indexOf("transport=websocket") !== -1) {
    socket.client.conn.close();
    return;
  }
  if (socket.handshake.xdomain === false) return next();
  socket.disconnect(true);
}

const asList = (v) => (v ? (Array.isArray(v) ? v : [v]) : []);

// Los middlewares del usuario van detrás del guardián.
const ownAdmin = asList(base.httpAdminMiddleware);
const ownNode = asList(base.httpNodeMiddleware);

// El dashboard lee base.dashboard (o base.ui). Un ioMiddleware del usuario sustituye al de fábrica.
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
