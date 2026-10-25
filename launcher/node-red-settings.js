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
let base;
if (fs.existsSync(userSettingsFile)) {
  base = require(userSettingsFile);
} else {
  base = { flowFile: "flows.json" };
}

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "::1"]);
const uiHost = base.uiHost || "127.0.0.1";
const listensOnLoopback = LOOPBACK_HOSTS.has(uiHost);

/** "127.0.0.1:1880" → "127.0.0.1"; "[::1]:1880" → "::1". */
function nombreDeHost(hostHeader) {
  const h = String(hostHeader || "").trim().toLowerCase();
  if (h.startsWith("[")) return h.slice(1, h.indexOf("]"));
  return h.replace(/:\d+$/, "");
}

function soloMismoOrigen(req, res, next) {
  if (listensOnLoopback && !LOOPBACK_HOSTS.has(nombreDeHost(req.headers.host))) {
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
function soloHostDelDashboard(socket, next) {
  const host = socket.request && socket.request.headers && socket.request.headers.host;
  if (listensOnLoopback && !LOOPBACK_HOSTS.has(nombreDeHost(host))) {
    next(new Error("Host no permitido"));
    return;
  }
  next();
}

/** Copia del middleware de fábrica del dashboard, que deja de montarse al definir ioMiddleware. */
function middlewareDeFabrica(socket, next) {
  if (socket.client.conn.request.url.indexOf("transport=websocket") !== -1) {
    socket.client.conn.close();
    return;
  }
  if (socket.handshake.xdomain === false) return next();
  socket.disconnect(true);
}

function comoLista(v) {
  if (!v) {
    return [];
  } else if (Array.isArray(v)) {
    return v;
  } else {
    return [v];
  }
}

// Los middlewares del usuario van detrás del guardián.
const ownAdmin = comoLista(base.httpAdminMiddleware);
const ownNode = comoLista(base.httpNodeMiddleware);

// El dashboard lee base.dashboard (o base.ui). Un ioMiddleware del usuario sustituye al de fábrica.
const baseDashboard = base.dashboard || base.ui || {};
const ownIo = comoLista(baseDashboard.ioMiddleware);
let ioDelUsuario;
if (ownIo.length) {
  ioDelUsuario = ownIo;
} else {
  ioDelUsuario = [middlewareDeFabrica];
}

module.exports = Object.assign({}, base, {
  uiHost,
  httpAdminMiddleware: [soloMismoOrigen, ...ownAdmin],
  httpNodeMiddleware: [soloMismoOrigen, ...ownNode],
  dashboard: Object.assign({}, baseDashboard, {
    ioMiddleware: [soloHostDelDashboard, ...ioDelUsuario],
  }),
});
