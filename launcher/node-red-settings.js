"use strict";

/**
 * Ajustes con los que el launcher arranca Node-RED (`node-red --settings <este fichero>`).
 *
 * Carga el settings.js del usuario tal cual y solo añade dos cosas. El fichero del usuario no se
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
 *     loopback, que es la huella del DNS rebinding.
 *
 * El guardián no sustituye a adminAuth: los websockets (comunicaciones del editor, socket.io del
 * dashboard) no pasan por httpAdminMiddleware. Quien vaya a exponer Node-RED necesita adminAuth.
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

// Si el usuario ya tenía su propio middleware, va detrás del guardián, no se pierde.
const own = base.httpAdminMiddleware;
const ownList = own ? (Array.isArray(own) ? own : [own]) : [];

module.exports = Object.assign({}, base, {
  uiHost,
  httpAdminMiddleware: [sameOriginOnly, ...ownList],
});
