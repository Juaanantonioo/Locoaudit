"use strict";

/**
 * test-node-red-guard.js: ajustes con los que el launcher arranca Node-RED.
 * Comprueba uiHost en loopback, el guardián de Origin y Host (httpAdmin y httpNode),
 * el middleware del socket.io del dashboard y que se respete el settings.js del usuario.
 * Uso: node test/manual/test-node-red-guard.js
 */

const fs   = require("fs");
const os   = require("os");
const path = require("path");

let failed = 0, passed = 0;
function ok(cond, label, detail) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}`); if (detail) console.log(`      ${detail}`); }
}

const SETTINGS = path.resolve(__dirname, "../../launcher/node-red-settings.js");
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "lcaudit-test-guard-"));

/** Carga los ajustes con un userDir propio; cada carga es limpia. */
function load(userDir) {
  process.env.LCAUDIT_NODE_RED_DIR = userDir;
  for (const k of Object.keys(require.cache)) {
    if (k === SETTINGS || k.startsWith(tmp)) delete require.cache[k];
  }
  return require(SETTINGS);
}

/** Pasa una petición falsa por la cadena de middlewares y devuelve el código, o "next". */
function run(chain, headers) {
  let status = "next";
  const res = { status(c) { status = c; return this; }, end() {} };
  for (const mw of chain) {
    let called = false;
    mw({ headers }, res, () => { called = true; });
    if (!called) return status;
  }
  return status;
}

// ── 1 · sin settings.js ─────────────────────────────────────────────────────────────────────
console.log("\n── 1 · Sin settings.js del usuario ───────────────────────────────\n");
const vacio = path.join(tmp, "vacio");
fs.mkdirSync(vacio);
const s1 = load(vacio);
ok(s1.uiHost === "127.0.0.1", "escucha en 127.0.0.1", s1.uiHost);
ok(s1.flowFile === "flows.json", "lee flows.json, el que copia el launcher", s1.flowFile);
ok(Array.isArray(s1.httpAdminMiddleware) && s1.httpAdminMiddleware.length === 1, "un middleware: el guardián");

// ── 2 · el guardián ─────────────────────────────────────────────────────────────────────────
console.log("\n── 2 · Qué deja pasar el guardián ────────────────────────────────\n");
const chain = s1.httpAdminMiddleware;
const H = "127.0.0.1:1880";
const CASOS = [
  ["navegación normal, sin Origin",           { host: H },                                        "next"],
  ["petición del propio editor",              { host: H, origin: "http://127.0.0.1:1880" },       "next"],
  ["localhost",                               { host: "localhost:1880", origin: "http://localhost:1880" }, "next"],
  ["IPv6 loopback",                           { host: "[::1]:1880" },                             "next"],
  ["web ajena (CSRF / lectura cross-origin)", { host: H, origin: "http://evil.example" },          403],
  ["mismo host, otro puerto",                 { host: H, origin: "http://127.0.0.1:8080" },       403],
  ["Origin null (iframe sandbox)",            { host: H, origin: "null" },                        403],
  ["Origin malformado",                       { host: H, origin: "::::" },                        403],
  ["DNS rebinding, sin Origin",               { host: "rebind.evil.example:1880" },               403],
  ["DNS rebinding con Origin coherente",      { host: "rebind.evil.example:1880", origin: "http://rebind.evil.example:1880" }, 403],
  ["Host que solo empieza por 127.0.0.1",     { host: "127.0.0.1.evil.example:1880" },            403],
  ["sin cabecera Host",                       {},                                                 403],
];
for (const [label, headers, esperado] of CASOS) {
  const r = run(chain, headers);
  ok(r === esperado, `${label} → ${esperado === "next" ? "pasa" : esperado}`, `obtenido: ${r}`);
}

ok(Array.isArray(s1.httpNodeMiddleware) && s1.httpNodeMiddleware[0] === chain[0],
   "el mismo guardián protege httpNode (dashboard y /locoaudit/chat)");
for (const [label, headers, esperado] of CASOS) {
  const r = run(s1.httpNodeMiddleware, headers);
  if (r !== esperado) ok(false, `httpNode: ${label}`, `obtenido: ${r}`);
}

// ── 2b · socket.io del dashboard ────────────────────────────────────────────────────────────
console.log("\n── 2b · socket.io del dashboard ──────────────────────────────────\n");

/** Socket falso con lo que miran los dos middlewares. */
function fakeSocket(host, { websocket = false, xdomain = false } = {}) {
  const state = { closed: false, disconnected: false };
  const socket = {
    request: { headers: host === undefined ? {} : { host } },
    handshake: { xdomain },
    client: { conn: { request: { url: websocket ? "/dashboard/socket.io/?EIO=4&transport=websocket" : "/dashboard/socket.io/?EIO=4&transport=polling" },
                      close() { state.closed = true; } } },
    disconnect() { state.disconnected = true; },
  };
  return { socket, state };
}
function runIo(list, host, opts) {
  const { socket, state } = fakeSocket(host, opts);
  for (const mw of list) {
    let result = null;
    mw(socket, (err) => { result = err ? "error" : "next"; });
    if (result !== "next") return result || (state.closed ? "closed" : state.disconnected ? "disconnected" : "parado");
  }
  return "next";
}
const io = (s1.dashboard || {}).ioMiddleware || [];
ok(io.length === 2, "dos middlewares: control de Host y el de fábrica del dashboard", String(io.length));
ok(runIo(io, H) === "next", "dashboard normal en 127.0.0.1 → pasa");
ok(runIo(io, "localhost:1880") === "next", "localhost → pasa");
ok(runIo(io, "rebind.evil.example:1880") === "error", "DNS rebinding (Host ajeno, mismo origen) → rechazado");
ok(runIo(io, undefined) === "error", "sin Host → rechazado");
ok(runIo(io, H, { xdomain: true }) === "disconnected", "otro origen → desconectado, como el de fábrica");
ok(runIo(io, H, { websocket: true }) === "closed", "websocket directo sin polling → cerrado, como el de fábrica");

// ── 3 · con settings.js del usuario ─────────────────────────────────────────────────────────
console.log("\n── 3 · Con settings.js del usuario ───────────────────────────────\n");
const propio = path.join(tmp, "propio");
fs.mkdirSync(propio);
fs.writeFileSync(path.join(propio, "settings.js"),
  "module.exports = { uiHost: '0.0.0.0', flowFile: 'mio.json', httpAdminMiddleware: function (req, res, next) { req.headers.mio = 1; next(); } };\n");
const s3 = load(propio);
ok(s3.uiHost === "0.0.0.0", "se respeta el uiHost elegido por el usuario", s3.uiHost);
ok(s3.flowFile === "mio.json", "y el resto de sus ajustes", s3.flowFile);
ok(s3.httpAdminMiddleware.length === 2, "su middleware se conserva, detrás del guardián");
ok(run(s3.httpAdminMiddleware, { host: "192.168.1.10:1880" }) === "next",
   "fuera de loopback por decisión del usuario, el Host de la LAN no se rechaza");
ok(run(s3.httpAdminMiddleware, { host: "192.168.1.10:1880", origin: "http://evil.example" }) === 403,
   "pero el origen ajeno sí");
ok(fs.readFileSync(path.join(propio, "settings.js"), "utf8").includes("0.0.0.0"), "el settings.js del usuario no se modifica");

const conIo = path.join(tmp, "con-io");
fs.mkdirSync(conIo);
fs.writeFileSync(path.join(conIo, "settings.js"),
  "module.exports = { dashboard: { path: 'panel', ioMiddleware: function mio(socket, next) { next(); } } };\n");
const s4 = load(conIo);
ok(s4.dashboard.path === "panel", "se conservan los ajustes de dashboard del usuario", s4.dashboard.path);
ok(s4.dashboard.ioMiddleware.length === 2 && s4.dashboard.ioMiddleware[1].name === "mio",
   "su ioMiddleware sustituye al de fábrica, detrás del control de Host");

fs.rmSync(tmp, { recursive: true, force: true });
delete process.env.LCAUDIT_NODE_RED_DIR;
console.log(`\n${passed} ok · ${failed} fallo(s)\n`);
process.exit(failed ? 1 : 0);
