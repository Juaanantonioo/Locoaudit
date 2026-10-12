"use strict";

/**
 * test-node-red-guard.js — Ajustes con los que el launcher arranca Node-RED.
 *
 * launcher/node-red-settings.js carga el settings.js del usuario y añade dos cosas: escucha en
 * 127.0.0.1 si el usuario no eligió otra, y un middleware delante de la API del editor que
 * rechaza peticiones de otro origen o con un Host que no es loopback. Sin él, el CORS abierto
 * de @node-red/editor-api dejaba a cualquier web leer /flows y desplegar desde el navegador.
 *
 * Bloques:
 *   1. Sin settings.js del usuario: uiHost 127.0.0.1 y flowFile flows.json.
 *   2. El guardián: qué pasa y qué se rechaza.
 *   3. Con settings.js del usuario: se respetan su uiHost y su propio middleware.
 *
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

fs.rmSync(tmp, { recursive: true, force: true });
delete process.env.LCAUDIT_NODE_RED_DIR;
console.log(`\n${passed} ok · ${failed} fallo(s)\n`);
process.exit(failed ? 1 : 0);
