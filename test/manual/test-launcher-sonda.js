"use strict";

/**
 * test-launcher-sonda.js: la sonda de herramientas del asistente usa una función que lib/executor exporta.
 * Ejecuta el mismo código JS que lanza el asistente. Uso: node test/manual/test-launcher-sonda.js
 */

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

let failed = 0, passed = 0;
function ok(cond, label, detail) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}`); if (detail) console.log(`      ${detail}`); }
}

const ROOT = path.join(__dirname, "../..");
const EXECUTOR = path.join(ROOT, "lib/executor.js");
const launcher = fs.readFileSync(path.join(ROOT, "launcher/lcaudit_launcher.py"), "utf8");

console.log("\n── Sonda del asistente de instalación ─────────────────────────────\n");

// _JS_PROBE es una tupla de cadenas de Python: se unen para obtener el código JS.
const bloque = launcher.match(/_JS_PROBE = \(\n([\s\S]*?)\n\)/);
ok(!!bloque, "el asistente define _JS_PROBE");

let sonda = "";
if (bloque) {
  const trozos = bloque[1].match(/"((?:[^"\\]|\\.)*)"/g) || [];
  sonda = trozos.map((t) => JSON.parse(t)).join("");
}

const importada = (sonda.match(/const \{(\w+)\}=require/) || [])[1];
const exportadas = Object.keys(require(EXECUTOR));
ok(!!importada && exportadas.includes(importada), `lib/executor exporta '${importada}'`, `exporta: ${exportadas.join(", ")}`);

const r = spawnSync(process.execPath, ["-e", sonda, EXECUTOR, "node", "herramienta-que-no-existe-xyz"], { encoding: "utf8" });
ok(r.status === 0, "la sonda termina sin error", (r.stderr || "").split("\n")[0]);

let datos = null;
try { datos = JSON.parse(r.stdout); } catch (_) { /* se comprueba abajo */ }
ok(datos && typeof datos === "object", "devuelve JSON", r.stdout);
ok(datos && typeof datos.node === "string" && datos.node.length > 0, "encuentra una herramienta instalada", JSON.stringify(datos));
ok(datos && datos["herramienta-que-no-existe-xyz"] === null, "una herramienta ausente es null, no un error", JSON.stringify(datos));

console.log(`\n${passed} pasados · ${failed} fallidos`);
process.exit(failed ? 1 : 0);
