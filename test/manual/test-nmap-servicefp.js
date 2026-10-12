"use strict";

/**
 * test-nmap-servicefp.js — Un servicio que nmap no reconoce del todo NO se lee como "unknown".
 *
 * Bug preexistente (61206c9, 2026-04-12): `-sV` mete un atributo `servicefp` con la huella del servicio y esa huella lleva
 * barras ("HTTP/1\.1"). El regex `/<service\s([^/]*)\/?>/` no cruza barras, dejaba de casar y el servicio caía a "unknown".
 * Se pierden name, product, version y extrainfo (y con ellos el fix por servicio); el puerto y su severidad no cambian.
 * El fixture es una captura real de 2026-08-12 y el test no depende del análisis NSE. El efecto sobre tunnel="ssl" se
 * comprueba en test-nse-parse.js.
 * Uso: node test/manual/test-nmap-servicefp.js
 */

const fs   = require("fs");
const path = require("path");

const { parseNmapXml } = require("../../nodes/audit-network/modules/nmap-wrapper");

let failed = 0;
let passed = 0;

function ok(cond, label, detail) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}`); if (detail) console.log(`      ${detail}`); }
}

const fixture = (n) => fs.readFileSync(path.join(__dirname, "../fixtures/nmap", n), "utf8");

console.log("\n── Un servicefp con barras no puede tapar el nombre del servicio ──\n");

// scan-ports-open.xml: captura real de nmap 7.99 contra 127.0.0.1. El 5000 es AirTunes, que -sV
// sondea sin llegar a identificar, así que emite la huella entera.
const xml    = fixture("scan-ports-open.xml");
const p5000  = parseNmapXml(xml).find((p) => p.port === 5000);

ok(p5000, "el puerto con servicefp sigue apareciendo: el bug nunca perdió puertos");
ok(/servicefp="[^"]*\//.test(xml), "y el fixture trae de verdad una huella con barras dentro");
ok(p5000.service === "rtsp",
   "el servicio se lee del atributo name, no del fallback 'unknown'", p5000.service);

// La regresión concreta, escrita como la comprobaría quien la sufrió: el patrón viejo, aplicado
// al bloque real, NO CASA. Va aquí para que el día que alguien "simplifique" el regex el test
// diga qué se rompe y por qué, en vez de solo cambiar de color.
const bloque = xml.match(/<port\s[^>]*portid="5000">[\s\S]*?<\/port>/)[0];
ok(bloque.match(/<service\s([^/]*)\/?>/) === null,
   "el patrón ANTIGUO no casaba con este bloque: de ahí salía el 'unknown'");
ok(bloque.match(/<service\b([^>]*?)\/?>/) !== null,
   "el actual sí, porque corta en '>' y nmap escapa cualquier '>' interno como &gt;");

// Lo que NO puede cambiar al arreglarlo: los puertos sin servicefp se leen igual que siempre.
const p22 = parseNmapXml(xml).find((p) => p.port === 22);
ok(p22 && p22.service === "ssh", "un puerto normal se sigue leyendo igual", p22 && p22.service);

console.log(`\n${failed === 0 ? "OK" : "FALLOS"}: ${passed} pasadas, ${failed} fallidas\n`);
process.exit(failed === 0 ? 0 : 1);
