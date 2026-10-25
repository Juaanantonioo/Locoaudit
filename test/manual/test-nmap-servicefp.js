"use strict";

/**
 * test-nmap-servicefp.js — Un servicio que nmap no reconoce del todo no se lee como "unknown".
 * El atributo `servicefp` de -sV lleva barras ("HTTP/1\.1") y el parser tiene que cruzarlas.
 * Uso: node test/manual/test-nmap-servicefp.js
 */

const fs   = require("fs");
const path = require("path");

const { leerXmlNmap } = require("../../nodes/audit-network/modules/nmap-wrapper");

let failed = 0;
let passed = 0;

function ok(cond, label, detail) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}`); if (detail) console.log(`      ${detail}`); }
}

const fixture = (n) => fs.readFileSync(path.join(__dirname, "../fixtures/nmap", n), "utf8");

console.log("\n── Un servicefp con barras no puede tapar el nombre del servicio ──\n");

// Captura real de nmap 7.99; el 5000 (AirTunes) no se identifica y emite la huella entera.
const xml    = fixture("scan-ports-open.xml");
const p5000  = leerXmlNmap(xml).find((p) => p.port === 5000);

ok(p5000, "el puerto con servicefp sigue apareciendo: el bug nunca perdió puertos");
ok(/servicefp="[^"]*\//.test(xml), "y el fixture trae de verdad una huella con barras dentro");
ok(p5000.service === "rtsp",
   "el servicio se lee del atributo name, no del fallback 'unknown'", p5000.service);

// El patrón que no cruza barras no casa con el bloque real: documenta qué se rompería.
const bloque = xml.match(/<port\s[^>]*portid="5000">[\s\S]*?<\/port>/)[0];
ok(bloque.match(/<service\s([^/]*)\/?>/) === null,
   "el patrón ANTIGUO no casaba con este bloque: de ahí salía el 'unknown'");
ok(bloque.match(/<service\b([^>]*?)\/?>/) !== null,
   "el actual sí, porque corta en '>' y nmap escapa cualquier '>' interno como &gt;");

// Lo que NO puede cambiar al arreglarlo: los puertos sin servicefp se leen igual que siempre.
const p22 = leerXmlNmap(xml).find((p) => p.port === 22);
ok(p22 && p22.service === "ssh", "un puerto normal se sigue leyendo igual", p22 && p22.service);

console.log(`\n${failed === 0 ? "OK" : "FALLOS"}: ${passed} pasadas, ${failed} fallidas\n`);
process.exit(failed === 0 ? 0 : 1);
