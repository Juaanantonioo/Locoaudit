"use strict";

/**
 * test-network-hostname.js — El nombre PTR del objetivo, de nmap al dashboard.
 *
 * El escaneo NO usa -n, así que nmap ya resolvía el DNS inverso del objetivo y
 * emitía <hostnames> en el XML… que el parser tiraba a la basura. Este test fija
 * las tres formas del bloque y la regla de pintado, que es donde está el riesgo
 * de inventar dato:
 *
 *   <hostname type="PTR"/>  → dato real            → se muestra
 *   <hostname type="user"/> → el eco del target    → NO se muestra (sería
 *                             devolverle al usuario lo que él escribió)
 *   <hostnames></hostnames> → sin PTR              → NO se muestra NADA, ni un
 *                             guion: un guion sugiere "se comprobó y no tiene
 *                             nombre", y lo que pasa es que no hay dato
 *
 * La lógica de la píldora se EXTRAE del ui_template, no se reimplementa: así el
 * test no puede dar verde sobre una copia que ya divergió del dashboard real.
 *
 * Uso: node test/manual/test-network-hostname.js
 */

const fs   = require("fs");
const path = require("path");
const { parsePtrHostname } = require("../../nodes/audit-network/modules/nmap-wrapper");

const ROOT = path.join(__dirname, "..", "..");
const FIX  = path.join(ROOT, "test", "fixtures", "nmap");
const leer = (f) => fs.readFileSync(path.join(FIX, f), "utf8");

let failed = 0, passed = 0;
function ok(cond, label, detail) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}`); if (detail) console.log(`      ${detail}`); }
}

console.log("\n── 1 · Las tres formas del bloque <hostnames> ────────────────────\n");

ok(parsePtrHostname(leer("scan-ports-open.xml")) === "localhost",
   "XML con PTR → devuelve el nombre",
   `devolvió ${JSON.stringify(parsePtrHostname(leer("scan-ports-open.xml")))}`);

ok(parsePtrHostname(leer("scan-no-ports.xml")) === "localhost",
   "el PTR no depende de que haya puertos abiertos");

ok(parsePtrHostname(leer("scan-unreachable.xml")) === null,
   "<hostnames></hostnames> vacío → null",
   `devolvió ${JSON.stringify(parsePtrHostname(leer("scan-unreachable.xml")))}`);

// type="user" es lo que escribió el usuario, no un descubrimiento.
const SOLO_USER = '<hostnames>\n<hostname name="example.com" type="user"/>\n</hostnames>';
ok(parsePtrHostname(SOLO_USER) === null, 'solo type="user" → null (no es dato nuevo)');

const USER_Y_PTR = '<hostnames>\n<hostname name="mi-nas" type="user"/>\n<hostname name="nas.local" type="PTR"/>\n</hostnames>';
ok(parsePtrHostname(USER_Y_PTR) === "nas.local", 'con "user" y "PTR" mezclados, se coge el PTR');

ok(parsePtrHostname("") === null && parsePtrHostname(null) === null,
   "XML vacío o nulo → null, sin lanzar");

console.log("\n── 2 · runNmap propaga el hostname con la misma forma ────────────\n");

// Se comprueba sobre el contrato del objeto `scan`, sin ejecutar nmap: las dos
// salidas posibles (escaneo OK y no concluyente) tienen que llevar el campo,
// para que el dashboard no tenga que distinguir casos.
const wrapperSrc = fs.readFileSync(path.join(ROOT, "nodes", "audit-network", "modules", "nmap-wrapper.js"), "utf8");
const scanLines = wrapperSrc.split("\n").filter((l) => /scan: \{ target, portSpec, scanMode/.test(l));
ok(scanLines.length === 2, "hay dos formas de salida de `scan` (ok y no concluyente)", `encontradas: ${scanLines.length}`);
ok(scanLines.every((l) => /hostname/.test(l)), "las dos llevan `hostname`");
ok(/scan: \{[^}]*hostname: null[^}]*\}/.test(wrapperSrc), "la rama no concluyente lo deja explícitamente en null");

const nodeSrc = fs.readFileSync(path.join(ROOT, "nodes", "audit-network", "audit-network.js"), "utf8");
ok(/hostname:\s+nmapScan \? nmapScan\.hostname : null/.test(nodeSrc),
   "audit-network.js copia el hostname a scanMeta (null si no hubo escaneo)");

console.log("\n── 3 · Regla de pintado, con el código REAL del dashboard ────────\n");

const tpl = fs.readFileSync(path.join(ROOT, "examples", "dashboard-network-template.html"), "utf8");
const m = tpl.match(/hostnameLabel\(\) \{[\s\S]*?\n    \},/);
ok(!!m, "hostnameLabel() existe en el ui_template");
// eslint-disable-next-line no-eval
const hostnameLabel = eval("(function " + m[0].replace(/,$/, "") + ")");
const pill = (target, hostname) =>
  hostnameLabel.call({ auditData: { scanMeta: { target, hostname } }, targetLabel: target });

ok(pill("127.0.0.1", "localhost") === "localhost",
   "PTR distinto del target → se pinta la píldora");
ok(pill("192.168.0.1", null) === null,
   "sin PTR → NO se pinta (ni guion ni placeholder)");
ok(pill("localhost", "localhost") === null,
   "PTR idéntico al target → NO se pinta (sería la misma info dos veces)");
ok(pill("192.168.0.40", "") === null && pill("192.168.0.40", undefined) === null,
   "cadena vacía o undefined se tratan como 'sin dato'");

// La píldora usa v-if, como el resto de campos opcionales de la tira
ok(/v-if="hostnameLabel"[^>]*>[\s\S]{0,120}?pill-label">Nombre/.test(tpl),
   "la píldora del dashboard va con v-if, igual que Puertos y Duración");

console.log(`\n${"─".repeat(60)}`);
console.log(`  ${passed} correctos · ${failed} fallidos`);
console.log("─".repeat(60) + "\n");
process.exit(failed ? 1 : 0);
