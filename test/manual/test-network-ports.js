"use strict";

/**
 * test-network-ports.js — La lista de puertos y el rango de cada modo de audit-network.
 * A nmap le llega la lista normalizada, nunca el texto del campo; el tiempo máximo escala con los puertos.
 *
 * Bloques:
 *   1. validarPuertos(): qué se acepta, qué se rechaza y cómo se normaliza.
 *   2. tiempoMaximoEscaneo(): los límites medidos se conservan y los nuevos escalan con los puertos.
 *   3. La orden que llega a nmap en cada modo (un nmap falso guarda sus argumentos).
 *   4. El nodo con una lista no válida: NET-CFG-ERR y nmap sin ejecutar.
 *
 * Uso: node test/manual/test-network-ports.js
 */

const fs   = require("fs");
const os   = require("os");
const path = require("path");

let failed = 0, passed = 0;
function ok(cond, label, detail) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}`); if (detail) console.log(`      ${detail}`); }
}

const isWin = process.platform === "win32";
const tmp     = fs.mkdtempSync(path.join(os.tmpdir(), "lcaudit-test-ports-"));
const argsLog = path.join(tmp, "nmap-args");
const pwned   = path.join(tmp, "pwned");
if (!isWin) {
  // Guarda los argumentos y devuelve un escaneo terminado sin puertos abiertos.
  fs.writeFileSync(path.join(tmp, "nmap"),
    "#!/bin/sh\n" +
    `echo "$@" >> "${argsLog}"\n` +
    "echo '<?xml version=\"1.0\"?><nmaprun><host><status state=\"up\" reason=\"user-set\"/></host>" +
    "<runstats><finished time=\"1\" exit=\"success\"/><hosts up=\"1\" down=\"0\" total=\"1\"/></runstats></nmaprun>'\n",
    { mode: 0o755 });
  process.env.PATH = `${tmp}${path.delimiter}${process.env.PATH}`;
}

const { validarPuertos, tiempoMaximoEscaneo } = require("../../nodes/audit-network/modules/network-utils");

// ── 1 · validarPuertos ──────────────────────────────────────────────────────────────────
console.log("\n── 1 · validarPuertos(): qué es una lista de puertos ───────────\n");

const VALIDAS = [
  ["22",                    "22",                  1],
  ["22,80,443",             "22,80,443",           3],
  [" 22 , 80 ,443 ",        "22,80,443",           3],      // espacios alrededor de las comas
  ["8000-8080",             "8000-8080",           81],
  ["1-65535",               "1-65535",             65535],
  ["20-25,22",              "20-25,22",            6],      // solapes: count cuenta puertos distintos
  ["1-1024,1000-2000",      "1-1024,1000-2000",    2000],
  ["65535",                 "65535",               1],
];
for (const [entrada, spec, count] of VALIDAS) {
  const r = validarPuertos(entrada);
  ok(r.ok && r.spec === spec && r.count === count,
     `acepta ${JSON.stringify(entrada)} → ${spec} (${count} puertos)`, JSON.stringify(r));
}

const INVALIDAS = [
  ["",                         "vacía",                         true],
  ["   ",                      "solo espacios",                 true],
  [null,                       "nula",                          true],
  ["0",                        "puerto 0",                      false],
  ["65536",                    "puerto > 65535",                false],
  ["80-22",                    "rango al revés",                false],
  ["022",                      "cero a la izquierda",           false],
  ["22,,80",                   "elemento vacío",                false],
  ["22,",                      "coma final",                    false],
  ["ssh",                      "nombre de servicio",            false],
  ["T:22",                     "prefijo de protocolo de nmap",  false],
  ["1-",                       "rango sin final",               false],
  ["22 80",                    "espacio sin coma",              false],
  ["22; touch /tmp/x",         "inyección con ;",               false],
  ["22 && id",                 "inyección con &&",              false],
  ["$(id)",                    "sustitución de orden",          false],
  ["22\nid",                   "salto de línea",                false],
  ["`id`",                     "comillas invertidas",           false],
];
for (const [entrada, que, vacia] of INVALIDAS) {
  const r = validarPuertos(entrada);
  ok(!r.ok && r.empty === vacia && typeof r.reason === "string",
     `rechaza ${que}: ${JSON.stringify(entrada)}`, JSON.stringify(r));
}

// ── 2 · tiempoMaximoEscaneo ─────────────────────────────────────────────────────────────────────
console.log("\n── 2 · tiempoMaximoEscaneo(): el tiempo máximo de cada modo ────────────\n");

ok(tiempoMaximoEscaneo("rapido") === 90000,   "rápido conserva sus 90 s medidos");
ok(tiempoMaximoEscaneo("standard") === 240000, "estándar conserva sus 240 s medidos");
ok(tiempoMaximoEscaneo("full") === 65535 * 62, `completo: 65535 puertos × 62 ms = ${(65535 * 62 / 60000).toFixed(1)} min`);
ok(tiempoMaximoEscaneo("custom", 10000) === 620000,
   "personalizado con 10.000 puertos = 620 s, el límite que tenía antes el modo completo");
ok(tiempoMaximoEscaneo("custom", 3) === 90000, "personalizado con pocos puertos: nunca menos de 90 s");
ok(tiempoMaximoEscaneo("custom", 65535) === tiempoMaximoEscaneo("full"), "1-65535 a mano tarda lo mismo que el modo completo");

async function main() {
  if (isWin) {
    console.log("\n  ⊘ en Windows no hay nmap falso por PATH — bloques 3 y 4 omitidos\n");
  } else {
    // ── 3 · La orden que llega a nmap ─────────────────────────────────────────────────────
    console.log("\n── 3 · La orden que llega a nmap en cada modo ────────────────────\n");
    const { ejecutarNmap } = require("../../nodes/audit-network/modules/nmap-wrapper");
    const lastP = () => {
      const lines = fs.readFileSync(argsLog, "utf8").trim().split("\n");
      const m = lines[lines.length - 1].match(/-p (\S+)/);
      return m ? m[1] : null;
    };

    await ejecutarNmap({ target: "127.0.0.1", scanMode: "full", timeout: 5000 });
    ok(lastP() === "1-65535", "completo → -p 1-65535 (antes 1-10000,27017)", lastP());

    await ejecutarNmap({ target: "127.0.0.1", scanMode: "standard", timeout: 5000 });
    ok(/^1-3000,.*27017$/.test(lastP()), "estándar sin cambios: 1-3000 más el catálogo", lastP());

    await ejecutarNmap({ target: "127.0.0.1", scanMode: "rapido", timeout: 5000 });
    ok(/^1-1024,.*27017$/.test(lastP()), "rápido sin cambios: 1-1024 más el catálogo", lastP());

    // ── 4 · El nodo con una lista no válida ───────────────────────────────────────────────
    console.log("\n── 4 · El nodo: lista no válida → NET-CFG-ERR sin nmap ───────────\n");
    let Ctor = null;
    const RED = {
      nodes: {
        createNode(node) {
          node._h = {}; node.on = (e, f) => { node._h[e] = f; };
          node.status = (s) => { node._status = s; }; node.log = () => {}; node.warn = () => {}; node.error = () => {};
        },
        registerType(_n, C) { Ctor = C; },
        getNode() { return null; },
      },
    };
    require("../../nodes/audit-network/audit-network.js")(RED);
    const run = (config) => new Promise((resolve, reject) => {
      const node = {}; Ctor.call(node, config);
      node._h.input({}, (m) => resolve({ msg: m, node }), (err) => { if (err) reject(err); });
    });

    const CASOS = [
      [`22; touch ${pwned}`, "inyección"],
      ["80-22",              "rango al revés"],
      ["70000",              "puerto fuera de rango"],
    ];
    for (const [ports, que] of CASOS) {
      try { fs.rmSync(argsLog, { force: true }); } catch (_) {}
      const { msg, node } = await run({ scanTarget: "localhost", scanMode: "custom", customPorts: ports });
      const p = msg.payload;
      ok(p.findings.length === 1 && p.findings[0].id === "NET-CFG-ERR" &&
         /lista de puertos no es válida/.test(p.findings[0].title),
         `${que}: un único NET-CFG-ERR "lista de puertos no es válida"`, JSON.stringify(p.findings.map((f) => f.title)));
      ok(!fs.existsSync(argsLog), `${que}: nmap no se ha ejecutado`);
      ok(p.scanMeta.scanStatus === "not-run", `${que}: scanMeta dice que no se escaneó`);
      ok(node._status && node._status.text === "Configuración incorrecta", `${que}: estado "Configuración incorrecta"`);
    }
    ok(!fs.existsSync(pwned), "la orden inyectada no se ha ejecutado");

    // Una lista válida llega a nmap normalizada.
    try { fs.rmSync(argsLog, { force: true }); } catch (_) {}
    await run({ scanTarget: "localhost", scanMode: "custom", customPorts: " 22 , 80 ,8000-8080 " });
    ok(lastP() === "22,80,8000-8080", "lista válida → nmap recibe la forma normalizada", lastP());
  }

  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${passed} ok · ${failed} fallo(s)\n`);
  process.exit(failed ? 1 : 0);
}

main().catch((err) => { console.error(err); process.exit(1); });
