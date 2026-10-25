"use strict";

/**
 * test-network-ping-fallback.js — Ping del sistema como segunda opinión cuando Nmap da el equipo por caído.
 * nmap y ping son falsos, en un PATH propio, con salidas reales de macOS y de Windows en español.
 *
 * Bloques:
 *   1. pingSistema(): qué cuenta como respuesta y qué orden se lanza en cada sistema.
 *   2. comprobarAlcance(): cuándo se consulta el ping y qué cambia en el resultado.
 *
 * Uso: node test/manual/test-network-ping-fallback.js
 */

const fs   = require("fs");
const os   = require("os");
const path = require("path");

let failed = 0, passed = 0;
function ok(cond, label, detail) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}`); if (detail) console.log(`      ${detail}`); }
}

if (process.platform === "win32") {
  console.log("\n  ⊘ los binarios falsos son scripts de shell: test omitido en Windows\n");
  process.exit(0);
}

// ── Salidas reales ──────────────────────────────────────────────────────────────────────────
const OUT = {
  macReply:
    "PING 10.10.10.10 (10.10.10.10): 56 data bytes\n" +
    "64 bytes from 10.10.10.10: icmp_seq=0 ttl=63 time=15.773 ms\n" +
    "64 bytes from 10.10.10.10: icmp_seq=1 ttl=63 time=8.032 ms\n\n" +
    "--- 10.10.10.10 ping statistics ---\n" +
    "2 packets transmitted, 2 packets received, 0.0% packet loss\n",
  macTimeout:
    "PING 10.10.10.10 (10.10.10.10): 56 data bytes\n" +
    "Request timeout for icmp_seq 0\n\n" +
    "--- 10.10.10.10 ping statistics ---\n" +
    "2 packets transmitted, 0 packets received, 100.0% packet loss\n",
  winReplyEs:
    "\r\nHaciendo ping a 10.10.10.10 con 32 bytes de datos:\r\n" +
    "Respuesta desde 10.10.10.10: bytes=32 tiempo=6ms TTL=63\r\n" +
    "Respuesta desde 10.10.10.10: bytes=32 tiempo=7ms TTL=63\r\n",
  winRouterUnreachEs:
    "\r\nHaciendo ping a 10.10.10.10 con 32 bytes de datos:\r\n" +
    "Respuesta desde 192.168.1.1: Host de destino inaccesible.\r\n" +
    "Respuesta desde 192.168.1.1: Host de destino inaccesible.\r\n\r\n" +
    "Estadísticas de ping para 10.10.10.10:\r\n" +
    "    Paquetes: enviados = 2, recibidos = 2, perdidos = 0\r\n",
  linuxRouterUnreach:
    "PING 10.10.10.10 (10.10.10.10) 56(84) bytes of data.\n" +
    "From 192.168.1.1 icmp_seq=1 Destination Host Unreachable\n",
};

// Nmap -sn sin root y con el equipo "caído": XML completo, 0 hosts up, exit success.
const NMAP_DOWN_XML =
  '<?xml version="1.0"?><nmaprun><runstats><finished time="1" exit="success"/>' +
  '<hosts up="0" down="1" total="1"/></runstats></nmaprun>';
const NMAP_UP_XML =
  '<?xml version="1.0"?><nmaprun><host><status state="up" reason="syn-ack"/></host>' +
  '<runstats><finished time="1" exit="success"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>';
const NMAP_ERROR_XML =
  '<?xml version="1.0"?><nmaprun><runstats><finished time="1" exit="error" errormsg="boom"/>' +
  '<hosts up="0" down="0" total="0"/></runstats></nmaprun>';

const tmp     = fs.mkdtempSync(path.join(os.tmpdir(), "lcaudit-test-ping-"));
const binNmap = path.join(tmp, "bin-nmap");      // solo nmap
const binBoth = path.join(tmp, "bin-both");      // nmap y ping
fs.mkdirSync(binNmap); fs.mkdirSync(binBoth);
const pingWitness = path.join(tmp, "ping-called");

// Las salidas van a ficheros y los scripts las vuelcan con cat: nada de interpolar texto en sh.
const outFile = path.join(tmp, "ping-out.txt");
const xmlFile = path.join(tmp, "nmap-out.xml");

const NMAP_SH = `#!/bin/sh\ncat "${xmlFile}"\nexit 0\n`;
// $PING_EXIT decide el código de salida: el del sistema real en cada caso.
const PING_SH =
  `#!/bin/sh\necho "$@" > "${pingWitness}"\ncat "${outFile}"\nexit \${PING_EXIT:-0}\n`;

for (const dir of [binNmap, binBoth]) fs.writeFileSync(path.join(dir, "nmap"), NMAP_SH, { mode: 0o755 });
fs.writeFileSync(path.join(binBoth, "ping"), PING_SH, { mode: 0o755 });

const ORIGINAL_PATH = process.env.PATH;
// PATH sin el del sistema para que "no hay ping" sea cierto; se mantiene /bin para sh y cat.
function usePath(dir) { process.env.PATH = `${dir}${path.delimiter}/bin${path.delimiter}/usr/bin`; }
function setPing(out, exit) {
  fs.writeFileSync(outFile, out);
  process.env.PING_EXIT = String(exit);
  try { fs.rmSync(pingWitness, { force: true }); } catch (_) {}
}
function setNmap(xml) { fs.writeFileSync(xmlFile, xml); }

const { pingSistema, comprobarAlcance, deducirEstadoObjetivo } =
  require("../../nodes/audit-network/modules/host-discovery");

async function main() {
  // Puede haber un ping real en /bin o /usr/bin: se comprueba antes de los casos "sin ping".
  const realPing = ["/bin/ping", "/usr/bin/ping", "/sbin/ping", "/usr/sbin/ping"].some((p) => fs.existsSync(p));

  // ── 1 · pingSistema ───────────────────────────────────────────────────────────────────────
  console.log("\n── 1 · pingSistema(): qué cuenta como respuesta ───────────────────\n");
  usePath(binBoth);

  const CASOS = [
    ["macOS, responde (captura real)",          OUT.macReply,           0, true],
    ["macOS, sin respuesta (exit 2)",           OUT.macTimeout,         2, false],
    ["Windows ES, responde (TTL=63)",           OUT.winReplyEs,         0, true],
    ["Windows ES, router 'inaccesible', exit 0", OUT.winRouterUnreachEs, 0, false],
    ["Linux, router 'Unreachable' (exit 1)",    OUT.linuxRouterUnreach, 1, false],
  ];
  for (const [que, out, exit, esperado] of CASOS) {
    setPing(out, exit);
    const r = await pingSistema("10.10.10.10", "darwin");
    ok(r.ran === true && r.replied === esperado, `${que} → ${esperado ? "responde" : "no responde"}`, JSON.stringify(r));
  }

  setPing("", 1);
  const vacio = await pingSistema("10.10.10.10", "darwin");
  ok(vacio.ran === false && vacio.replied === false,
     "ping que no deja ninguna salida → no se pudo hacer (ran=false), no un 'no responde'", JSON.stringify(vacio));

  // La orden de cada sistema: los -W no significan lo mismo en macOS y en Linux.
  setPing(OUT.macReply, 0);
  const mac = await pingSistema("10.10.10.10", "darwin");
  ok(/ -n -c 2 -W 1000 10\.10\.10\.10$/.test(mac.cmd), "macOS: -c 2 -W 1000 (milisegundos)", mac.cmd);
  const lin = await pingSistema("10.10.10.10", "linux");
  ok(/ -n -c 2 -W 1 10\.10\.10\.10$/.test(lin.cmd), "Linux: -c 2 -W 1 (segundos)", lin.cmd);
  const win = await pingSistema("10.10.10.10", "win32");
  ok(/ -n 2 -w 1000 10\.10\.10\.10$/.test(win.cmd), "Windows: -n 2 -w 1000", win.cmd);

  if (!realPing) {
    usePath(binNmap);
    const sin = await pingSistema("10.10.10.10", "darwin");
    ok(sin.ran === false && sin.cmd === null, "sin ping instalado → ran=false y sin orden", JSON.stringify(sin));
  }

  // ── 2 · comprobarAlcance ───────────────────────────────────────────────────────────────
  console.log("\n── 2 · comprobarAlcance(): cuándo manda el ping ────────────────\n");
  const opts = { target: "10.10.10.10", isLocal: false, platform: "darwin" };

  // El caso real.
  usePath(binBoth); setNmap(NMAP_DOWN_XML); setPing(OUT.macReply, 0);
  let d = await comprobarAlcance(opts);
  ok(d.reachable === true && deducirEstadoObjetivo(d) === "reachable",
     "Nmap 'caído' + ping responde → accesible, y se escanea", JSON.stringify(d));
  ok(d.confirmedBy === "ping" && d.reason === "echo-reply", "consta que lo confirmó el ping del sistema");
  ok(d.method === "nmap-sn", "method sigue siendo nmap-sn (modulesRun no cambia)");
  ok(/no respondió a las sondas de Nmap, pero sí al ping del sistema/.test(d.detail), "el detalle lo explica", d.detail);

  // Equipo caído de verdad: el resultado de antes, con una frase más.
  setPing(OUT.macTimeout, 2);
  d = await comprobarAlcance(opts);
  ok(d.reachable === false && deducirEstadoObjetivo(d) === "unreachable",
     "Nmap 'caído' + ping sin respuesta → sigue 'no accesible'", JSON.stringify(d));
  ok(/Tampoco respondió al ping del sistema\.$/.test(d.detail), "el detalle dice que también se probó el ping", d.detail);

  // El router de Windows no cuela como respuesta.
  setPing(OUT.winRouterUnreachEs, 0);
  d = await comprobarAlcance({ ...opts, platform: "win32" });
  ok(d.reachable === false, "Windows: 'Host de destino inaccesible' con exit 0 → no accesible", JSON.stringify(d));

  // Sin ping: no se afirma una comprobación que no se hizo.
  if (!realPing) {
    usePath(binNmap); setNmap(NMAP_DOWN_XML);
    d = await comprobarAlcance(opts);
    ok(d.reachable === false && !/ping/i.test(d.detail),
       "sin ping instalado → 'no accesible' como antes y sin mencionar el ping", d.detail);
  }

  // Cuando Nmap ya ha decidido, el ping no se lanza.
  usePath(binBoth);
  setNmap(NMAP_UP_XML); setPing(OUT.macReply, 0);
  d = await comprobarAlcance(opts);
  ok(d.reachable === true && !d.confirmedBy && !fs.existsSync(pingWitness),
     "Nmap 'activo' → no se consulta el ping", JSON.stringify(d));

  setNmap(NMAP_ERROR_XML); setPing(OUT.macReply, 0);
  d = await comprobarAlcance(opts);
  ok(d.reachable === null && !fs.existsSync(pingWitness),
     "Nmap con error (ambiguo) → no se consulta el ping: ese caso ya se escanea", JSON.stringify(d));

  // Objetivo local: ni Nmap ni ping.
  d = await comprobarAlcance({ target: "127.0.0.1", isLocal: true });
  ok(d.method === "local" && !fs.existsSync(pingWitness), "objetivo local → ni descubrimiento ni ping");

  process.env.PATH = ORIGINAL_PATH;
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${passed} ok · ${failed} fallo(s)\n`);
  process.exit(failed ? 1 : 0);
}

main().catch((err) => { console.error(err); process.exit(1); });
