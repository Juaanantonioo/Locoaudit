"use strict";

/**
 * test-network-target.js — Qué objetivo acepta audit-network, y qué pasa cuando no es válido.
 *
 * Bloques:
 *   1. validarObjetivo(): lo que se acepta y lo que no, incluida la red y la difusión propias.
 *   2. El nodo con un objetivo no válido: un NET-CFG-ERR y nmap SIN ejecutar (un nmap falso
 *      en el PATH deja un fichero testigo si alguien lo llama).
 *   3. El NET-CFG-ERR de la lista de puertos vacía sigue saliendo con el payload de antes.
 *   4. Descubrimiento cortado por tiempo: el motivo es el tiempo, no el stderr de nmap.
 *
 * Uso: node test/manual/test-network-target.js
 */

const fs   = require("fs");
const os   = require("os");
const path = require("path");

let failed = 0, passed = 0, skipped = 0;
function ok(cond, label, detail) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}`); if (detail) console.log(`      ${detail}`); }
}

// ── nmap falso en un PATH propio, ANTES de cargar ningún módulo ─────────────────────────────
const isWin = process.platform === "win32";
const tmp   = fs.mkdtempSync(path.join(os.tmpdir(), "lcaudit-test-target-"));
const witness = path.join(tmp, "nmap-was-called");
if (!isWin) {
  // `exec sleep` para que el SIGTERM llegue al proceso que tiene abiertos stdout y stderr.
  fs.writeFileSync(path.join(tmp, "nmap"),
    "#!/bin/sh\n" +
    `echo called >> "${witness}"\n` +
    'echo "Warning:  You are not root -- using TCP pingscan rather than ICMP" >&2\n' +
    "exec sleep 5\n",
    { mode: 0o755 });
  process.env.PATH = `${tmp}${path.delimiter}${process.env.PATH}`;
}

const { validarObjetivo } = require("../../nodes/audit-network/modules/network-utils");

// ── 1 · validarObjetivo ──────────────────────────────────────────────────────────────────────
console.log("\n── 1 · validarObjetivo(): qué es la dirección de un equipo ────────\n");

// Interfaces fijas: el resultado no puede depender de la red de quien ejecuta el test.
const IFACES = {
  en0: [{ family: "IPv4", internal: false, address: "192.168.1.34", netmask: "255.255.255.0", cidr: "192.168.1.34/24" }],
  wg0: [{ family: "IPv4", internal: false, address: "10.8.0.2", netmask: "255.255.255.254", cidr: "10.8.0.2/31" }],
  lo0: [{ family: "IPv4", internal: true,  address: "127.0.0.1", netmask: "255.0.0.0", cidr: "127.0.0.1/8" }],
  eth1: [{ family: "IPv4", internal: false, address: "203.0.113.5", netmask: "255.255.255.0", cidr: "203.0.113.5/24" }],
};

const VALIDAS = [
  ["192.168.1.10", "192.168.1.10"],
  ["  192.168.1.20 ", "192.168.1.20"], // los espacios de alrededor se recortan
  ["203.0.113.40", "203.0.113.40"],    // pública, pero en una subred de este equipo
  ["127.0.0.1", "127.0.0.1"],
  ["10.8.0.3", "10.8.0.3"],            // en un /31 no hay red ni difusión
];
for (const [entrada, esperada] of VALIDAS) {
  const r = validarObjetivo(entrada, IFACES);
  ok(r.ok && r.ip === esperada, `acepta ${JSON.stringify(entrada)} → ${esperada}`, JSON.stringify(r));
}

const INVALIDAS = [
  ["", "vacío"],
  [null, "nulo"],
  ["10.10.10.0/24", "rango CIDR"],
  ["10.10.10.1-20", "rango con guion"],
  ["10.10.10.1,10.10.10.2", "lista"],
  ["10.10.10.1 10.10.10.2", "dos direcciones"],
  ["router.lan", "nombre de equipo"],
  ["localhost", "localhost (para eso está 'Este equipo')"],
  ["::1", "IPv6"],
  ["10.10.10.*", "comodín"],
  ["1.2.3.4; touch /tmp/x", "inyección con ;"],
  ["1.2.3.4 && id", "inyección con &&"],
  ["$(id)", "sustitución de orden"],
  ["1.2.3.4\nid", "salto de línea"],
  ["256.1.1.1", "octeto > 255"],
  ["192.168.01.10", "cero a la izquierda"],
  ["1.2.3", "tres octetos"],
  ["0.0.0.0", "0.0.0.0"],
  ["0.1.2.3", "rango 0/8"],
  ["224.0.0.251", "multidifusión"],
  ["255.255.255.255", "difusión global"],
  ["240.0.0.1", "reservada"],
  ["192.168.1.0", "dirección de red de una subred propia"],
  ["192.168.1.255", "difusión de una subred propia"],
  ["8.8.8.8", "pública fuera de las subredes propias"],
  ["10.10.10.20", "privada, pero de otra red"],
  ["172.16.5.5", "privada, pero de otra red"],
  ["169.254.10.20", "enlace local sin interfaz en esa red"],
  ["192.168.2.10", "subred vecina de la propia"],
  ["100.64.0.1", "CGNAT"],
];
for (const [entrada, que] of INVALIDAS) {
  const r = validarObjetivo(entrada, IFACES);
  ok(!r.ok && typeof r.reason === "string" && r.reason.length > 0,
     `rechaza ${que}: ${JSON.stringify(entrada)}`, JSON.stringify(r));
}

ok(/no está en la misma red/.test(validarObjetivo("8.8.8.8", IFACES).reason),
   "el motivo de una dirección de otra red lo dice", validarObjetivo("8.8.8.8", IFACES).reason);

// El caso que motiva la regla: el equipo está en 10.10.10.0/24 y se pide una dirección de 192.168.1.0/24.
const OTRA_RED = { en0: [{ family: "IPv4", internal: false, address: "10.10.10.5", netmask: "255.255.255.0", cidr: "10.10.10.5/24" }] };
ok(!validarObjetivo("192.168.1.10", OTRA_RED).ok, "desde 10.10.10.0/24 rechaza 192.168.1.10, aunque sea privada");
ok(validarObjetivo("10.10.10.20", OTRA_RED).ok, "desde 10.10.10.0/24 acepta 10.10.10.20");

ok(/red 192\.168\.1\.34\/24/.test(validarObjetivo("192.168.1.0", IFACES).reason),
   "el motivo de la dirección de red nombra la subred y la interfaz",
   validarObjetivo("192.168.1.0", IFACES).reason);

// ── Un RED mínimo para cargar el nodo de verdad ─────────────────────────────────────────────
function loadNode() {
  let Ctor = null;
  const RED = {
    nodes: {
      createNode(node) {
        node._handlers = {};
        node.on = (ev, fn) => { node._handlers[ev] = fn; };
        node.status = (s) => { node._status = s; };
        node.log = () => {}; node.warn = () => {}; node.error = () => {};
      },
      registerType(_name, C) { Ctor = C; },
      getNode() { return null; },
    },
  };
  require("../../nodes/audit-network/audit-network.js")(RED);
  return (config) => {
    const node = {};
    Ctor.call(node, config);
    return {
      node,
      run: () => new Promise((resolve, reject) => {
        const msg = {};
        node._handlers.input(msg, (m) => resolve(m), (err) => { if (err) reject(err); });
      }),
    };
  };
}

async function main() {
  // ── 2 · El nodo con un objetivo no válido ──────────────────────────────────────────────────
  console.log("\n── 2 · Objetivo no válido: NET-CFG-ERR y nmap sin ejecutar ───────\n");

  if (isWin) {
    console.log("  ⊘ en Windows no hay nmap falso por PATH — bloques 2 y 4 omitidos");
    skipped += 2;
  } else {
    const makeNode = loadNode();
    const CASOS = [
      ["10.10.10.0/24", "el rango del informe real"],
      ["1.2.3.4; touch /tmp/lcaudit-pwned", "inyección"],
      ["", "'Otro equipo' con el campo vacío (antes caía a 127.0.0.1)"],
    ];
    for (const [valor, que] of CASOS) {
      try { fs.rmSync(witness, { force: true }); } catch (_) {}
      const { node, run } = makeNode({ scanTarget: "custom", customTarget: valor, scanMode: "standard" });
      const msg = await run();
      const p = msg.payload;
      ok(p.findings.length === 1 && p.findings[0].id === "NET-CFG-ERR",
         `${que}: un único hallazgo NET-CFG-ERR`, JSON.stringify(p.findings.map((f) => f.id)));
      ok(!fs.existsSync(witness), `${que}: nmap no se ha ejecutado`);
      ok(p.scanMeta.scanStatus === "not-run" && p.scanMeta.portSource === "none",
         `${que}: scanMeta dice que no se escaneó`, JSON.stringify(p.scanMeta));
      ok(/NO significa que el equipo esté protegido/.test(p.findings[0].evidence),
         `${que}: la evidencia no deja leer el 0 como "seguro"`);
      ok(node._status && node._status.text === "Configuración incorrecta",
         `${que}: estado del nodo "Configuración incorrecta"`, JSON.stringify(node._status));
    }
    ok(!fs.existsSync("/tmp/lcaudit-pwned"), "la orden inyectada no se ha ejecutado");

    // El valor escrito se devuelve recortado, no entero.
    {
      const largo = "9".repeat(300);
      const { run } = makeNode({ scanTarget: "custom", customTarget: largo, scanMode: "standard" });
      const ev = (await run()).payload.findings[0].evidence;
      ok(!ev.includes(largo) && ev.includes("9".repeat(80)), "el valor indicado se recorta a 80 caracteres");
    }

    // ── 3 · El NET-CFG-ERR de siempre no ha cambiado ────────────────────────────────────────
    console.log("\n── 3 · Lista de puertos vacía: mismo payload que antes ───────────\n");
    {
      try { fs.rmSync(witness, { force: true }); } catch (_) {}
      const { run } = makeNode({ scanTarget: "localhost", scanMode: "custom", customPorts: "  " });
      const p = (await run()).payload;
      ok(p.findings[0].title === "Configuración incorrecta: lista de puertos vacía", "mismo título");
      ok(JSON.stringify(Object.keys(p.scanMeta)) ===
         JSON.stringify(["modulesRun", "portSource", "portsScanned", "portsOpen", "durationMs", "scanMode"]),
         "scanMeta con exactamente los campos de antes", JSON.stringify(Object.keys(p.scanMeta)));
      ok(!fs.existsSync(witness), "nmap no se ha ejecutado");
    }

    // ── 4 · Descubrimiento cortado por tiempo ───────────────────────────────────────────────
    console.log("\n── 4 · Descubrimiento con tiempo agotado ─────────────────────────\n");
    {
      const { comprobarAlcance } = require("../../nodes/audit-network/modules/host-discovery");
      const t0 = Date.now();
      const d = await comprobarAlcance({ target: "10.10.10.5", isLocal: false, timeout: 1500 });
      const secs = (Date.now() - t0) / 1000;
      ok(d.reachable === null && d.method === "error", "resultado ambiguo, no 'no accesible'", JSON.stringify(d));
      ok(d.reason === "timeout", "reason = 'timeout'", JSON.stringify(d.reason));
      ok(/no terminó en el límite de 2 s/.test(d.detail), "el detalle dice que se acabó el tiempo", d.detail);
      ok(!/not root/.test(d.detail), "el aviso de nmap sobre root ya no se presenta como la causa", d.detail);
      ok(secs < 4, `se corta al límite y no espera al proceso (${secs.toFixed(1)} s)`);
    }
  }

  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${passed} ok · ${failed} fallo(s)` + (skipped ? ` · ${skipped} bloque(s) omitido(s)` : "") + "\n");
  process.exit(failed ? 1 : 0);
}

main().catch((err) => { console.error(err); process.exit(1); });
