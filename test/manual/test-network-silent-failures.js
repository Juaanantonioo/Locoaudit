"use strict";

/**
 * test-network-silent-failures.js: un fallo de nmap o del cortafuegos nunca puede verse como resultado limpio.
 * Cubre el XML de nmap truncado con código 0, la consulta del cortafuegos que falla, la máscara 0.0.0.0
 * en validarObjetivo y el nombre de interfaz que va al -e. Sustituye lib/executor y os.networkInterfaces.
 * Uso: node test/manual/test-network-silent-failures.js
 */

const os   = require("os");
const path = require("path");

let failed = 0, passed = 0;
function ok(cond, label, detail) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}`); if (detail) console.log(`      ${detail}`); }
}

const ROOT = path.join(__dirname, "../..");
const executor = require(path.join(ROOT, "lib/executor"));

// Respuesta por orden; una función puede lanzar para simular el fallo.
let existen = new Set();
let respuestas = [];
const lanzadas = [];
executor.existeComando = async (cmd) => existen.has(cmd);
executor.ejecutar = async (cmd) => {
  lanzadas.push(cmd);
  for (const [re, r] of respuestas) if (re.test(cmd)) return typeof r === "function" ? r(cmd) : r;
  return "";
};
function falla(stdout, stderr) {
  return () => { throw Object.assign(new Error("Command failed"), { code: 1, stdout: stdout || "", stderr: stderr || "" }); };
}

let interfaces = {};
os.networkInterfaces = () => interfaces;

const { ejecutarNmap, interfazParaObjetivo } = require(path.join(ROOT, "nodes/audit-network/modules/nmap-wrapper"));
const { comandoDescubrimiento } = require(path.join(ROOT, "nodes/audit-network/modules/host-discovery"));
const serviceDetect = require(path.join(ROOT, "nodes/audit-network/modules/service-detect"));
const { validarObjetivo } = require(path.join(ROOT, "nodes/audit-network/modules/network-utils"));
const { normalizarRed } = require(path.join(ROOT, "lib/normalizer"));

const XML_COMPLETO =
  '<?xml version="1.0"?><nmaprun><host><ports>' +
  '<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>' +
  '</ports></host><runstats><finished time="1" exit="success"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>';
const XML_TRUNCADO = '<?xml version="1.0"?><nmaprun><host><ports>';

function auditarRed(config) {
  for (const k of Object.keys(require.cache)) {
    if (k.endsWith(`${path.sep}audit-network${path.sep}audit-network.js`)) delete require.cache[k];
  }
  let handler = null;
  const estados = [];
  const RED = {
    nodes: {
      createNode(n) { n.on = (ev, fn) => { if (ev === "input") handler = fn; }; n.status = (s) => estados.push(s); n.warn = () => {}; n.log = () => {}; },
      registerType(_t, Ctor) { Ctor.call({}, Object.assign({ scanMode: "rapido", scanTarget: "local" }, config)); },
      getNode() { return null; },
    },
    httpAdmin: { get() {}, post() {} },
  };
  require(path.join(ROOT, "nodes/audit-network/audit-network.js"))(RED);
  return new Promise((resolve, reject) => {
    handler({ payload: {} }, (m) => resolve({ p: m.payload, status: estados[estados.length - 1] }), (err) => err && reject(err));
  });
}

(async () => {
  console.log("\n── nmap con código 0 y sin <runstats> ─────────────────────────────\n");
  existen = new Set(["nmap"]);
  respuestas = [[/^nmap /, XML_TRUNCADO]];
  let r = await ejecutarNmap({ target: "127.0.0.1", scanMode: "rapido" });
  ok(r.skipped === true && r.inconclusive === true, "XML truncado → inconclusive, no 0 puertos", JSON.stringify(r).slice(0, 200));
  respuestas = [[/^nmap /, ""]];
  r = await ejecutarNmap({ target: "127.0.0.1", scanMode: "rapido" });
  ok(r.inconclusive === true, "salida vacía → inconclusive", JSON.stringify(r).slice(0, 200));
  respuestas = [[/^nmap /, XML_COMPLETO]];
  r = await ejecutarNmap({ target: "127.0.0.1", scanMode: "rapido" });
  ok(r.skipped === false && r.ports.length === 1, "XML completo sigue dando sus puertos", JSON.stringify(r).slice(0, 200));

  respuestas = [[/^nmap /, XML_TRUNCADO]];
  let { p, status } = await auditarRed({});
  ok(JSON.stringify(p.scanMeta).includes('"scanStatus":"inconclusive"') && p.findings.some((f) => f.id === "NET-SCAN-WARN"),
     "el nodo marca scanStatus inconclusive y avisa con NET-SCAN-WARN", JSON.stringify(p.scanMeta).slice(0, 300));
  ok(status && status.fill !== "green" && /no concluyente/.test(status.text), "el estado del nodo no queda en verde", JSON.stringify(status));

  console.log("\n── Cortafuegos cuya consulta falla ────────────────────────────────\n");
  existen = new Set(["firewall-cmd"]);
  respuestas = [[/firewall-cmd --state/, falla("", "Authorization failed")]];
  let fw = await serviceDetect.detectarFirewall("linux");
  ok(fw.name === "firewalld" && fw.active === null && fw.error, "firewalld sin permiso → active null con error", JSON.stringify(fw));

  respuestas = [[/firewall-cmd --state/, falla("", "not running\n")]];
  fw = await serviceDetect.detectarFirewall("linux");
  ok(fw.name === "firewalld" && fw.active === false, "firewalld que sale con error y dice 'not running' → inactivo", JSON.stringify(fw));

  respuestas = [[/firewall-cmd --state/, "running\n"]];
  fw = await serviceDetect.detectarFirewall("linux");
  ok(fw.active === true, "firewalld en marcha → activo", JSON.stringify(fw));

  existen = new Set(["ufw"]);
  respuestas = [[/ufw\.conf/, falla("", "grep: /etc/ufw/ufw.conf: Permission denied")]];
  fw = await serviceDetect.detectarFirewall("linux");
  ok(fw.name === "ufw" && fw.active === null, "ufw.conf ilegible → active null", JSON.stringify(fw));
  respuestas = [[/ufw\.conf/, "ENABLED=no\n"]];
  fw = await serviceDetect.detectarFirewall("linux");
  ok(fw.active === false, "ufw con ENABLED=no → inactivo", JSON.stringify(fw));

  existen = new Set(["nft"]);
  respuestas = [[/is-active nftables/, falla("inactive\n", "")]];
  fw = await serviceDetect.detectarFirewall("linux");
  ok(fw.active === false, "nftables inactive (sale con código 3) → inactivo", JSON.stringify(fw));

  existen = new Set();
  respuestas = [[/socketfilterfw/, falla("", "No such file")]];
  fw = await serviceDetect.detectarFirewall("darwin");
  ok(fw.name === "alf" && fw.active === null, "ALF que no responde → active null", JSON.stringify(fw));
  respuestas = [[/netsh/, falla("", "acceso denegado")]];
  fw = await serviceDetect.detectarFirewall("win32");
  ok(fw.name === "windows" && fw.active === null, "netsh que falla → active null", JSON.stringify(fw));

  const puerto = [{ port: 22, state: "open", service: "ssh", severity: "medium" }];
  let ev = normalizarRed(puerto, "nmap", { targetIsLocal: true, firewall: { name: "firewalld", active: null, error: "x" } })[0].evidence;
  ok(/no se pudo comprobar/.test(ev) && !/INACTIVO/.test(ev), "la evidencia dice que no se pudo comprobar, no INACTIVO", ev);
  ev = normalizarRed(puerto, "nmap", { targetIsLocal: true, firewall: { name: null, active: null, error: "x" } })[0].evidence;
  ok(/no se pudo comprobar/.test(ev) && !/no se detectó ninguno/.test(ev), "detector caído → no dice 'ninguno instalado'", ev);
  ev = normalizarRed(puerto, "nmap", { targetIsLocal: true, firewall: { name: "ufw", active: false } })[0].evidence;
  ok(/ufw \(INACTIVO\)/.test(ev), "un cortafuegos apagado sigue saliendo como INACTIVO", ev);
  ev = normalizarRed(puerto, "nmap", { targetIsLocal: true, firewall: { name: null, active: false } })[0].evidence;
  ok(/no se detectó ninguno instalado/.test(ev), "sin cortafuegos sigue diciendo que no hay ninguno", ev);

  // El detector entero lanza: el nodo no puede dejarlo en null.
  const original = serviceDetect.detectarFirewall;
  serviceDetect.detectarFirewall = async () => { throw new Error("fallo inesperado"); };
  existen = new Set(["nmap"]);
  respuestas = [[/^nmap /, XML_COMPLETO]];
  ({ p } = await auditarRed({}));
  serviceDetect.detectarFirewall = original;
  const f22 = p.findings.find((f) => /22\/tcp/.test(f.title || ""));
  ok(f22 && /no se pudo comprobar/.test(f22.evidence), "detector que lanza → la evidencia lo dice", f22 && f22.evidence);

  console.log("\n── validarObjetivo con una interfaz de máscara 0.0.0.0 ─────────────\n");
  const ifs = {
    eth0: [{ family: "IPv4", internal: false, address: "192.168.1.5", netmask: "255.255.255.0", cidr: "192.168.1.5/24" }],
    tun0: [{ family: "IPv4", internal: false, address: "10.8.0.2", netmask: "0.0.0.0", cidr: "10.8.0.2/0" }],
  };
  let v = validarObjetivo("8.8.8.8", ifs);
  ok(v.ok === false, "una IP ajena no cuenta como de la propia red por la máscara /0", JSON.stringify(v));
  v = validarObjetivo("192.168.1.20", ifs);
  ok(v.ok === true, "una IP de la red real sigue valiendo", JSON.stringify(v));

  console.log("\n── Nombre de interfaz que va al -e ────────────────────────────────\n");
  interfaces = { "eth0;touch x": [{ family: "IPv4", internal: false, address: "192.168.1.5", netmask: "255.255.255.0" }] };
  ok(interfazParaObjetivo("192.168.1.20", "linux") === null, "un nombre con ';' se descarta");
  ok(!/-e /.test(comandoDescubrimiento("192.168.1.20")), "el descubrimiento no pasa -e con ese nombre", comandoDescubrimiento("192.168.1.20"));
  existen = new Set(["nmap"]);
  respuestas = [[/^nmap /, XML_COMPLETO]];
  lanzadas.length = 0;
  await ejecutarNmap({ target: "192.168.1.20", scanMode: "rapido" });
  ok(lanzadas.length && !/-e /.test(lanzadas[0]) && !/touch/.test(lanzadas[0]), "el escaneo tampoco", lanzadas[0]);
  interfaces = { "en0": [{ family: "IPv4", internal: false, address: "192.168.1.5", netmask: "255.255.255.0" }],
                 "eth0.100": [{ family: "IPv4", internal: false, address: "10.0.0.5", netmask: "255.255.255.0" }] };
  ok(interfazParaObjetivo("192.168.1.20", "linux") === "en0", "un nombre normal se sigue usando");
  ok(interfazParaObjetivo("10.0.0.9", "linux") === "eth0.100", "y uno con VLAN (eth0.100) también");

  console.log(`\n${passed} pasados · ${failed} fallidos`);
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
