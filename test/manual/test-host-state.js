"use strict";

/**
 * test-host-state.js — Estado del objetivo en audit-network.
 *
 * Fija el comportamiento que arregla el falso verde: auditar una IP que no
 * existe mostraba "Sin puertos expuestos · SIN RIESGO · 0 puertos abiertos",
 * indistinguible de un equipo real sin servicios expuestos.
 *
 * Hay TRES estados y el dashboard solo representaba dos:
 *   1. alcanzable CON puertos abiertos
 *   2. alcanzable SIN puertos abiertos   ← el único que merece verde
 *   3. NO alcanzable                     ← antes se confundía con el 2
 *
 * Uso:
 *   node test/manual/test-host-state.js            # solo fixtures (offline)
 *   node test/manual/test-host-state.js --live     # + descubrimiento real
 *
 * Sin framework de tests, como el resto de test/manual/*.js. Sale con código 1
 * si algún assert falla.
 */

const fs   = require("fs");
const path = require("path");

const {
  parseDiscoveryXml,
  deriveTargetState,
  buildDiscoveryCmd,
  checkHostReachable,
} = require("../../nodes/audit-network/modules/host-discovery");
const { parseNmapXml } = require("../../nodes/audit-network/modules/nmap-wrapper");

const FIXTURES = path.join(__dirname, "..", "fixtures", "nmap");
const SEP = "─".repeat(72);

let passed = 0;
let failed = 0;
let skipped = 0;

function ok(name, cond, detail) {
  if (cond) {
    passed++;
    console.log(`  ✓ ${name}`);
  } else {
    failed++;
    console.log(`  ✗ ${name}${detail ? "\n      → " + detail : ""}`);
  }
}

function eq(name, actual, expected) {
  ok(name, actual === expected, `esperado ${JSON.stringify(expected)}, obtenido ${JSON.stringify(actual)}`);
}

/**
 * Lee un fixture. Devuelve null si no existe: los fixtures que solo se pueden
 * capturar en otra plataforma (host-unreach solo aparece cuando el SO informa
 * de EHOSTUNREACH, típico de Linux) no deben hacer fallar la suite.
 */
function fixture(name) {
  const file = path.join(FIXTURES, name);
  if (!fs.existsSync(file)) return null;
  return fs.readFileSync(file, "utf8");
}

function skip(name, why) {
  skipped++;
  console.log(`  ⊘ ${name} — ${why}`);
}

// ── 1. Descubrimiento: nmap -sn ───────────────────────────────────────────────

function testDiscovery() {
  console.log(SEP);
  console.log("1 · parseDiscoveryXml() — interpretación de nmap -sn");
  console.log(SEP);

  const up = fixture("sn-up.xml");
  const r1 = parseDiscoveryXml(up);
  eq("host vivo → reachable true", r1.reachable, true);
  eq("host vivo → targetState 'reachable'", deriveTargetState({ reachable: r1.reachable }), "reachable");

  const down = fixture("sn-down.xml");
  const r2 = parseDiscoveryXml(down);
  eq("host inexistente (hosts up=0 down=1) → reachable false", r2.reachable, false);
  eq("host inexistente → targetState 'unreachable'", deriveTargetState({ reachable: r2.reachable }), "unreachable");

  const trunc = fixture("sn-truncated.xml");
  const r3 = parseDiscoveryXml(trunc);
  eq("salida truncada sin <runstats> → reachable null (ambiguo)", r3.reachable, null);
  eq("ambiguo → targetState 'unknown'", deriveTargetState({ reachable: r3.reachable }), "unknown");

  // nmap abortado: emite <runstats> y <hosts up="0" down="0" total="0"/>, que
  // antes se leía como "host caído". Es un fallo de la herramienta, no un dato
  // sobre el objetivo. Caso real de Windows: -e con el nombre amigable del
  // adaptador ("Wi-Fi"), que el nmap de Windows no entiende.
  const errXml = '<?xml version="1.0"?><nmaprun><runstats><finished time="1" ' +
    'timestr="x" elapsed="0.05" summary="s" exit="error" errormsg="I cannot ' +
    'figure out what source address to use for device Wi-Fi, does it even ' +
    'exist?"/><hosts up="0" down="0" total="0"/></runstats></nmaprun>';
  const r5 = parseDiscoveryXml(errXml);
  eq("nmap abortado (exit=error) → reachable null, NUNCA false", r5.reachable, null);
  eq("nmap abortado → targetState 'unknown'", deriveTargetState({ reachable: r5.reachable }), "unknown");
  ok("nmap abortado → se guarda el errormsg para diagnóstico",
     typeof r5.error === "string" && r5.error.includes("Wi-Fi"), String(r5.error));

  eq("XML vacío → ambiguo, nunca false", parseDiscoveryXml("").reachable, null);
  eq("basura → ambiguo, nunca false", parseDiscoveryXml("<nope/>").reachable, null);

  // Ambiguo NO debe cancelar la auditoría: la regla del nodo es
  // skipScan = (targetState === 'unreachable' && !forceScan)
  ok(
    "ambiguo NO cancela el escaneo (solo 'unreachable' lo hace)",
    deriveTargetState({ reachable: null }) !== "unreachable"
  );

  // El motivo es informativo, nunca decide.
  const hu = fixture("sn-host-unreach.xml");
  if (hu === null) {
    skip("reason 'host-unreach' (sin ruta)", "fixture pendiente de capturar en CachyOS");
  } else {
    const r4 = parseDiscoveryXml(hu);
    eq("sin ruta → reachable false", r4.reachable, false);
    eq("sin ruta → reason host-unreach", r4.reason, "host-unreach");
  }

  const cmd = buildDiscoveryCmd("10.0.0.5");
  ok("el comando de descubrimiento es -sn", cmd.includes("nmap -sn"), cmd);
  ok("el descubrimiento NO lleva -Pn (lo anularía)", !cmd.includes("-Pn"), cmd);
  ok("amplía las sondas TCP más allá de 80/443", cmd.includes("-PS22,80,443,8080"), cmd);

  // En Windows os.networkInterfaces() da el nombre amigable ("Wi-Fi"), que el
  // nmap de Windows no entiende: allí el comando sale sin -e.
  const { findInterfaceForTarget } = require("../../nodes/audit-network/modules/nmap-wrapper");
  eq("Windows → sin interfaz para -e", findInterfaceForTarget("192.168.0.30", "win32"), null);
  ok("macOS/Linux → se sigue eligiendo interfaz cuando la hay",
     findInterfaceForTarget("127.0.0.1", "darwin") === null, "localhost nunca lleva -e");
}

// ── 2. Escaneo de puertos ─────────────────────────────────────────────────────

function testPortScan() {
  console.log(SEP);
  console.log("2 · parseNmapXml() — los tres estados");
  console.log(SEP);

  const open = parseNmapXml(fixture("scan-ports-open.xml"));
  ok("host vivo con puertos → al menos 1 puerto abierto", open.length > 0, `obtenidos ${open.length}`);
  ok("todos los puertos devueltos están 'open'", open.every((p) => p.state === "open"));

  const none = parseNmapXml(fixture("scan-no-ports.xml"));
  eq("host vivo sin puertos abiertos → 0 puertos", none.length, 0);

  const dead = parseNmapXml(fixture("scan-unreachable.xml"));
  eq("host inexistente → 0 puertos", dead.length, 0);

  // Sin --open el escaneo conserva el recuento de filtrados y su motivo.
  const deadXml = fixture("scan-unreachable.xml");
  const filtered = deadXml.match(/<extraports\s+state="filtered"\s+count="(\d+)"/);
  ok("sin --open se conserva <extraports state=\"filtered\">", !!filtered, "no encontrado");
  ok("sin --open se conserva el motivo <extrareasons>", /<extrareasons\s+reason="/.test(deadXml));
}

// ── 3. El assert que da nombre al arreglo ─────────────────────────────────────

function testNeverGreenWhenDead() {
  console.log(SEP);
  console.log("3 · Un host inalcanzable NUNCA puede acabar en verde");
  console.log(SEP);

  const deadScan = fixture("scan-unreachable.xml");
  const deadDisc = fixture("sn-down.xml");

  // La señal ANTIGUA (la del escaneo con -Pn) miente: dice "1 host up".
  const lying = deadScan.match(/<hosts\s+up="(\d+)"/);
  ok(
    "el escaneo con -Pn declara 'host up' incluso sobre una IP inexistente (por eso no vale)",
    !!lying && parseInt(lying[1], 10) === 1,
    lying ? lying[0] : "no encontrado"
  );
  ok(
    "y su <status> dice reason=\"user-set\": nmap no comprobó nada",
    /<status\s+state="up"\s+reason="user-set"/.test(deadScan)
  );

  // La señal NUEVA (descubrimiento) acierta.
  const state = deriveTargetState(parseDiscoveryXml(deadDisc));
  eq("targetState derivado del descubrimiento → 'unreachable'", state, "unreachable");
  ok("targetState NUNCA es 'reachable' para el fixture inalcanzable", state !== "reachable");

  // Y el escaneo de ese mismo host no aporta puertos: 0 puertos + unreachable
  // = "no auditado", no "sin riesgo".
  const ports = parseNmapXml(deadScan);
  ok(
    "0 puertos + unreachable ⇒ estado neutro, no verde",
    ports.length === 0 && state === "unreachable"
  );

  // Contraste: 0 puertos + reachable SÍ es el verde legítimo.
  const aliveState = deriveTargetState(parseDiscoveryXml(fixture("sn-up.xml")));
  const alivePorts = parseNmapXml(fixture("scan-no-ports.xml"));
  ok(
    "0 puertos + reachable ⇒ verde legítimo (el estado 2 se conserva)",
    alivePorts.length === 0 && aliveState === "reachable"
  );
}

// ── 4. Dashboard: cómo interpreta el estado ───────────────────────────────────

/**
 * Carga los computed del ui_template de red desde examples/ (fuente de verdad;
 * el flujo instalado es una copia) y los evalúa sobre un payload como el que
 * emite el nodo. Sin Vue: se resuelven como getters sobre un objeto plano, que
 * es exactamente lo que hace Vue con `computed`.
 */
function loadDashboardVm(scanMeta, ports, summary) {
  const file = path.join(__dirname, "..", "..", "examples", "dashboard-network-template.html");
  const html = fs.readFileSync(file, "utf8");
  const from = html.indexOf("<script>\nexport default");
  const to   = html.lastIndexOf("</script>");
  const body = html.slice(from + "<script>".length, to).replace("export default", "return");
  const comp = new Function(body)();          // eslint-disable-line no-new-func

  const vm = Object.assign({}, comp.data(), {
    state: "done",
    auditData: {
      auditType: "network",
      scanMeta,
      summary: summary || { maxSeverity: "info", counts: {} },
      raw: { ports: ports || [] },
      findings: [],
      timestamp: new Date().toISOString(),
    },
  });
  Object.keys(comp.computed).forEach(function (k) {
    Object.defineProperty(vm, k, { get: comp.computed[k].bind(vm), configurable: true });
  });
  return vm;
}

function testDashboard() {
  console.log(SEP);
  console.log("4 · Dashboard — 0 puertos no siempre es verde");
  console.log(SEP);

  // Estado 3: el objetivo no responde. Es el caso que producía el falso verde.
  const dead = loadDashboardVm({
    target: "10.0.0.5", targetState: "unreachable", scanStatus: "not-run",
    portSource: "none", portsOpen: 0, forceScan: false,
    discovery: { method: "nmap-sn", reason: null, detail: "10.0.0.5 no respondió al descubrimiento de red." },
  }, []);

  eq("unreachable → notAudited", dead.notAudited, true);
  ok("badge NUNCA dice 'Sin Riesgo'", dead.riskLabel !== "Sin Riesgo", dead.riskLabel);
  eq("badge dice 'No auditado'", dead.riskLabel, "No auditado");
  eq("badge en gris neutro, no en la clase de severidad", dead.riskClass, "not-audited");
  eq("el contador no muestra un 0 (se leería como resultado)", dead.portCountLabel, "—");
  ok("sale el banner de aviso", !!dead.scanWarn, "no hay banner");
  ok("el banner es neutro, no una alerta de riesgo", dead.scanWarn.neutral === true);
  ok("el aviso nombra el objetivo", dead.scanWarn.title.indexOf("10.0.0.5") >= 0, dead.scanWarn.title);
  ok("explica las causas posibles en lenguaje llano",
    /apagado/.test(dead.scanWarn.desc) && /IP/.test(dead.scanWarn.desc) && /VPN/.test(dead.scanWarn.desc));
  ok("dice explícitamente que 0 hallazgos ≠ seguro", /NO significa/.test(dead.scanWarn.desc));
  ok("propone comprobarlo: ping", /ping 10\.0\.0\.5/.test(dead.scanWarn.desc), dead.scanWarn.desc);

  // Sin ruta: el motivo solo afina el texto, la decisión ya está tomada.
  const noRoute = loadDashboardVm({
    target: "10.0.0.5", targetState: "unreachable", scanStatus: "not-run",
    discovery: { method: "nmap-sn", reason: "host-unreach", detail: "" },
  }, []);
  ok("reason host-unreach → habla de ruta, no de que no conteste",
    /ruta de red/.test(noRoute.scanWarn.desc), noRoute.scanWarn.desc);
  eq("y el estado sigue siendo el mismo", noRoute.riskLabel, "No auditado");

  // Estado 2: alcanzable sin puertos abiertos. El verde legítimo se conserva.
  const clean = loadDashboardVm({
    target: "127.0.0.1", targetState: "reachable", scanStatus: "ok",
    portSource: "nmap", portsOpen: 0, forceScan: false,
    discovery: { method: "local", reason: "localhost", detail: "" },
  }, []);
  eq("reachable + 0 puertos → NO es 'no auditado'", clean.notAudited, false);
  eq("mantiene 'Sin Riesgo'", clean.riskLabel, "Sin Riesgo");
  eq("y muestra el 0", clean.portCountLabel, 0);
  eq("sin banner de aviso", clean.scanWarn, null);

  // Payload viejo (sin targetState): no debe romperse ni volverse neutro.
  const legacy = loadDashboardVm({ target: "127.0.0.1", scanStatus: "ok", portsOpen: 0 }, []);
  eq("payload sin targetState → se asume 'reachable' (compatibilidad)", legacy.targetState, "reachable");
  eq("y sigue pintando el verde de siempre", legacy.riskLabel, "Sin Riesgo");
}

// ── 5. Descubrimiento real (--live) ───────────────────────────────────────────

async function testLive() {
  console.log(SEP);
  console.log("5 · Descubrimiento real (--live)");
  console.log(SEP);

  const targets = [
    { target: "127.0.0.1", isLocal: true,  expect: "reachable"   },
    { target: "127.0.0.1", isLocal: false, expect: "reachable"   },
    { target: "10.0.0.5",  isLocal: false, expect: "unreachable" },
  ];

  for (const t of targets) {
    const d = await checkHostReachable({ target: t.target, isLocal: t.isLocal });
    const state = deriveTargetState(d);
    console.log(
      `  ${t.target.padEnd(12)} local=${String(t.isLocal).padEnd(5)} → ` +
      `${state.padEnd(12)} ${String(d.durationMs + " ms").padEnd(9)} ` +
      `method=${d.method} reason=${d.reason}`
    );
    console.log(`      ${d.detail}`);
    eq(`  ${t.target} (local=${t.isLocal}) → ${t.expect}`, state, t.expect);
  }
}

// ── Runner ────────────────────────────────────────────────────────────────────

(async function main() {
  console.log("\nLoCoAudit — estado del objetivo en audit-network\n");
  testDiscovery();
  testPortScan();
  testNeverGreenWhenDead();
  testDashboard();
  if (process.argv.includes("--live")) {
    await testLive();
  } else {
    console.log(SEP);
    console.log("5 · Descubrimiento real omitido (añade --live para ejecutarlo)");
    console.log(SEP);
  }

  console.log("");
  console.log(`${passed} OK · ${failed} fallos · ${skipped} omitidos`);
  process.exit(failed === 0 ? 0 : 1);
})();
