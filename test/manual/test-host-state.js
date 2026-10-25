"use strict";

/**
 * test-host-state.js — Estado del objetivo en audit-network.
 * Tres estados: alcanzable con puertos, alcanzable sin puertos (el único verde) y no alcanzable.
 *
 * Uso:
 *   node test/manual/test-host-state.js            # solo fixtures (offline)
 *   node test/manual/test-host-state.js --live     # + descubrimiento real
 *
 * Sin framework; sale con código 1 si algún assert falla.
 */

const fs   = require("fs");
const path = require("path");

const {
  leerXmlDescubrimiento,
  deducirEstadoObjetivo,
  comandoDescubrimiento,
  comprobarAlcance,
} = require("../../nodes/audit-network/modules/host-discovery");
const { leerXmlNmap } = require("../../nodes/audit-network/modules/nmap-wrapper");

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

/** Lee un fixture, o null si no existe (algunos solo se capturan en otra plataforma). */
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
  console.log("1 · leerXmlDescubrimiento() — interpretación de nmap -sn");
  console.log(SEP);

  const up = fixture("sn-up.xml");
  const r1 = leerXmlDescubrimiento(up);
  eq("host vivo → reachable true", r1.reachable, true);
  eq("host vivo → targetState 'reachable'", deducirEstadoObjetivo({ reachable: r1.reachable }), "reachable");

  const down = fixture("sn-down.xml");
  const r2 = leerXmlDescubrimiento(down);
  eq("host inexistente (hosts up=0 down=1) → reachable false", r2.reachable, false);
  eq("host inexistente → targetState 'unreachable'", deducirEstadoObjetivo({ reachable: r2.reachable }), "unreachable");

  const trunc = fixture("sn-truncated.xml");
  const r3 = leerXmlDescubrimiento(trunc);
  eq("salida truncada sin <runstats> → reachable null (ambiguo)", r3.reachable, null);
  eq("ambiguo → targetState 'unknown'", deducirEstadoObjetivo({ reachable: r3.reachable }), "unknown");

  // nmap abortado (hosts total="0"): es un fallo de la herramienta, no un host caído.
  const errXml = '<?xml version="1.0"?><nmaprun><runstats><finished time="1" ' +
    'timestr="x" elapsed="0.05" summary="s" exit="error" errormsg="I cannot ' +
    'figure out what source address to use for device Wi-Fi, does it even ' +
    'exist?"/><hosts up="0" down="0" total="0"/></runstats></nmaprun>';
  const r5 = leerXmlDescubrimiento(errXml);
  eq("nmap abortado (exit=error) → reachable null, NUNCA false", r5.reachable, null);
  eq("nmap abortado → targetState 'unknown'", deducirEstadoObjetivo({ reachable: r5.reachable }), "unknown");
  ok("nmap abortado → se guarda el errormsg para diagnóstico",
     typeof r5.error === "string" && r5.error.includes("Wi-Fi"), String(r5.error));

  eq("XML vacío → ambiguo, nunca false", leerXmlDescubrimiento("").reachable, null);
  eq("basura → ambiguo, nunca false", leerXmlDescubrimiento("<nope/>").reachable, null);

  // Ambiguo no cancela: skipScan = (targetState === 'unreachable' && !forceScan)
  ok(
    "ambiguo NO cancela el escaneo (solo 'unreachable' lo hace)",
    deducirEstadoObjetivo({ reachable: null }) !== "unreachable"
  );

  // El motivo es informativo, nunca decide.
  const hu = fixture("sn-host-unreach.xml");
  if (hu === null) {
    skip("reason 'host-unreach' (sin ruta)", "fixture pendiente de capturar en CachyOS");
  } else {
    const r4 = leerXmlDescubrimiento(hu);
    eq("sin ruta → reachable false", r4.reachable, false);
    eq("sin ruta → reason host-unreach", r4.reason, "host-unreach");
  }

  const cmd = comandoDescubrimiento("10.0.0.5");
  ok("el comando de descubrimiento es -sn", cmd.includes("nmap -sn"), cmd);
  ok("el descubrimiento NO lleva -Pn (lo anularía)", !cmd.includes("-Pn"), cmd);
  ok("amplía las sondas TCP más allá de 80/443", cmd.includes("-PS22,80,443,8080"), cmd);

  // En Windows el comando sale sin -e: nmap no entiende el nombre amigable del adaptador.
  const { interfazParaObjetivo } = require("../../nodes/audit-network/modules/nmap-wrapper");
  eq("Windows → sin interfaz para -e", interfazParaObjetivo("192.168.0.30", "win32"), null);
  ok("macOS/Linux → se sigue eligiendo interfaz cuando la hay",
     interfazParaObjetivo("127.0.0.1", "darwin") === null, "localhost nunca lleva -e");
}

// ── 2. Escaneo de puertos ─────────────────────────────────────────────────────

function testPortScan() {
  console.log(SEP);
  console.log("2 · leerXmlNmap() — los tres estados");
  console.log(SEP);

  const open = leerXmlNmap(fixture("scan-ports-open.xml"));
  ok("host vivo con puertos → al menos 1 puerto abierto", open.length > 0, `obtenidos ${open.length}`);
  ok("todos los puertos devueltos están 'open'", open.every((p) => p.state === "open"));

  const none = leerXmlNmap(fixture("scan-no-ports.xml"));
  eq("host vivo sin puertos abiertos → 0 puertos", none.length, 0);

  const dead = leerXmlNmap(fixture("scan-unreachable.xml"));
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
  const state = deducirEstadoObjetivo(leerXmlDescubrimiento(deadDisc));
  eq("targetState derivado del descubrimiento → 'unreachable'", state, "unreachable");
  ok("targetState NUNCA es 'reachable' para el fixture inalcanzable", state !== "reachable");

  // 0 puertos + unreachable = "no auditado", no "sin riesgo".
  const ports = leerXmlNmap(deadScan);
  ok(
    "0 puertos + unreachable ⇒ estado neutro, no verde",
    ports.length === 0 && state === "unreachable"
  );

  // Contraste: 0 puertos + reachable SÍ es el verde legítimo.
  const aliveState = deducirEstadoObjetivo(leerXmlDescubrimiento(fixture("sn-up.xml")));
  const alivePorts = leerXmlNmap(fixture("scan-no-ports.xml"));
  ok(
    "0 puertos + reachable ⇒ verde legítimo (el estado 2 se conserva)",
    alivePorts.length === 0 && aliveState === "reachable"
  );
}

// ── 4. Dashboard: cómo interpreta el estado ───────────────────────────────────

/** Evalúa los computed del ui_template de red (examples/) como getters, sin Vue. */
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

  eq("unreachable → notAudited", dead.noAuditado, true);
  ok("badge NUNCA dice 'Sin Riesgo'", dead.etiquetaRiesgo !== "Sin Riesgo", dead.etiquetaRiesgo);
  eq("badge dice 'No auditado'", dead.etiquetaRiesgo, "No auditado");
  eq("badge en gris neutro, no en la clase de severidad", dead.claseRiesgo, "not-audited");
  eq("el contador no muestra un 0 (se leería como resultado)", dead.etiquetaNumPuertos, "—");
  ok("sale el banner de aviso", !!dead.avisoEscaneo, "no hay banner");
  ok("el banner es neutro, no una alerta de riesgo", dead.avisoEscaneo.neutral === true);
  ok("el aviso nombra el objetivo", dead.avisoEscaneo.title.indexOf("10.0.0.5") >= 0, dead.avisoEscaneo.title);
  ok("explica las causas posibles en lenguaje llano",
    /apagado/.test(dead.avisoEscaneo.desc) && /IP/.test(dead.avisoEscaneo.desc) && /VPN/.test(dead.avisoEscaneo.desc));
  ok("dice explícitamente que 0 hallazgos ≠ seguro", /NO significa/.test(dead.avisoEscaneo.desc));
  ok("propone comprobarlo: ping", /ping 10\.0\.0\.5/.test(dead.avisoEscaneo.desc), dead.avisoEscaneo.desc);

  // Sin ruta: el motivo solo afina el texto, la decisión ya está tomada.
  const noRoute = loadDashboardVm({
    target: "10.0.0.5", targetState: "unreachable", scanStatus: "not-run",
    discovery: { method: "nmap-sn", reason: "host-unreach", detail: "" },
  }, []);
  ok("reason host-unreach → habla de ruta, no de que no conteste",
    /ruta de red/.test(noRoute.avisoEscaneo.desc), noRoute.avisoEscaneo.desc);
  eq("y el estado sigue siendo el mismo", noRoute.etiquetaRiesgo, "No auditado");

  // Estado 2: alcanzable sin puertos abiertos. El verde legítimo se conserva.
  const clean = loadDashboardVm({
    target: "127.0.0.1", targetState: "reachable", scanStatus: "ok",
    portSource: "nmap", portsOpen: 0, forceScan: false,
    discovery: { method: "local", reason: "localhost", detail: "" },
  }, []);
  eq("reachable + 0 puertos → NO es 'no auditado'", clean.noAuditado, false);
  eq("mantiene 'Sin Riesgo'", clean.etiquetaRiesgo, "Sin Riesgo");
  eq("y muestra el 0", clean.etiquetaNumPuertos, 0);
  eq("sin banner de aviso", clean.avisoEscaneo, null);

  // Payload viejo (sin targetState): no debe romperse ni volverse neutro.
  const legacy = loadDashboardVm({ target: "127.0.0.1", scanStatus: "ok", portsOpen: 0 }, []);
  eq("payload sin targetState → se asume 'reachable' (compatibilidad)", legacy.estadoObjetivo, "reachable");
  eq("y sigue pintando el verde de siempre", legacy.etiquetaRiesgo, "Sin Riesgo");
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
    const d = await comprobarAlcance({ target: t.target, isLocal: t.isLocal });
    const state = deducirEstadoObjetivo(d);
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
