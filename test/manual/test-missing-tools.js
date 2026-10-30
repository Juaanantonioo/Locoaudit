"use strict";

/**
 * test-missing-tools.js: si falta una herramienta obligatoria, el nodo falla y no envía nada al dashboard.
 * Cubre Nmap en audit-network y Docker (ausente o parado) y Trivy en audit-image, en los dos modos.
 * Sustituye lib/executor. Uso: node test/manual/test-missing-tools.js
 */

const path = require("path");

let failed = 0, passed = 0;
function ok(cond, label, detail) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}`); if (detail) console.log(`      ${detail}`); }
}

const ROOT = path.join(__dirname, "../..");
const executor = require(path.join(ROOT, "lib/executor"));

let existen = new Set();
let dockerParado = false;
executor.existeComando = async (cmd) => existen.has(cmd);
executor.ejecutar = async (cmd) => {
  if (cmd.startsWith("docker info")) {
    if (dockerParado) throw new Error("Cannot connect to the Docker daemon");
    return "27.0.0";
  }
  if (cmd.startsWith("docker images")) return "id1|nginx|1.21|10MB|2024";
  if (cmd.startsWith("docker ps")) return "";
  if (cmd.startsWith("trivy --version")) return "Version: 0.50.0";
  if (cmd.startsWith("trivy image")) {
    const ref = cmd.split(" ").pop();
    return JSON.stringify({ ArtifactName: ref, Metadata: { OS: { Family: "debian", Name: "12" } }, Results: [] });
  }
  return "";
};

// Lanza el nodo y devuelve { payload, error, status }: payload solo si llegó a enviarse.
function lanzar(nodo, config) {
  for (const k of Object.keys(require.cache)) {
    if (k.includes(`${path.sep}nodes${path.sep}${nodo}${path.sep}`)) delete require.cache[k];
  }
  let handler = null;
  let status = null;
  const RED = {
    nodes: {
      createNode(n) { n.on = (ev, fn) => { if (ev === "input") handler = fn; }; n.status = (s) => { status = s; }; n.warn = () => {}; n.log = () => {}; },
      registerType(_t, Ctor) { Ctor.call({}, config); },
      getNode() { return null; },
    },
    httpAdmin: { get() {}, post() {} },
    util: { evaluateNodeProperty: (v) => v },
  };
  require(path.join(ROOT, `nodes/${nodo}/${nodo}.js`))(RED);
  return new Promise((resolve) => {
    let payload = null;
    handler({ payload: {} }, (m) => { payload = m.payload; }, (err) => resolve({ payload, error: err || null, status }));
  });
}

(async () => {
  console.log("\n── audit-network sin Nmap ─────────────────────────────────────────\n");
  existen = new Set();
  let r = await lanzar("audit-network", { scanMode: "quick", scanTarget: "local" });
  ok(r.error && /Nmap/.test(r.error.message) && /nmap --version/.test(r.error.message), "falla con las instrucciones de instalación", String(r.error && r.error.message));
  ok(r.payload === null, "no envía resultado al dashboard");
  ok(r.status && r.status.fill === "red", "estado en rojo", JSON.stringify(r.status));

  console.log("\n── audit-image (local) sin Docker ─────────────────────────────────\n");
  existen = new Set(["trivy"]);
  r = await lanzar("audit-image", { scanMode: "local" });
  ok(r.error && /Docker no se encontró instalado/.test(r.error.message), "falla indicando que Docker no está instalado", String(r.error && r.error.message));
  ok(r.payload === null, "no envía resultado al dashboard");
  ok(r.status && r.status.fill === "red", "estado en rojo", JSON.stringify(r.status));

  console.log("\n── audit-image (local) con Docker parado ──────────────────────────\n");
  existen = new Set(["docker", "trivy"]);
  dockerParado = true;
  r = await lanzar("audit-image", { scanMode: "local" });
  ok(r.error && /servicio no responde/.test(r.error.message), "falla indicando que el servicio no responde", String(r.error && r.error.message));
  ok(r.payload === null, "no envía resultado al dashboard");
  dockerParado = false;

  console.log("\n── audit-image (local) sin Trivy ──────────────────────────────────\n");
  existen = new Set(["docker"]);
  r = await lanzar("audit-image", { scanMode: "local" });
  ok(r.error && /Trivy/.test(r.error.message), "falla indicando que falta Trivy", String(r.error && r.error.message));
  ok(r.payload === null, "no envía resultado al dashboard");

  console.log("\n── audit-image (local) sin Trivy pero con el análisis desactivado ─\n");
  r = await lanzar("audit-image", { scanMode: "local", enableTrivy: false });
  ok(!r.error && r.payload && r.payload.findings.some((f) => f.id === "IMG-TRIVY-SKIP" && f.kind === "disabled"), "no falla: queda como desactivado a propósito",
     String(r.error && r.error.message));

  console.log("\n── audit-image (imagen específica) sin Trivy ──────────────────────\n");
  existen = new Set();
  r = await lanzar("audit-image", { scanMode: "specific", imageRef: "nginx:latest", imageRefType: "str" });
  ok(r.error && /Trivy/.test(r.error.message), "falla indicando que falta Trivy", String(r.error && r.error.message));
  ok(r.payload === null, "no envía resultado al dashboard");

  console.log("\n── audit-image (imagen específica) con Trivy ──────────────────────\n");
  existen = new Set(["trivy"]);
  r = await lanzar("audit-image", { scanMode: "specific", imageRef: "nginx:latest", imageRefType: "str" });
  ok(!r.error && r.payload && r.payload.auditType === "image", "con Trivy sigue funcionando sin Docker", String(r.error && r.error.message));

  console.log(`\n${passed} pasados · ${failed} fallidos`);
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
