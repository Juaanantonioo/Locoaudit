"use strict";

/**
 * test-image-scan-failures.js: un fallo de Trivy o de docker inspect nunca puede verse como imagen limpia.
 * Cubre el informe sin SO ni paquetes (NO_OS), IMG-SCAN-ERR como comprobación no realizada con su
 * estado de nodo, y el JSON ilegible de docker inspect. Simula Docker y Trivy sustituyendo lib/executor.
 * Uso: node test/manual/test-image-scan-failures.js
 */

const path = require("path");

let failed = 0, passed = 0;
function ok(cond, label, detail) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}`); if (detail) console.log(`      ${detail}`); }
}

const ROOT = path.join(__dirname, "../..");
const executor = require(path.join(ROOT, "lib/executor"));

// Informe de Trivy por referencia y salida de docker inspect por formato.
let informes = {};
let contenedores = "";
let inspectOut = {};
executor.existeComando = async (cmd) => cmd === "docker" || cmd === "trivy";
executor.ejecutar = async (cmd) => {
  if (cmd.startsWith("docker info")) return "27.0.0";
  if (cmd.startsWith("docker images")) return "id1|nginx|1.21|10MB|2024\nid2|scratch-app|1|2MB|2024";
  if (cmd.startsWith("docker ps")) return contenedores;
  if (cmd.startsWith("docker inspect")) {
    for (const [k, v] of Object.entries(inspectOut)) if (cmd.includes(k)) return v;
    return "";
  }
  if (cmd.startsWith("trivy --version")) return "Version: 0.50.0";
  if (cmd.startsWith("trivy image")) {
    const ref = cmd.split(" ").pop();
    return JSON.stringify(Object.assign({ ArtifactName: ref }, informes[ref] || {}));
  }
  throw new Error("orden inesperada: " + cmd);
};

const CON_OS = { Metadata: { OS: { Family: "debian", Name: "12" } }, Results: [] };
const SIN_NADA = { Metadata: {}, Results: [] };
const OS_NONE = { Metadata: { OS: { Family: "none" } }, Results: [{ Target: "x", Class: "os-pkgs" }] };
// Binario Go en una imagen distroless: sin SO, pero con paquetes de lenguaje.
const DISTROLESS = { Metadata: {}, Results: [{ Target: "app", Class: "lang-pkgs", Type: "gobinary",
  Packages: [{ Name: "golang.org/x/net", Version: "0.1.0" }] }] };

function auditar(config) {
  for (const k of Object.keys(require.cache)) {
    if (k.includes(`${path.sep}nodes${path.sep}audit-image${path.sep}`)) delete require.cache[k];
  }
  let handler = null;
  const estados = [];
  const RED = {
    nodes: {
      createNode(n) { n.on = (ev, fn) => { if (ev === "input") handler = fn; }; n.status = (s) => estados.push(s); n.warn = () => {}; n.log = () => {}; },
      registerType(_t, Ctor) { Ctor.call({}, Object.assign({ scanMode: "local" }, config)); },
      getNode() { return null; },
    },
    util: { evaluateNodeProperty: (v) => v },
    httpAdmin: { get() {}, post() {} },
  };
  require(path.join(ROOT, "nodes/audit-image/audit-image.js"))(RED);
  return new Promise((resolve, reject) => {
    handler({ payload: {} }, (m) => resolve({ p: m.payload, status: estados[estados.length - 1] }), (err) => err && reject(err));
  });
}

(async () => {
  console.log("\n── Informe de Trivy sin SO ni paquetes (NO_OS) ────────────────────\n");
  informes = { "nginx:1.21": CON_OS, "scratch-app:1": SIN_NADA };
  let { p, status } = await auditar({});
  let estado = Object.fromEntries(p.raw.docker.images.map((i) => [`${i.repository}:${i.tag}`, i.cveScan]));
  ok(estado["scratch-app:1"] === "fallida", "la imagen sin SO ni paquetes queda como fallida, no limpia", JSON.stringify(estado));
  ok(estado["nginx:1.21"] === "analizada", "la imagen con SO sigue analizada", JSON.stringify(estado));
  const err = p.findings.find((f) => /^IMG-SCAN-ERR/.test(f.id));
  ok(err && /sistema operativo/.test(err.evidence) && !/^NO_OS/.test(err.evidence),
     "IMG-SCAN-ERR explica el caso NO_OS en lenguaje claro", err && err.evidence);

  informes = { "nginx:1.21": CON_OS, "scratch-app:1": OS_NONE };
  ({ p } = await auditar({}));
  estado = Object.fromEntries(p.raw.docker.images.map((i) => [`${i.repository}:${i.tag}`, i.cveScan]));
  ok(estado["scratch-app:1"] === "fallida", 'Family "none" y sin paquetes también es fallo', JSON.stringify(estado));

  informes = { "nginx:1.21": CON_OS, "scratch-app:1": DISTROLESS };
  ({ p } = await auditar({}));
  estado = Object.fromEntries(p.raw.docker.images.map((i) => [`${i.repository}:${i.tag}`, i.cveScan]));
  ok(estado["scratch-app:1"] === "analizada", "sin SO pero con paquetes de lenguaje (distroless) sí se da por analizada", JSON.stringify(estado));

  console.log("\n── IMG-SCAN-ERR cuenta como comprobación no realizada ─────────────\n");
  informes = { "nginx:1.21": SIN_NADA, "scratch-app:1": SIN_NADA };
  ({ p, status } = await auditar({}));
  const errs = p.findings.filter((f) => /^IMG-SCAN-ERR/.test(f.id));
  ok(errs.length === 2 && errs.every((f) => f.skipped === true && f.kind === "error"),
     "cada IMG-SCAN-ERR lleva skipped:true y kind:error", JSON.stringify(errs.map((f) => [f.id, f.skipped, f.kind])));
  ok(p.scanMeta.checksSkipped && p.scanMeta.checksSkipped.failed === 2,
     "fallan todas → aparecen en checksSkipped", JSON.stringify(p.scanMeta.checksSkipped && p.scanMeta.checksSkipped.failed));
  ok(status && status.fill === "yellow" && status.shape === "ring",
     "modo local con imágenes fallidas → estado amarillo en anillo", JSON.stringify(status));

  informes = { "nginx:1.21": CON_OS, "scratch-app:1": CON_OS };
  ({ status } = await auditar({}));
  ok(status && status.fill === "green" && status.shape === "dot", "sin fallos el estado sigue verde", JSON.stringify(status));

  informes = { "nginx:latest": SIN_NADA };
  ({ p, status } = await auditar({ scanMode: "specific", imageRef: "nginx:latest" }));
  ok(p.scanMeta.checksSkipped && p.scanMeta.checksSkipped.failed === 1,
     "modo específico: el fallo llega a checksSkipped", JSON.stringify(p.scanMeta.checksSkipped));
  ok(status && status.fill === "yellow" && status.shape === "ring",
     "modo específico con fallo → amarillo en anillo", JSON.stringify(status));

  informes = { "nginx:latest": CON_OS };
  ({ status } = await auditar({ scanMode: "specific", imageRef: "nginx:latest" }));
  ok(status && status.fill === "green", "modo específico sin fallos sigue verde", JSON.stringify(status));

  console.log("\n── docker inspect con JSON ilegible ───────────────────────────────\n");
  informes = { "nginx:1.21": CON_OS, "scratch-app:1": CON_OS };
  contenedores = "c1|web|nginx:1.21|Up 2 hours|0.0.0.0:80->80/tcp";
  inspectOut = { ".Config.User": "app", ".Config.Env": "{roto", ".HostConfig.Binds": "[\"/var/run/docker.sock:/var/run/docker.sock\"" };
  ({ p } = await auditar({}));
  let cfg = p.findings.find((f) => /^IMG-CFG-SKIP/.test(f.id));
  ok(cfg && cfg.skipped === true && /variables de entorno/.test(cfg.evidence) && /montajes/.test(cfg.evidence),
     "Env y Binds ilegibles → IMG-CFG-SKIP que los nombra", cfg && cfg.evidence);

  inspectOut = { ".Config.User": "app", ".Config.Env": "[\"PATH=/bin\"]", ".HostConfig.Binds": "null" };
  ({ p } = await auditar({}));
  cfg = p.findings.find((f) => /^IMG-CFG-SKIP/.test(f.id));
  ok(!cfg, "Env válido y Binds null → sin IMG-CFG-SKIP", cfg && cfg.evidence);

  console.log(`\n${passed} pasados · ${failed} fallidos`);
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
