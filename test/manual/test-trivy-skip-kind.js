"use strict";

/**
 * test-trivy-skip-kind.js — Naturaleza (`kind`) de un `skipped` de trivy-fs.
 * Quien llama decide por `kind`, no por el texto de `reason`, que cambia con la plataforma.
 *
 * Uso:
 *   node test/manual/test-trivy-skip-kind.js
 */

const { normalizeHost, normalizeImage } = require("../../lib/normalizer");
const { systemPackagesSupport } = require("../../lib/trivy-rootfs");

let failed = 0;
let passed = 0;

function ok(cond, label, detail) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}`); if (detail) console.log(`      ${detail}`); }
}

console.log("\n── 1 · Cada skipped declara su naturaleza ────────────────────────\n");

// Formas exactas que devuelve trivy-fs.js, con su kind esperado.
const FORMAS = [
  { reason: "trivy not installed",                        kind: "not-installed", fatal: true  },
  { reason: "rootfs solo aplica en Linux",                kind: "unsupported",   fatal: false },
  { reason: "Trivy no soporta pacman",                    kind: "unsupported",   fatal: false },
  { reason: "trivy failed: exit status 2",                kind: "error",         fatal: true  },
  { reason: "trivy output is not valid JSON",             kind: "error",         fatal: true  },
  { reason: "Trivy no pudo recorrer /Users/x/Library…",   kind: "error",         fatal: true, walkError: true },
  { reason: "no se pudo leer el home /home/x: EACCES",    kind: "error",         fatal: true  },
];

// Réplica de la decisión de audit-host.js: por kind, NUNCA por reason.
function esFatal(res) {
  return res.kind === "not-installed" || res.kind === "error";
}

for (const forma of FORMAS) {
  const res = Object.assign({ skipped: true }, forma);
  ok(esFatal(res) === forma.fatal,
     `"${forma.reason.slice(0, 42)}…" → kind ${forma.kind} · ${forma.fatal ? "fatal" : "la auditoría continúa"}`,
     `esFatal() devolvió ${esFatal(res)}`);
}

console.log("\n── 2 · Los dos 'unsupported' son indistinguibles por kind ────────\n");

const macos = { skipped: true, kind: "unsupported", reason: "rootfs solo aplica en Linux" };
const arch  = { skipped: true, kind: "unsupported", reason: "Trivy no soporta pacman" };

ok(macos.kind === arch.kind, "misma naturaleza pese a textos distintos");
ok(macos.reason !== arch.reason, "el texto se conserva para poder mostrarlo al usuario");
ok(!esFatal(macos) && !esFatal(arch), "ninguno aborta la auditoría");

console.log("\n── 3 · Un skipped no rompe el normalizador y queda declarado ─────\n");

// Un escaneo omitido deja un finding informativo, para no confundirse con cero CVE.
for (const forma of FORMAS) {
  const res = Object.assign({ skipped: true }, forma);
  let findings, error = null;
  try { findings = normalizeHost({ trivy: res }, { platform: "linux", pkgManager: "pacman" }); }
  catch (e) { error = e; }

  ok(!error && Array.isArray(findings) && findings.length === 1,
     `normalizeHost({trivy: ${forma.kind}}) → 1 finding informativo, sin lanzar`,
     error ? `lanzó: ${error.message}` : `devolvió ${JSON.stringify(findings)}`);
  ok(!error && findings[0].id === "HOST-CVE-SKIP" && findings[0].severity === "info",
     `${forma.kind} → HOST-CVE-SKIP con severidad info`,
     !error && `${findings[0].id} / ${findings[0].severity}`);
  ok(!error && String(findings[0].evidence).includes(forma.reason),
     `${forma.kind} → el motivo real llega a la evidencia`);
}

console.log("\n── 3b · En imagen, el aviso general no duplica los errores por imagen ─\n");

// El aviso general solo aparece si el fallo no trae ya su IMG-SCAN-ERR-nnn.
const conFallos = normalizeImage(
  { skipped: true, reason: "all image scans failed", failed: [{ ref: "nginx:latest", error: "TIMEOUT" }] },
  "trivy"
);
ok(conFallos.length === 0,
   "IMG-CVE con failed[] → sin aviso general (ya hay uno por imagen)",
   `devolvió ${JSON.stringify(conFallos.map((f) => f.id))}`);

const sinFallos = normalizeImage({ skipped: true, kind: "not-installed", reason: "trivy not installed" }, "trivy");
ok(sinFallos.length === 1 && sinFallos[0].id === "IMG-CVE-SKIP",
   "IMG-CVE sin failed[] → IMG-CVE-SKIP",
   `devolvió ${JSON.stringify(sinFallos.map((f) => f.id))}`);
ok(sinFallos.length === 1 && sinFallos[0].severity === "info",
   "IMG-CVE-SKIP con severidad info");

console.log("\n── 4 · El caso pacman llega hasta el estado de alcance ───────────\n");

// Trivy no reconoce los paquetes (CachyOS): 'os-unsupported' → 'unsupported-manager', sin abortar.
const rootfsArch = {
  skipped: true, kind: "os-unsupported",
  reason: "Trivy no ha detectado la familia del sistema operativo",
};
const estado = systemPackagesSupport("linux", rootfsArch, { enabled: true });
ok(estado === "unsupported-manager",
   `linux + informe sin OS.Family + interruptor activo → "${estado}"`,
   "esperado 'unsupported-manager'");

// Un informe sin familia de SO no cuenta como análisis conseguido.
ok(estado !== "scanned", "un informe sin OS.Family jamás sale como 'scanned'");

console.log(`\n${passed} pasados · ${failed} fallidos\n`);
process.exit(failed > 0 ? 1 : 0);
