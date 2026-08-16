"use strict";

/**
 * test-trivy-skip-kind.js — Naturaleza de un `skipped` de trivy-fs.
 *
 * Un `skipped` no siempre es un fallo, y quien llama tenía que distinguirlo
 * comparando el TEXTO de `reason`. Ese texto cambia con la plataforma:
 *
 *   macOS → "rootfs solo aplica en Linux"
 *   Arch  → "Trivy no soporta pacman"
 *
 * Son el mismo caso (esta combinación no se puede analizar) con dos redacciones,
 * así que la comparación de strings los mandaba a la rama de error y abortaba la
 * auditoría entera. Ahora cada `skipped` declara su naturaleza en `kind`.
 *
 * Uso:
 *   node test/manual/test-trivy-skip-kind.js
 */

const { normalizeHost } = require("../../lib/normalizer");
const { systemPackagesSupport } = require("../../nodes/audit-host/modules/trivy-fs");

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

console.log("\n── 3 · Un skipped no rompe el normalizador ───────────────────────\n");

for (const forma of FORMAS) {
  const res = Object.assign({ skipped: true }, forma);
  let findings, error = null;
  try { findings = normalizeHost({ trivy: res }, { platform: "linux", pkgManager: "pacman" }); }
  catch (e) { error = e; }
  ok(!error && Array.isArray(findings) && findings.length === 0,
     `normalizeHost({trivy: ${forma.kind}}) → [] sin lanzar`,
     error ? `lanzó: ${error.message}` : `devolvió ${JSON.stringify(findings)}`);
}

console.log("\n── 4 · El caso pacman llega hasta el estado de alcance ───────────\n");

// El escenario real de CachyOS: el gate devuelve 'unsupported' y el estado que
// verá el dashboard es 'unsupported-manager', no un error.
const estado = systemPackagesSupport("linux", "pacman", { enabled: true, result: arch });
ok(estado === "unsupported-manager",
   `linux + pacman + interruptor activo → "${estado}"`,
   "esperado 'unsupported-manager'");

console.log(`\n${passed} pasados · ${failed} fallidos\n`);
process.exit(failed > 0 ? 1 : 0);
