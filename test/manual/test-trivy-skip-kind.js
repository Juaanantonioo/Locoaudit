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

// Antes devolvía []: cero CVE por no haber mirado se leía igual que cero CVE
// tras analizar. Ahora sale un finding informativo que lo dice.
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

// audit-image.js ya emite un IMG-SCAN-ERR-nnn por imagen fallida: el aviso
// general solo aparece cuando el fallo no trae ese detalle.
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

// El escenario real de CachyOS. Ya no lo decide una lista nuestra de gestores:
// se ejecuta Trivy, Trivy no reconoce la base de datos de paquetes y devuelve
// kind 'os-unsupported'. El estado que verá el dashboard es 'unsupported-manager',
// no un error, y la auditoría no se aborta.
const rootfsArch = {
  skipped: true, kind: "os-unsupported",
  reason: "Trivy no ha detectado la familia del sistema operativo",
};
const estado = systemPackagesSupport("linux", rootfsArch, { enabled: true });
ok(estado === "unsupported-manager",
   `linux + informe sin OS.Family + interruptor activo → "${estado}"`,
   "esperado 'unsupported-manager'");

// Y lo que NO puede pasar: que un informe sin familia de SO acabe contando como
// análisis conseguido. Cero vulnerabilidades del sistema sobre un sistema que
// Trivy no supo leer es el falso verde que todo esto existe para evitar.
ok(estado !== "scanned", "un informe sin OS.Family jamás sale como 'scanned'");

console.log(`\n${passed} pasados · ${failed} fallidos\n`);
process.exit(failed > 0 ? 1 : 0);
