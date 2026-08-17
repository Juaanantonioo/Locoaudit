"use strict";

/**
 * test-lynis-skip-kind.js — Naturaleza de un `skipped` de lynis.js.
 *
 * Mismo defecto que tenía trivy-fs.js antes de `kind`: el gate de audit-host.js
 * trataba CUALQUIER lynis.skipped como fatal y abortaba con done(err) antes del
 * send(msg), así que el dashboard no recibía payload y se quedaba enseñando la
 * ejecución anterior. Y el mensaje decía "no está instalado" en los cuatro
 * casos, mandando al usuario a reinstalar una herramienta que ya tiene.
 *
 * El caso que lo hacía visible: en Windows sin WSL no hay binario de Lynis, así
 * que el módulo caía en "not installed" y abortaba la auditoría entera — siendo
 * un límite conocido y documentado en CLAUDE.md, no un olvido de instalación.
 *
 * Uso:
 *   node test/manual/test-lynis-skip-kind.js
 */

const { runLynis } = require("../../nodes/audit-host/modules/lynis");
const { fromLynisRaw } = require("../../lib/normalizer");

let failed = 0;
let passed = 0;

function ok(cond, label, detail) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}`); if (detail) console.log(`      ${detail}`); }
}

console.log("\n── 1 · Cada skipped declara su naturaleza ────────────────────────\n");

// Formas exactas que devuelve lynis.js, con su kind esperado.
const FORMAS = [
  { reason: "Lynis no funciona en Windows sin WSL",          kind: "unsupported",   fatal: false },
  { reason: "lynis not installed",                           kind: "not-installed", fatal: true  },
  { reason: "Lynis superó el límite de 180 s sin terminar",  kind: "timeout",       fatal: true  },
  { reason: "lynis failed: Command failed: lynis audit…",    kind: "error",         fatal: true  },
  { reason: "lynis report not found at /tmp/… nor /var/log/…", kind: "error",       fatal: true  },
  { reason: "cannot read /var/log/lynis-report.dat: EACCES", kind: "error",         fatal: true  },
];

// Réplica de la decisión de audit-host.js: por kind, NUNCA por reason.
function esFatal(res) {
  return res.kind === "not-installed" || res.kind === "timeout" || res.kind === "error";
}

for (const forma of FORMAS) {
  const res = Object.assign({ skipped: true }, forma);
  ok(esFatal(res) === forma.fatal,
     `"${forma.reason.slice(0, 44)}…" → kind ${forma.kind} · ${forma.fatal ? "fatal" : "la auditoría continúa"}`,
     `esFatal() devolvió ${esFatal(res)}`);
}

console.log("\n── 2 · 'unsupported' se produce de verdad, no solo se etiqueta ───\n");

// El caso no existía en el módulo: en win32 se caía en commandExists → "not
// installed". La comprobación de plataforma va ANTES, así que hay que poder
// obtenerlo sin tener Lynis instalado ni estar en Windows.
const realPlatform = Object.getOwnPropertyDescriptor(process, "platform");
Object.defineProperty(process, "platform", { value: "win32", configurable: true });

runLynis()
  .then((res) => {
    Object.defineProperty(process, "platform", realPlatform);

    ok(res.skipped === true, "win32 devuelve skipped");
    ok(res.kind === "unsupported",
       "win32 → kind 'unsupported', NO 'not-installed'", `kind: ${res.kind}`);
    ok(!esFatal(res), "y por tanto NO aborta la auditoría");
    ok(/WSL/i.test(res.reason || ""),
       "el motivo nombra WSL, que es la salida real del usuario", res.reason);

    console.log("\n── 3 · Un skipped no produce findings, sea cual sea el kind ──────\n");

    for (const forma of FORMAS) {
      const res2 = Object.assign({ skipped: true }, forma);
      ok(fromLynisRaw(res2, "win32", null).length === 0,
         `kind ${forma.kind} → 0 findings`);
    }

    console.log(`\n${"─".repeat(66)}`);
    console.log(`  ${passed} pasados · ${failed} fallidos`);
    console.log(`${"─".repeat(66)}\n`);
    process.exit(failed > 0 ? 1 : 0);
  })
  .catch((err) => {
    Object.defineProperty(process, "platform", realPlatform);
    console.error("  ✗ runLynis() lanzó:", err);
    process.exit(1);
  });
