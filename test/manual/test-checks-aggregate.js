"use strict";

/**
 * test-checks-aggregate.js — Comprobaciones no realizadas: agregadas y bien clasificadas.
 *
 * Cubre tres cambios que van juntos porque tocan el mismo dato:
 *
 *   1. AGREGACIÓN. Cada comprobación caída era un hallazgo informativo suelto dentro de
 *      "Sistema & Actualizaciones", mezclado con hallazgos reales sobre el equipo. Cuatro
 *      tarjetas que decían "esto no se ha mirado" se leían como cuatro problemas más. Ahora
 *      salen agregadas en un solo bloque junto al panel de Alcance.
 *
 *   2. LOS *-SKIP SIGUEN EMITIÉNDOSE. El bloque se DERIVA de ellos, nunca de una lista paralela:
 *      dos recuentos de comprobaciones caídas acabarían divergiendo. Y así la exportación JSON
 *      conserva el detalle íntegro y `failedCheckFindings` del dashboard conserva su fuente.
 *
 *   3. "NO APLICA" ≠ "NO SE HA PODIDO". Trivy no cubre los paquetes de sistema de macOS ni de
 *      Windows, y Lynis no existe para Windows nativo. Redactarlo como fallo manda al usuario a
 *      buscar una solución que no existe.
 *
 * Uso:
 *   node test/manual/test-checks-aggregate.js
 */

const { normalizeHost, buildSkippedChecksSummary, esNoAplica, SKIP_KINDS_NO_APLICA } =
  require("../../lib/normalizer");

let failed = 0;
let passed = 0;

function ok(cond, label, detail) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}`); if (detail) console.log(`      ${detail}`); }
}

console.log("\n── 1 · Los seis kinds de límite estructural ──────────────────────\n");

// La lista se comprueba entera, no por muestreo: es la única fuente y un olvido aquí se traduce
// en un aviso ámbar sobre algo que nadie puede arreglar.
for (const k of ["unsupported", "os-unsupported", "nothing-to-scan"]) {
  ok(esNoAplica(k), `'${k}' es límite del sistema, no fallo`);
}
// Y lo que NO puede colarse: instalar una herramienta que falta SÍ es una acción posible.
for (const k of ["error", "timeout", "not-installed", "output-too-large", "invalid-json",
                 "empty-output", "daemon-down", "disabled"]) {
  ok(!esNoAplica(k), `'${k}' NO cuenta como límite del sistema`);
}
ok(SKIP_KINDS_NO_APLICA.size === 3,
   "la lista tiene exactamente 3 kinds", `tiene ${SKIP_KINDS_NO_APLICA.size}`);

console.log("\n── 2 · El registro del texto cambia con el motivo ────────────────\n");

const CASOS = [
  { nombre: "macOS · trivy-rootfs",
    raw: { trivyRootfs: { skipped: true, kind: "os-unsupported", reason: "Trivy no ha detectado la familia del SO" } },
    plat: "darwin", espera: /no aplica en este sistema/ },
  { nombre: "Windows · lynis",
    raw: { lynis: { skipped: true, kind: "unsupported", reason: "Lynis no funciona en Windows sin WSL" } },
    plat: "win32", espera: /no aplica en este sistema/ },
  { nombre: "lynis apagado",
    raw: { lynis: { skipped: true, kind: "disabled", reason: "desactivado en el nodo" } },
    plat: "linux", espera: /desactivado en el nodo/ },
  { nombre: "lynis CAÍDO",
    raw: { lynis: { skipped: true, kind: "error", reason: "lynis salió con código 2" } },
    plat: "linux", espera: /no se ha podido comprobar/ },
  { nombre: "actualizaciones CAÍDAS",
    raw: { pendingUpdates: { skipped: true, kind: "error", reason: "Windows Update devolvió 0x8024402C" } },
    plat: "win32", espera: /no se han podido consultar/ },
];

for (const c of CASOS) {
  const f = normalizeHost(c.raw, { platform: c.plat })[0];
  ok(c.espera.test(f.title), `[${c.nombre}] ${f.title}`, f.title);
}

// El flag, no el texto: es lo que lee el dashboard.
const macos = normalizeHost(
  { trivyRootfs: { skipped: true, kind: "os-unsupported", reason: "x" } }, { platform: "darwin" })[0];
ok(macos.notApplicable === true, "y viaja como `notApplicable: true` en el finding");
ok(macos.skipped === true, "sin dejar de ser `skipped`: tampoco se comprobó");

const caido = normalizeHost(
  { lynis: { skipped: true, kind: "error", reason: "x" } }, { platform: "linux" })[0];
ok(!caido.notApplicable, "un fallo real NO lleva el flag", String(caido.notApplicable));

console.log("\n── 3 · El agregado sale de esos mismos findings ──────────────────\n");

const mezcla = normalizeHost({
  lynis:        { skipped: true, kind: "disabled",       reason: "desactivado en el nodo" },
  trivy:        { skipped: true, kind: "disabled",       reason: "desactivado en el nodo" },
  trivyRootfs:  { skipped: true, kind: "os-unsupported", reason: "Trivy no reconoce este sistema" },
  pendingUpdates: { skipped: true, kind: "error",        reason: "Windows Update devolvió 0x8024402C" },
}, { platform: "win32" });

const resumen = buildSkippedChecksSummary(mezcla);
const omitidos = mezcla.filter((f) => f.skipped);

console.log(`  ${resumen.title}`);
resumen.items.forEach((i) => console.log(`     · ${i.estado.padEnd(15)}${i.title}`));

ok(resumen.total === omitidos.length,
   "el total del agregado es exactamente el número de findings `skipped`",
   `${resumen.total} vs ${omitidos.length}`);
ok(resumen.failed + resumen.notApplicable + resumen.disabled === resumen.total,
   "la partición en tres es exhaustiva: no hay ninguno sin clasificar");
ok(resumen.failed === 1, "1 fallo real", String(resumen.failed));
ok(resumen.notApplicable === 1, "1 límite del sistema", String(resumen.notApplicable));
ok(resumen.disabled === 2, "2 apagados por el usuario", String(resumen.disabled));

// La condición del encargo: derivado, nunca una lista paralela.
ok(resumen.items.every((i) => omitidos.some((f) => f.id === i.id && f.title === i.title)),
   "cada línea del agregado corresponde a un finding real, con su mismo título");
ok(resumen.items.length === omitidos.length, "y no hay ninguna de más");

// Los findings SIGUEN en el payload: es lo que conserva el detalle en el JSON exportado y lo que
// alimenta el estado ámbar del dashboard.
ok(omitidos.length === 4, "los 4 *-SKIP siguen emitiéndose", String(omitidos.length));
ok(omitidos.every((f) => f.evidence && f.evidence.length > 20),
   "cada uno conserva su evidencia íntegra para la exportación JSON");

console.log("\n── 4 · Con un fallo y sin ninguno, el texto cambia ───────────────\n");

ok(/se intentó y no pudo completarse/.test(resumen.evidence),
   "con un fallo, el texto lo dice", resumen.evidence.split("\n")[0]);
ok(/dejan un hueco en el informe/.test(resumen.evidence),
   "y avisa de que ahí falta cobertura");

const sinFallos = buildSkippedChecksSummary(normalizeHost({
  lynis:       { skipped: true, kind: "disabled",       reason: "desactivado" },
  trivyRootfs: { skipped: true, kind: "os-unsupported", reason: "no reconoce el sistema" },
}, { platform: "darwin" }));

console.log(`  ${sinFallos.title}`);
ok(sinFallos.failed === 0, "sin fallos, failed = 0");
ok(/Ninguna ha fallado/.test(sinFallos.evidence),
   "y el texto NO habla de huecos: es alcance conocido", sinFallos.evidence);
ok(!/dejan un hueco/.test(sinFallos.evidence),
   "nada de avisar de un agujero que no existe");

console.log("\n── 5 · Sin comprobaciones omitidas no hay bloque ─────────────────\n");

ok(buildSkippedChecksSummary([]) === null, "lista vacía → null");
ok(buildSkippedChecksSummary(normalizeHost(
     { cpuMemory: { cpu: { loadPercent: 10, cores: 8 }, memory: { totalBytes: 8e9, usedBytes: 4e9, usedPercent: 50 } } },
     { platform: "linux" })) === null,
   "un informe sin ninguna omitida → null, y el bloque no se renderiza");

console.log(`\n${passed} pasados · ${failed} fallidos\n`);
process.exit(failed > 0 ? 1 : 0);
