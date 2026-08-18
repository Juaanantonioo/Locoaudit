"use strict";

/**
 * test-dashboard-counts.js — Cabecera, donut y barras cuentan LO MISMO.
 *
 * La cabecera ("4 requieren tu atención · 117 informativos") y el donut salen de
 * summarize() (lib/severity-map.js), que recorre TODOS los findings. Las barras
 * de "Hallazgos por Categoría" salen de catBars() → groups(), dentro del
 * ui_template. groups() descartaba la categoría 'disk', así que las barras
 * sumaban menos que la cabecera —en CachyOS, 25 frente a 37— y ningún disco
 * lleno aparecía en la lista de hallazgos aunque contase en el donut.
 *
 * Este test NO reimplementa groups()/catBars(): los EXTRAE del propio
 * dashboard-host-template.html y los ejecuta, para que una regresión en el
 * template lo rompa.
 *
 * Uso:
 *   node test/manual/test-dashboard-counts.js
 */

const fs = require("fs");
const path = require("path");
const { parseDfOutput } = require("../../nodes/audit-host/modules/disk-storage");
const { normalizeHost } = require("../../lib/normalizer");
const { summarize } = require("../../lib/severity-map");

const ROOT = path.join(__dirname, "..", "..");
const TEMPLATE = path.join(ROOT, "examples", "dashboard-host-template.html");
const FIX = path.join(ROOT, "test", "fixtures", "df");

let failed = 0;
let passed = 0;

function ok(cond, label, detail) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}`); if (detail) console.log(`      ${detail}`); }
}

// ── Extraer los computed reales del template ────────────────────────────────

const tpl = fs.readFileSync(TEMPLATE, "utf8");

/** Recorta `nombre() { … }` del template contando llaves. */
function extractMethod(src, name) {
  const start = src.indexOf("\n    " + name + "() {");
  if (start < 0) throw new Error(`no encuentro ${name}() en el template`);
  let i = src.indexOf("{", start);
  let depth = 0;
  for (let j = i; j < src.length; j++) {
    if (src[j] === "{") depth++;
    else if (src[j] === "}") { depth--; if (depth === 0) return src.slice(start + 1, j + 1); }
  }
  throw new Error(`llaves sin cerrar en ${name}()`);
}

const computed = new Function(
  "return {" + extractMethod(tpl, "groups") + "," + extractMethod(tpl, "catBars") + "};"
)();

/** Ejecuta groups()/catBars() del template sobre un payload. */
function barsFor(auditData) {
  const ctx = { auditData, filterSev: "all" };
  ctx.groups = computed.groups.call(ctx);
  return computed.catBars.call(ctx);
}

const sum = (bars) => bars.reduce((a, b) => a + b.count, 0);

// ── Findings no-disco: una mezcla realista de las demás categorías ──────────

function otrosFindings(n) {
  const CATS = ["vulnerability", "system", "network", "cpu", "memory", "system-logs"];
  const SEVS = ["critical", "high", "medium", "low", "info"];
  const out = [];
  for (let i = 0; i < n; i++) {
    out.push({
      id: `FAKE-${i}`,
      title: `hallazgo ${i}`,
      severity: SEVS[i % SEVS.length],
      evidence: "-",
      fix: null,
      category: CATS[i % CATS.length],
      source: "native",
      timestamp: new Date().toISOString(),
    });
  }
  return out;
}

// ── Escenarios ──────────────────────────────────────────────────────────────

function escenario(nombre, dfFile, hasType, nOtros) {
  console.log(`\n── ${nombre} ─────────────────────────────────────────\n`);

  const disk = parseDfOutput(fs.readFileSync(path.join(FIX, dfFile), "utf8"), hasType);
  const findings = normalizeHost({ disk }, "native").concat(otrosFindings(nOtros));
  const s = summarize(findings);
  const auditData = { findings, summary: s };

  const bars = barsFor(auditData);
  const cab = s.actionable.total + s.informative.total;
  const donut = Object.values(s.counts).reduce((a, b) => a + b, 0);
  const barras = sum(bars);

  console.log(`     discos: ${disk.length}  ·  cabecera: ${cab}  ·  donut: ${donut}  ·  barras: ${barras}`);

  ok(cab === donut, `cabecera (${cab}) = donut (${donut})`);
  ok(barras === cab, `barras (${barras}) = cabecera (${cab})`,
     "las barras por categoría deben sumar todos los findings");
  ok(bars.some((b) => b.key === "disk"),
     `existe la barra "Almacenamiento" (${(bars.find((b) => b.key === "disk") || {}).count} hallazgos)`);
  ok(bars.every((b) => b.count > 0), "ninguna barra vacía");

  return { disk: disk.length, cab, barras };
}

const mac = escenario("macOS (APFS, df real del portátil)", "macos-apfs-real.txt", false, 25);
ok(mac.disk === 2, `macOS sigue con 2 entradas de disco`, "el deduplicado no debe tocar APFS");

const cachy = escenario("CachyOS (btrfs, 7 subvolúmenes + tmpfs)", "linux-btrfs-cachyos.txt", true, 25);
ok(cachy.disk === 2, `CachyOS pasa de 12 a ${cachy.disk} entradas de disco`);
ok(cachy.cab === 27,
   `cabecera CachyOS = ${cachy.cab} (25 no-disco + 2 disco)`,
   "antes eran 25 + 12 = 37 en cabecera y 25 en barras");

// ── El caso que se veía en pantalla ─────────────────────────────────────────
console.log("\n── El desfase reportado ya no se puede reproducir ───────────────\n");

ok(mac.barras === mac.cab && cachy.barras === cachy.cab,
   "en los dos sistemas las barras cuadran con la cabecera");

console.log(`\n${passed} pasados · ${failed} fallidos\n`);
process.exit(failed > 0 ? 1 : 0);
