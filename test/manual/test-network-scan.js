"use strict";

const { scanPorts }       = require("../../nodes/audit-network/modules/port-scanner");
const { enrichPorts }     = require("../../nodes/audit-network/modules/service-detect");
const { normalizeNetwork } = require("../../lib/normalizer");

async function main() {
  // ── 1. Escaneo ─────────────────────────────────────────────────────────────
  console.log("Escaneando puertos TCP del host local...\n");
  const openPorts = await scanPorts({ timeout: 500, concurrency: 20 });

  console.log(`Puertos abiertos encontrados: ${openPorts.length}`);

  // ── 2. Enriquecimiento ─────────────────────────────────────────────────────
  const enriched = await enrichPorts(openPorts);

  if (enriched.length > 0) {
    console.log();
    console.log("─".repeat(70));
    console.log("PUERTO  SERVICIO       SEVERIDAD  PROCESO");
    console.log("─".repeat(70));
    for (const p of enriched) {
      const proc = p.process ? `${p.process} (PID ${p.pid})` : "—";
      console.log(
        String(p.port).padEnd(8) +
        p.service.padEnd(15) +
        p.severity.toUpperCase().padEnd(11) +
        proc
      );
    }
  }

  // ── 3. Normalización ───────────────────────────────────────────────────────
  const findings = normalizeNetwork(enriched, "native");

  console.log();
  console.log("─".repeat(70));
  console.log(`Findings generados: ${findings.length}`);
  console.log("─".repeat(70));
  for (const f of findings) {
    console.log(
      f.severity.toUpperCase().padEnd(9) +
      f.id.padEnd(16) +
      f.title
    );
  }

  // ── 4. Resumen ─────────────────────────────────────────────────────────────
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;

  console.log();
  console.log("Resumen por severidad:");
  for (const [level, n] of Object.entries(counts)) {
    if (n > 0) console.log(`  ${level.padEnd(8)} ${n}`);
  }
  console.log();
}

main().catch(err => {
  console.error("Error:", err.message);
  process.exit(1);
});
