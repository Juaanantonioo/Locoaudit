"use strict";

const { runNmap }          = require("../../nodes/audit-network/modules/nmap-wrapper");
const { enrichPorts }      = require("../../nodes/audit-network/modules/service-detect");
const { normalizeNetwork } = require("../../lib/normalizer");

const SEP = "─".repeat(72);

// ── Helpers de impresión ──────────────────────────────────────────────────────

function printPortTable(enriched) {
  if (enriched.length === 0) {
    console.log("  (ningún puerto abierto)");
    return;
  }
  console.log(SEP);
  console.log(
    "PUERTO  ".padEnd(8) +
    "SERVICIO       ".padEnd(16) +
    "VERSIÓN                ".padEnd(24) +
    "SEVERIDAD  ".padEnd(11) +
    "PROCESO"
  );
  console.log(SEP);
  for (const p of enriched) {
    const version = (p.version || "").slice(0, 20) || "—";
    const proc    = p.process ? `${p.process} (PID ${p.pid})` : "—";
    console.log(
      String(p.port).padEnd(8) +
      p.service.padEnd(16) +
      version.padEnd(24) +
      p.severity.toUpperCase().padEnd(11) +
      proc
    );
  }
  console.log(SEP);
}

function printFindings(findings) {
  console.log(`Findings generados: ${findings.length}`);
  console.log(SEP);
  for (const f of findings) {
    console.log(
      f.severity.toUpperCase().padEnd(9) +
      f.id.padEnd(16) +
      f.title
    );
  }
}

function printCounts(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  console.log("\nResumen por severidad:");
  for (const [level, n] of Object.entries(counts)) {
    if (n > 0) console.log(`  ${level.padEnd(8)} ${n}`);
  }
}

// ── Pasada genérica ───────────────────────────────────────────────────────────

async function runPass(label, openPorts, normSource) {
  console.log(`\n${"═".repeat(72)}`);
  console.log(`  PASADA: ${label}`);
  console.log(`${"═".repeat(72)}`);
  console.log(`Puertos abiertos encontrados: ${openPorts.length}\n`);

  const enriched = await enrichPorts(openPorts);
  printPortTable(enriched);

  const findings = normalizeNetwork(enriched, normSource);
  console.log();
  printFindings(findings);
  printCounts(findings);
  console.log();

  return { openPorts, findings };
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  // Nmap es el único escáner del nodo: ya no hay comparativa contra el escáner
  // nativo (port-scanner.js se eliminó al pasar Nmap a requisito).
  const nmapResult = await runNmap({ target: "127.0.0.1", timeout: 240000 });

  if (nmapResult.skipped && !nmapResult.inconclusive) {
    console.log("═".repeat(72));
    console.log("  NMAP NO DISPONIBLE");
    console.log("═".repeat(72));
    console.log(`Motivo: ${nmapResult.reason}`);
    console.log("Nmap es requisito de audit-network. Instálalo y repite la prueba:");
    console.log("  macOS:   brew install nmap");
    console.log("  Debian:  sudo apt install nmap");
    console.log("  Arch:    sudo pacman -S nmap");
    console.log("  Windows: winget install -e --id Insecure.Nmap\n");
    return;
  }

  if (nmapResult.inconclusive) {
    console.log(`\n⚠ Escaneo no concluyente: ${nmapResult.reason}\n`);
    return;
  }

  await runPass("NMAP (nmap-wrapper.js)", nmapResult.ports, "nmap");
}

main().catch((err) => {
  console.error("Error:", err.message);
  process.exit(1);
});
