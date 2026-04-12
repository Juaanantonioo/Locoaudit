"use strict";

const { scanPorts }        = require("../../nodes/audit-network/modules/port-scanner");
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
  // ── Pasada 1: escáner nativo ────────────────────────────────────────────────
  const nativePorts    = await scanPorts({ timeout: 500, concurrency: 20 });
  const { openPorts: nativeOpen, findings: nativeFindings } =
    await runPass("ESCÁNER NATIVO (port-scanner.js)", nativePorts, "native");

  // ── Pasada 2: nmap ──────────────────────────────────────────────────────────
  let nmapOpen     = null;
  let nmapFindings = null;

  const nmapResult = await runNmap({ target: "127.0.0.1", timeout: 30000 });

  if (nmapResult.skipped) {
    console.log(`${"═".repeat(72)}`);
    console.log("  PASADA: NMAP");
    console.log(`${"═".repeat(72)}`);
    console.log(`nmap no disponible: ${nmapResult.reason}`);
    console.log("Solo se dispone de la pasada nativa.\n");
  } else {
    const { openPorts: no, findings: nf } =
      await runPass("NMAP (nmap-wrapper.js)", nmapResult.ports, "nmap");
    nmapOpen     = no;
    nmapFindings = nf;
  }

  // ── Comparativa ─────────────────────────────────────────────────────────────
  if (nmapOpen !== null) {
    console.log(`${"═".repeat(72)}`);
    console.log("  COMPARATIVA");
    console.log(`${"═".repeat(72)}`);

    const nativeSet = new Set(nativeOpen.map((p) => p.port));
    const nmapSet   = new Set(nmapOpen.map((p) => p.port));

    const soloNmap   = nmapOpen.filter((p) => !nativeSet.has(p.port));
    const soloNative = nativeOpen.filter((p) => !nmapSet.has(p.port));

    if (soloNmap.length > 0) {
      console.log(`\nPuertos encontrados por nmap pero NO por el escáner nativo (${soloNmap.length}):`);
      for (const p of soloNmap) {
        console.log(`  :${p.port}  ${p.service}  [${p.severity}]${p.version ? "  v" + p.version : ""}`);
      }
    } else {
      console.log("\nNmap no encontró puertos adicionales respecto al escáner nativo.");
    }

    if (soloNative.length > 0) {
      console.log(`\nPuertos encontrados por el escáner nativo pero NO por nmap (${soloNative.length}):`);
      for (const p of soloNative) {
        console.log(`  :${p.port}  ${p.service}  [${p.severity}]`);
      }
    } else {
      console.log("El escáner nativo no encontró puertos adicionales respecto a nmap.");
    }
    console.log();
  }
}

main().catch((err) => {
  console.error("Error:", err.message);
  process.exit(1);
});
