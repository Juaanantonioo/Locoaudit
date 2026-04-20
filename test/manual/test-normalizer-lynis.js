"use strict";

const { fromLynisRaw } = require("../../lib/normalizer");

// ── Datos de prueba ──────────────────────────────────────────────────────────

const rawLynis = {
  hardeningIndex: 45,
  warnings: [
    { id: "SSH-7408",  description: "PermitRootLogin is set to yes" },
    { id: "FIRE-4513", description: "No firewall found" },
    { id: "AUTH-9262", description: "PAM configuration is weak" },
    { id: "USB-1000",  description: "USB autoran is enabled" },
    { id: "KRNL-5820", description: "Kernel parameters not hardened" },
    { id: "CRYP-001",  description: "Weak cryptographic settings" },
    { id: "MAIL-8818", description: "Mail relay is open" },
    { id: "NAME-4408", description: "DNSSEC not configured" },
  ],
  suggestions: [
    { id: "TOOL-5002", description: "Install a rootkit detection tool" },
    { id: "BANN-7126", description: "Add a legal banner to /etc/motd" },
    { id: "ACCT-9622", description: "Enable process accounting (acct)" },
    { id: "ACCT-9626", description: "Install sysstat for system statistics" },
    { id: "STRG-1846", description: "Disable squashfs module if not needed" },
    { id: "MISC-001",  description: "Misc hardening suggestion 1" },
    { id: "MISC-002",  description: "Misc hardening suggestion 2" },
    { id: "MISC-003",  description: "Misc hardening suggestion 3" },
    { id: "MISC-004",  description: "Misc hardening suggestion 4" },
    { id: "MISC-005",  description: "Misc hardening suggestion 5" },
    { id: "MISC-006",  description: "Misc hardening suggestion 6" },
    { id: "MISC-007",  description: "Misc hardening suggestion 7" },
  ],
};

// ── Ejecutar normalización ───────────────────────────────────────────────────

const findings = fromLynisRaw(rawLynis);

// ── Imprimir resultados ──────────────────────────────────────────────────────

console.log(`\nTotal findings generados: ${findings.length}\n`);
console.log("─".repeat(80));

for (const f of findings) {
  const sev = f.severity.toUpperCase().padEnd(8);
  const id  = f.id.padEnd(24);
  console.log(`${sev} ${id} ${f.title}`);
}

console.log("─".repeat(80));

// ── Resumen por severidad ────────────────────────────────────────────────────

const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
for (const f of findings) {
  counts[f.severity] = (counts[f.severity] || 0) + 1;
}

console.log("\nResumen por severidad:");
for (const [level, n] of Object.entries(counts)) {
  if (n > 0) console.log(`  ${level.padEnd(8)} ${n}`);
}
console.log();
