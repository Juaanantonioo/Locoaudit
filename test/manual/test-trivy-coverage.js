"use strict";

/**
 * test-trivy-coverage.js — Diagnóstico del filtro --skip-dirs en trivy fs.
 *
 * Compara hallazgos de Trivy sobre /opt/homebrew/Cellar con y sin --skip-dirs
 * para verificar que el filtro no oculta vulnerabilidades reales.
 *
 * Uso:
 *   node test/manual/test-trivy-coverage.js
 *
 * Output: consola + /tmp/trivy-coverage-report.txt
 */

const { execSync } = require("child_process");
const fs = require("fs");

const OUTPUT_FILE = "/tmp/trivy-coverage-report.txt";
const TIMEOUT_MS  = 180000;

// ── Helpers ──────────────────────────────────────────────────────────────────

function run(cmd) {
  try {
    return execSync(cmd, { timeout: TIMEOUT_MS, maxBuffer: 64 * 1024 * 1024 }).toString();
  } catch (err) {
    // Trivy puede salir con código != 0 si encuentra CVEs — la salida sigue siendo JSON válido
    const out = err.stdout ? err.stdout.toString() : "";
    if (out.trim()) return out;
    throw new Error(`Command failed: ${err.stderr ? err.stderr.toString().trim() : err.message}`);
  }
}

function brewPrefix() {
  try {
    return execSync("brew --prefix", { timeout: 5000 }).toString().trim();
  } catch (_) {
    return "/opt/homebrew";
  }
}

/**
 * Categoriza un target path para el resumen.
 * @param {string} target
 * @param {string} prefix  brew prefix
 * @returns {string}
 */
function categorizeTarget(target, prefix) {
  const t = target.toLowerCase();
  const cellar = `${prefix}/cellar`.toLowerCase();

  if (!t.startsWith(cellar)) return "other";

  // Extraer la parte relativa dentro de Cellar: <formula>/<version>/...
  const rel = target.slice(`${prefix}/Cellar/`.length);
  const parts = rel.split("/");
  // parts[0] = formula, parts[1] = version, parts[2+] = subpath
  const subpath = parts.slice(2).join("/");

  if (subpath.startsWith("share/")) return "share";
  if (subpath.startsWith("examples/")) return "examples";
  if (subpath.startsWith("bin/")) return "bin";
  if (subpath.startsWith("lib/")) return "lib";
  if (subpath.startsWith("libexec/")) return "libexec";
  if (subpath.startsWith("include/")) return "include";
  return "other_cellar";
}

/**
 * Extrae todos los findings de un resultado JSON de Trivy.
 * @param {string} jsonStr
 * @returns {Array<{pkgKey, pkgName, version, cve, target, category}>}
 */
function extractFindings(jsonStr, prefix) {
  let parsed;
  try {
    parsed = JSON.parse(jsonStr);
  } catch (_) {
    return [];
  }

  const findings = [];
  for (const result of (parsed.Results || [])) {
    const target = result.Target || "unknown";
    const category = categorizeTarget(target, prefix);
    for (const v of (result.Vulnerabilities || [])) {
      findings.push({
        pkgKey:   `${v.PkgName}@${v.InstalledVersion || "?"}`,
        pkgName:  v.PkgName,
        version:  v.InstalledVersion || "?",
        cve:      v.VulnerabilityID,
        severity: (v.Severity || "UNKNOWN").toUpperCase(),
        target,
        category,
      });
    }
  }
  return findings;
}

// ── Clasificación heurística: ¿es un ejecutable real o un ejemplo? ────────────

const REAL_BINARY_CATEGORIES = new Set(["bin", "lib", "libexec"]);

function isRealVuln(finding) {
  return REAL_BINARY_CATEGORIES.has(finding.category);
}

// ── Main ─────────────────────────────────────────────────────────────────────

function main() {
  const lines = [];
  const log = (...args) => {
    const line = args.join(" ");
    console.log(line);
    lines.push(line);
  };

  const prefix = brewPrefix();
  const cellarPath = `${prefix}/Cellar`;
  const skipDirs = `${prefix}/Cellar/*/*/share,${prefix}/Cellar/*/*/examples,${prefix}/Library/Homebrew`;

  log("═══════════════════════════════════════════════════════════════════");
  log(" TRIVY COVERAGE DIAGNOSTIC");
  log(`  Target:    ${cellarPath}`);
  log(`  Skip-dirs: ${skipDirs}`);
  log(`  Timestamp: ${new Date().toISOString()}`);
  log("═══════════════════════════════════════════════════════════════════");
  log("");

  // ── Escaneo SIN --skip-dirs ───────────────────────────────────────────────
  log("▶ Ejecutando trivy fs SIN --skip-dirs ...");
  let rawWithout;
  try {
    rawWithout = run(
      `trivy fs --format json --quiet --scanners vuln ${cellarPath}`
    );
  } catch (err) {
    log(`  ERROR: ${err.message}`);
    process.exit(1);
  }
  const withoutFindings = extractFindings(rawWithout, prefix);
  log(`  Encontrados: ${withoutFindings.length} findings`);
  log("");

  // ── Escaneo CON --skip-dirs ───────────────────────────────────────────────
  log(`▶ Ejecutando trivy fs CON --skip-dirs ...`);
  let rawWith;
  try {
    rawWith = run(
      `trivy fs --format json --quiet --scanners vuln --skip-dirs "${skipDirs}" ${cellarPath}`
    );
  } catch (err) {
    log(`  ERROR: ${err.message}`);
    process.exit(1);
  }
  const withFindings = extractFindings(rawWith, prefix);
  log(`  Encontrados: ${withFindings.length} findings`);
  log("");

  // ── Comparación ────────────────────────────────────────────────────────────
  const withKeys = new Set(withFindings.map((f) => `${f.cve}:${f.pkgKey}:${f.target}`));

  const filtered = withoutFindings.filter(
    (f) => !withKeys.has(`${f.cve}:${f.pkgKey}:${f.target}`)
  );

  // Agrupar filtrados por categoría
  const byCategory = {};
  for (const f of filtered) {
    if (!byCategory[f.category]) byCategory[f.category] = [];
    byCategory[f.category].push(f);
  }

  // Paquetes únicos filtrados (pkgKey)
  const filteredPkgMap = new Map(); // pkgKey → { targets: Set, cves: Set, category, severity }
  for (const f of filtered) {
    if (!filteredPkgMap.has(f.pkgKey)) {
      filteredPkgMap.set(f.pkgKey, { targets: new Set(), cves: new Set(), category: f.category, severity: f.severity });
    }
    filteredPkgMap.get(f.pkgKey).targets.add(f.target);
    filteredPkgMap.get(f.pkgKey).cves.add(f.cve);
  }

  // Separar: reales vs ejemplos
  const realFiltered    = filtered.filter(isRealVuln);
  const exampleFiltered = filtered.filter((f) => !isRealVuln(f));

  log("═══════════════════════════════════════════════════════════════════");
  log(" RESUMEN");
  log("═══════════════════════════════════════════════════════════════════");
  log(`  ANTES (sin filtro):   ${withoutFindings.length} findings`);
  log(`  DESPUÉS (con filtro): ${withFindings.length} findings`);
  log(`  FILTRADOS:            ${filtered.length} findings`);
  log("");

  // Desglose por categoría
  log("── Por categoría de path ──────────────────────────────────────────");
  const categoryOrder = ["bin", "lib", "libexec", "share", "examples", "include", "other_cellar", "other"];
  for (const cat of categoryOrder) {
    const items = byCategory[cat];
    if (!items || items.length === 0) continue;
    const marker = REAL_BINARY_CATEGORIES.has(cat) ? "⚠ REAL" : "OK  ";
    log(`  ${marker}  ${cat.padEnd(14)} ${items.length} findings`);
  }
  log("");

  // ── Paquetes reales filtrados (PROBLEMA) ──────────────────────────────────
  if (realFiltered.length > 0) {
    log("══ ⚠  PAQUETES REALES FILTRADOS (REVISAR SKIP-DIRS) ══════════════");
    log("   Estos están en bin/ lib/ libexec/ y NO deberían excluirse:");
    log("");
    for (const [pkgKey, info] of filteredPkgMap) {
      if (!REAL_BINARY_CATEGORIES.has(info.category)) continue;
      const cveList = [...info.cves].slice(0, 3).join(", ") +
        (info.cves.size > 3 ? ` (+${info.cves.size - 3} más)` : "");
      log(`  ● ${pkgKey} [${info.severity}]`);
      log(`    CVEs:    ${cveList}`);
      log(`    Path:    ${[...info.targets][0]}`);
    }
    log("");
  } else {
    log("══ ✓  Sin paquetes reales filtrados ══════════════════════════════");
    log("   Todos los filtrados son archivos de ejemplo/share. Filtro OK.");
    log("");
  }

  // ── Lista completa de paquetes filtrados ──────────────────────────────────
  log("── Paquetes únicos excluidos por --skip-dirs ──────────────────────");
  if (filteredPkgMap.size === 0) {
    log("  (ninguno)");
  } else {
    for (const [pkgKey, info] of filteredPkgMap) {
      const label = REAL_BINARY_CATEGORIES.has(info.category) ? "⚠ REAL    " : "OK ejemplo";
      const cveCount = info.cves.size;
      const targetSample = [...info.targets][0];
      log(`  ${label}  ${pkgKey.padEnd(35)} ${cveCount} CVE(s)  cat:${info.category}`);
      log(`             └─ ${targetSample}`);
    }
  }
  log("");

  // ── Findings retenidos (con filtro) por categoría ─────────────────────────
  const withByCategory = {};
  for (const f of withFindings) {
    if (!withByCategory[f.category]) withByCategory[f.category] = 0;
    withByCategory[f.category]++;
  }
  log("── Findings retenidos (con filtro) por categoría ──────────────────");
  for (const cat of categoryOrder) {
    if (!withByCategory[cat]) continue;
    log(`  ${cat.padEnd(16)} ${withByCategory[cat]} findings`);
  }
  log("");

  // ── Veredicto ─────────────────────────────────────────────────────────────
  log("── Veredicto ──────────────────────────────────────────────────────");
  if (realFiltered.length === 0) {
    log("  ✓ FILTRO CORRECTO: solo se excluyen archivos de ejemplo (/share/,");
    log("    /examples/, Homebrew meta-files). No se pierden vulnerabilidades reales.");
  } else {
    log("  ⚠ FILTRO DEMASIADO AGRESIVO: hay vulnerabilidades reales excluidas.");
    log("    Revisar los --skip-dirs y ajustar para preservar bin/ lib/ libexec/.");
  }
  log("═══════════════════════════════════════════════════════════════════");

  // ── Guardar a fichero ─────────────────────────────────────────────────────
  fs.writeFileSync(OUTPUT_FILE, lines.join("\n") + "\n", "utf8");
  console.log(`\nReport guardado en ${OUTPUT_FILE}`);
}

main();
