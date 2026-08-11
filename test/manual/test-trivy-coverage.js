"use strict";

/**
 * test-trivy-coverage.js — Cobertura de los hallazgos de Trivy.
 *
 * Dos bloques independientes:
 *
 *   1. CASOS DETERMINISTAS (siempre) — fixtures JSON con la forma real de la
 *      salida de Trivy, sin ejecutar la herramienta. Verifican la procedencia
 *      (origin/location a partir de PkgPath) y el comando de remediación que
 *      genera cada Type. Ejecutables en cualquier SO y en segundos.
 *
 *   2. DIAGNÓSTICO CON TRIVY REAL (solo con --full) — compara hallazgos sobre
 *      /opt/homebrew/Cellar con y sin --skip-dirs. Queda como herramienta de
 *      inspección: el Cellar ya NO es el ámbito de producción (ahora se audita
 *      el HOME del usuario, ver nodes/audit-host/modules/trivy-fs.js).
 *
 * Uso:
 *   node test/manual/test-trivy-coverage.js          → casos deterministas
 *   node test/manual/test-trivy-coverage.js --full   → + diagnóstico con Trivy
 *
 * Output: consola + /tmp/trivy-coverage-report.txt (solo con --full)
 */

const { execSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { fromTrivyJson } = require("../../lib/normalizer");
const { DEFAULT_SKIP_DIRS } = require("../../nodes/audit-host/modules/trivy-fs");

const OUTPUT_FILE = "/tmp/trivy-coverage-report.txt";
const TIMEOUT_MS  = 180000;

// ── Bloque 1: casos deterministas de procedencia y remediación ───────────────

/**
 * Construye una salida de Trivy mínima pero con la forma real.
 * `pkgPath: null` reproduce una dependencia anotada en un fichero de bloqueo.
 */
function trivyFixture({ target, type, cls, pkgName, pkgPath, installed = "1.0.0", fixed = "2.0.0", id = "CVE-2026-0001" }) {
  return {
    Results: [{
      Target: target,
      Class: cls || "lang-pkgs",
      Type: type,
      Vulnerabilities: [{
        VulnerabilityID: id,
        PkgName: pkgName,
        PkgPath: pkgPath,
        InstalledVersion: installed,
        FixedVersion: fixed,
        Severity: "CRITICAL",
        Description: "Fixture de prueba.",
      }],
    }],
  };
}

/** Normaliza un fixture a findings de host. */
function findingsFor(fixture, pkgManager = null) {
  return fromTrivyJson(fixture, "HOST-CVE", "vulnerability", "trivy", { platform: process.platform, pkgManager });
}

/**
 * Ejercita las TRES ramas de resolveUserHome() manipulando el entorno.
 *
 * No es cosmético: Node-RED puede correr como servicio bajo otro usuario, y de
 * esa cadena depende que se audite el home de la persona y no /root.
 */
function runHomeResolutionCases(check) {
  const { resolveUserHome, resolveScanTarget } = require("../../nodes/audit-host/modules/trivy-fs");
  const saved = { SUDO_USER: process.env.SUDO_USER, HOME: process.env.HOME, USERPROFILE: process.env.USERPROFILE };
  const restore = () => {
    for (const k of Object.keys(saved)) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  };

  try {
    // Rama 1 · SUDO_USER manda sobre HOME (caso "lanzado con sudo").
    // HOME apunta a /tmp a propósito: si ganara HOME, el home resuelto sería ese.
    const realUser = execSync("id -un", { timeout: 5000 }).toString().trim();
    const realHome = saved.HOME;
    process.env.SUDO_USER = realUser;
    process.env.HOME = os.tmpdir();
    const r1 = resolveUserHome();
    check("H1 · SUDO_USER tiene prioridad sobre HOME",
      r1.resolvedFrom === "SUDO_USER" && r1.home === realHome, `${r1.resolvedFrom}/${r1.home}`);

    // Rama 2 · sin SUDO_USER → HOME del entorno.
    delete process.env.SUDO_USER;
    process.env.HOME = os.tmpdir();
    const r2 = resolveUserHome();
    check("H2 · sin SUDO_USER → HOME del entorno",
      r2.resolvedFrom === "env" && r2.home === os.tmpdir(), `${r2.resolvedFrom}/${r2.home}`);

    // Rama 2b · un HOME que NO existe se descarta (no se audita una ruta fantasma).
    process.env.HOME = path.join(os.tmpdir(), "locoaudit-no-existe-" + Date.now());
    const r2b = resolveUserHome();
    check("H2b · HOME inexistente se descarta → cae a os.homedir()",
      r2b.resolvedFrom === "os.homedir", `${r2b.resolvedFrom}/${r2b.home}`);

    // Rama 3 · sin SUDO_USER y sin HOME → os.homedir().
    delete process.env.HOME;
    delete process.env.USERPROFILE;
    const r3 = resolveUserHome();
    check("H3 · sin SUDO_USER ni HOME → os.homedir()",
      r3.resolvedFrom === "os.homedir" && r3.home === os.homedir(), `${r3.resolvedFrom}/${r3.home}`);

    // Objetivo configurado: gana sobre todo y expande "~".
    process.env.HOME = realHome;
    const c1 = resolveScanTarget("/ruta/elegida");
    check("H4 · target configurado → resolvedFrom 'config'",
      c1.resolvedFrom === "config" && c1.target === "/ruta/elegida", `${c1.resolvedFrom}/${c1.target}`);
    const c2 = resolveScanTarget("~/proyectos");
    check("H5 · '~/proyectos' se expande contra el home resuelto",
      c2.target === path.join(realHome, "proyectos"), c2.target);
  } finally {
    restore();
  }
}

function runOriginCases() {
  const results = [];
  const check = (name, cond, detail) => results.push({ name, ok: Boolean(cond), detail });

  console.log("═══════════════════════════════════════════════════════════════════");
  console.log(" CASOS DETERMINISTAS — procedencia (origin) y remediación");
  console.log("═══════════════════════════════════════════════════════════════════\n");

  // 1 · PkgPath null + Type pip → declared, sin comando (caso OBLIGATORIO)
  {
    const t = "usr/lib/python3.14/site-packages/ansible_collections/cisco/meraki/Pipfile.lock";
    const [f] = findingsFor(trivyFixture({ target: t, type: "pip", pkgName: "aiohttp", pkgPath: null }));
    check("1 · PkgPath null (Pipfile.lock) → origin 'declared'", f.origin === "declared", f.origin);
    check("1 · declared ⇒ isCommand=false y command=null", f.isCommand === false && f.command === null, `isCommand=${f.isCommand}`);
    check("1 · fix explica que es un fichero de bloqueo", /fichero de bloqueo/.test(f.fix), f.fix.slice(0, 60));
    console.log(`  fix(1): ${f.fix.slice(0, 100)}…\n`);
  }

  // 2 · PkgPath null + Type poetry (poetry.lock de las colecciones de Ansible)
  {
    const t = "usr/lib/python3.14/site-packages/ansible_collections/netbox/netbox/poetry.lock";
    const [f] = findingsFor(trivyFixture({ target: t, type: "poetry", pkgName: "black", pkgPath: null }));
    check("2 · poetry.lock con PkgPath null → 'declared' sin comando",
      f.origin === "declared" && f.command === null, `${f.origin}/${f.command}`);
  }

  // 3 · PkgPath presente + Type arch → comando de pacman
  {
    const [f] = findingsFor(trivyFixture({
      target: "usr/lib", type: "arch", cls: "os-pkgs", pkgName: "curl", pkgPath: "/usr/bin/curl",
    }));
    check("3 · Type arch instalado → sudo pacman -Syu curl",
      f.origin === "installed" && f.command === "sudo pacman -Syu curl", f.command);
    check("3 · installed con comando ⇒ isCommand=true", f.isCommand === true, `isCommand=${f.isCommand}`);
  }

  // 4 · python-pkg bajo prefijo de sistema → gestor del SO, NUNCA pip (PEP 668)
  {
    const p = "/usr/lib/python3.14/site-packages/aiohttp/__init__.py";
    const [f] = findingsFor(trivyFixture({
      target: "usr/lib", type: "python-pkg", pkgName: "aiohttp", pkgPath: p,
    }), "pacman");
    check("4 · python-pkg en /usr/lib → comando del gestor del SO",
      f.command === "sudo pacman -Syu aiohttp", f.command);
    check("4 · NO propone pip (fallaría por entorno gestionado)", !/pip install/.test(f.fix || ""), f.fix.slice(0, 60));
    check("4 · location = PkgPath", f.location === p, f.location);
  }

  // 5 · python-pkg en un venv del usuario → pip
  {
    const p = path.join(os.homedir(), "proyecto/.venv/lib/python3.12/site-packages/requests/__init__.py");
    const [f] = findingsFor(trivyFixture({
      target: "proyecto", type: "python-pkg", pkgName: "requests", pkgPath: p,
    }), "pacman");
    check("5 · python-pkg en venv → pip install --upgrade",
      f.command === "pip install --upgrade requests==2.0.0", f.command);
  }

  // 6 · Types de lenguaje con comando fiable
  {
    const cases = [
      ["npm",   "npm update lodash",        "lodash"],
      ["cargo", "cargo update -p tokio",    "tokio"],
      ["pnpm",  "pnpm update axios",        "axios"],
    ];
    for (const [type, expected, pkg] of cases) {
      const [f] = findingsFor(trivyFixture({
        target: `proyecto/${type}.lock`, type, pkgName: pkg, pkgPath: `/home/u/proyecto/node_modules/${pkg}/index.js`,
      }));
      check(`6 · Type ${type} instalado → ${expected}`, f.command === expected, f.command);
    }
  }

  // 7 · nuget sigue en TRIVY_LANG_MANUAL → prosa, sin comando
  {
    const [f] = findingsFor(trivyFixture({
      target: "proyecto/packages.config", type: "nuget", pkgName: "Newtonsoft.Json", pkgPath: "/srv/app/bin/Newtonsoft.Json.dll",
    }));
    check("7 · Type nuget → prosa sin comando", f.isCommand === false && f.command === null, `isCommand=${f.isCommand}`);
  }

  // 8 · Respaldo de location: sin PkgPath se usa el Target
  {
    const t = "proyecto/poetry.lock";
    const [f] = findingsFor(trivyFixture({ target: t, type: "poetry", pkgName: "django", pkgPath: null }));
    check("8 · sin PkgPath → location = Target", f.location === t, f.location);
  }

  // 9 · Mismo paquete y versión, declarado E instalado → DOS findings
  {
    const fixture = {
      Results: [
        {
          Target: "proyecto/poetry.lock", Class: "lang-pkgs", Type: "poetry",
          Vulnerabilities: [{
            VulnerabilityID: "CVE-2026-0009", PkgName: "urllib3", PkgPath: null,
            InstalledVersion: "1.0.0", FixedVersion: "2.0.0", Severity: "CRITICAL", Description: "x",
          }],
        },
        {
          Target: "proyecto", Class: "lang-pkgs", Type: "python-pkg",
          Vulnerabilities: [{
            VulnerabilityID: "CVE-2026-0009", PkgName: "urllib3",
            PkgPath: "/home/u/proyecto/.venv/lib/python3.12/site-packages/urllib3/__init__.py",
            InstalledVersion: "1.0.0", FixedVersion: "2.0.0", Severity: "CRITICAL", Description: "x",
          }],
        },
      ],
    };
    const fs2 = findingsFor(fixture);
    const origins = fs2.map((f) => f.origin).sort();
    check("9 · declarado + instalado → 2 findings, no 1", fs2.length === 2, `${fs2.length} findings`);
    check("9 · uno 'declared' y otro 'installed'",
      origins.join(",") === "declared,installed", origins.join(","));
  }

  // 10 · DEFAULT_SKIP_DIRS: ninguna entrada acaba en "/*"
  {
    const bad = DEFAULT_SKIP_DIRS.filter((d) => d.endsWith("/*"));
    check("10 · ningún --skip-dirs acaba en '/*' (excluiría hijos, no el dir)",
      bad.length === 0, bad.join(",") || "ninguno");
    check("10 · node_modules NO está excluido",
      !DEFAULT_SKIP_DIRS.some((d) => d.includes("node_modules")), DEFAULT_SKIP_DIRS.join(","));
  }

  // 11 (extra) · node-pkg suelto, sin package.json ancestro → prosa
  {
    const [f] = findingsFor(trivyFixture({
      target: "descargas", type: "node-pkg", pkgName: "minimist",
      pkgPath: "/tmp/no-existe-locoaudit/node_modules/minimist/index.js",
    }));
    check("11 · node-pkg sin package.json ancestro → prosa sin comando",
      f.command === null && f.isCommand === false, `command=${f.command}`);
  }

  // 12 · resolución del home (tres ramas + objetivo configurado)
  runHomeResolutionCases(check);

  let failed = 0;
  for (const r of results) {
    console.log(`  ${r.ok ? "✓" : "✗"} ${r.name}${r.ok ? "" : `  →  obtenido: ${r.detail}`}`);
    if (!r.ok) failed++;
  }
  console.log(`\n  Comprobaciones OK: ${results.length - failed} · Fallos: ${failed}`);
  console.log("═══════════════════════════════════════════════════════════════════\n");
  return failed === 0;
}

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

// Casos deterministas: siempre. El diagnóstico con Trivy real tarda minutos y
// escanea el Cellar, que ya no es el ámbito de producción → solo con --full.
const ok = runOriginCases();
if (process.argv.includes("--full")) main();
process.exit(ok ? 0 : 1);
