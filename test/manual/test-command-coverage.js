"use strict";

/**
 * test-command-coverage.js — Guardarraíl contra la regresión de isCommand.
 *
 * Bug que previene: el texto del fix ("poetry update ansible-core") se generaba
 * en un sitio (getTrivyFixCommand / lynisFix) y la decisión "esto es un
 * comando" en OTRO (regex _CMD_PATTERNS). Al añadir un gestor nuevo a la tabla de
 * generación sin tocar el regex, el fix salía como comando pero isCommand=false,
 * y el dashboard lo pintaba como texto plano en vez de con botón «Copiar».
 *
 * Este test recorre las TABLAS REALES del normalizador (no una lista fija), así
 * que un gestor nuevo queda cubierto automáticamente. Para decidir si algo es un
 * comando usa un ORÁCULO INDEPENDIENTE (COMMAND_VERBS más abajo), NO el mismo
 * regex de producción — si producción deja de reconocer un comando, aquí falla.
 *
 * Uso:
 *   node test/manual/test-command-coverage.js            # solo invariantes sintéticas
 *   node test/manual/test-command-coverage.js --trivy .  # además, trivy fs real
 *
 * Sale con código 1 si detecta cualquier regresión.
 */

const norm = require("../../lib/normalizer");
const { TRIVY_TYPE_TO_MANAGER } = require("../../lib/pkg-manager");
const { execFileSync } = require("child_process");

const {
  fromTrivyJson,
  fromLynisRaw,
  TRIVY_LANG_CMD,
  TRIVY_LANG_MANUAL,
  TRIVY_OS_TYPES,
} = norm;

// ── Oráculo INDEPENDIENTE ────────────────────────────────────────────────────
// Verbos que, al inicio de la primera línea de un fix, delatan un comando de
// terminal. Mantenido a mano y a propósito separado de _CMD_PATTERNS: es el
// contraste que detecta que producción y presentación se han desincronizado.
const COMMAND_VERBS = [
  "sudo", "brew", "npm", "pnpm", "yarn", "pip", "poetry", "pipenv",
  "cargo", "go", "bundle", "composer", "apt", "dnf", "yum", "zypper",
  "apk", "pacman", "emerge", "winget", "choco", "scoop", "port",
];

function firstLine(s) {
  return (s || "").split("\n")[0].trim();
}

function looksLikeCommand(fix) {
  const line = firstLine(fix);
  if (!line) return false;
  const verb = line.split(/\s+/)[0].toLowerCase();
  return COMMAND_VERBS.includes(verb);
}

// ── Mini-framework de aserciones ─────────────────────────────────────────────
let failures = 0;
let checks = 0;
const log = (...a) => console.log(...a);

function fail(msg) {
  failures++;
  log(`  ✗ ${msg}`);
}
function ok(msg) {
  checks++;
  log(`  ✓ ${msg}`);
}

/**
 * Invariante central: un finding cuyo fix TIENE pinta de comando (según el
 * oráculo independiente) DEBE tener isCommand=true y command no nulo, y a la
 * inversa. Además, si hay command, debe casar con la primera línea del fix.
 */
function assertConsistent(label, f) {
  const looks = looksLikeCommand(f.fix);
  const isCmd = f.isCommand === true;
  const hasCmd = f.command != null && f.command !== "";

  if (looks && !isCmd) {
    fail(`${label}: fix parece comando ("${firstLine(f.fix)}") pero isCommand=false`);
    return;
  }
  if (isCmd && !hasCmd) {
    fail(`${label}: isCommand=true pero command está vacío`);
    return;
  }
  if (hasCmd && !isCmd) {
    fail(`${label}: hay command ("${f.command}") pero isCommand=false`);
    return;
  }
  if (hasCmd && f.command !== firstLine(f.fix)) {
    fail(`${label}: command ("${f.command}") no coincide con la 1ª línea del fix ("${firstLine(f.fix)}")`);
    return;
  }
  ok(`${label}: coherente (isCommand=${isCmd}, command=${f.command ? "«" + f.command + "»" : "null"})`);
}

// ── Constructores sintéticos ─────────────────────────────────────────────────
/**
 * Finding de host para un Type de Trivy. `installed` decide si el fixture lleva PkgPath:
 *   - con PkgPath (origin 'installed') es el único caso con comando de gestor; la ruta queda FUERA de SYSTEM_PREFIXES,
 *     porque el desvío al gestor del sistema se prueba en test-trivy-coverage.js.
 *   - sin PkgPath (origin 'declared', anotación en un lockfile) NUNCA debe salir un comando.
 */
function hostFindingForType(type, installed = true) {
  const vuln = {
    VulnerabilityID: "CVE-2024-9999",
    PkgName: "demo-pkg",
    InstalledVersion: "1.0.0",
    FixedVersion: "1.0.1",
    Severity: "HIGH",
    Description: "synthetic vuln for coverage test",
  };
  if (installed) vuln.PkgPath = "/home/demo/proyecto/demo-pkg/init.js";

  const raw = {
    Results: [{
      Target: installed ? "synthetic-target" : "synthetic-target/poetry.lock",
      Type: type,
      Vulnerabilities: [vuln],
    }],
  };
  const out = fromTrivyJson(raw, "HOST-CVE", "vulnerability", "trivy", { platform: process.platform });
  return out[0];
}

/**
 * Contra-prueba de la variante DECLARADA: ningún Type puede producir comando
 * cuando el paquete solo está anotado en un lockfile.
 */
function testDeclaredNeverCommand() {
  log("\n── Procedencia 'declared' (sin PkgPath) → nunca hay comando ──────────");
  const types = [...Object.keys(TRIVY_LANG_CMD), ...TRIVY_OS_TYPES].slice(0, 12);
  for (const type of types) {
    const f = hostFindingForType(type, false);
    if (f.origin !== "declared") {
      fail(`Type "${type}" declarado: origin esperado 'declared', obtenido '${f.origin}'`);
      continue;
    }
    if (f.isCommand !== false || f.command !== null) {
      fail(`Type "${type}" declarado: NO debería haber comando (isCommand=${f.isCommand}, command=${f.command})`);
      continue;
    }
    ok(`Type "${type}" declarado: sin comando (origin=declared)`);
  }
}

// ── Bloque 1: gestores de lenguaje con comando fiable (TRIVY_LANG_CMD) ────────
function testLangCmd() {
  log("\n── TRIVY_LANG_CMD (gestores de lenguaje → comando esperado) ──────────");
  for (const type of Object.keys(TRIVY_LANG_CMD)) {
    const f = hostFindingForType(type);
    if (!f) { fail(`Type "${type}": no generó finding`); continue; }
    if (f.isCommand !== true || !f.command) {
      fail(`Type "${type}": DEBERÍA ser comando y no lo es (fix="${firstLine(f.fix)}", isCommand=${f.isCommand})`);
    } else {
      assertConsistent(`Type "${type}"`, f);
    }
  }
}

// ── Bloque 2: paquetes de SO (TRIVY_OS_TYPES → comando del gestor) ────────────
function testOsTypes() {
  log("\n── TRIVY_OS_TYPES (paquetes de SO → comando del gestor esperado) ─────");
  for (const type of TRIVY_OS_TYPES) {
    const f = hostFindingForType(type);
    if (!f) { fail(`Type "${type}": no generó finding`); continue; }
    const mapped = TRIVY_TYPE_TO_MANAGER[type];
    if (mapped && (f.isCommand !== true || !f.command)) {
      fail(`Type "${type}" (mapea a ${mapped}): DEBERÍA ser comando (fix="${firstLine(f.fix)}", isCommand=${f.isCommand})`);
    } else {
      assertConsistent(`Type "${type}"`, f);
    }
  }
}

// ── Bloque 3: lenguajes sin comando fiable (TRIVY_LANG_MANUAL → prosa) ────────
function testLangManual() {
  log("\n── TRIVY_LANG_MANUAL (sin comando único → prosa esperada) ────────────");
  for (const type of TRIVY_LANG_MANUAL) {
    const f = hostFindingForType(type);
    if (!f) { fail(`Type "${type}": no generó finding`); continue; }
    if (f.isCommand === true || f.command) {
      fail(`Type "${type}": debería ser PROSA pero salió como comando (command="${f.command}")`);
    } else {
      assertConsistent(`Type "${type}"`, f);
    }
  }
}

// ── Bloque 4: Lynis (comando en 2ª línea → debe tener botón) ─────────────────
function testLynisPkgs() {
  log("\n── Lynis: comando de instalación en 2ª línea ─────────────────────────");

  // ACCT-9626 pide instalar sysstat, y ese SÍ es un paso ejecutable. El comando se compone con
  // installCmd() a partir del gestor real, así que apt, dnf y pacman salen correctos sin escribir
  // tres textos. Gestor forzado para que el test sea determinista en cualquier SO.
  const raw = { hardeningIndex: null, warnings: [], suggestions: [{ id: "ACCT-9626", description: "Enable sysstat" }] };
  const out = fromLynisRaw(raw, "linux", "apt");
  const f = out.find((x) => x.control === "ACCT-9626");
  if (!f) { fail("Lynis ACCT-9626: no generó finding individual"); return; }
  if (f.command !== "sudo apt update && sudo apt install -y sysstat") {
    fail(`Lynis ACCT-9626: command esperado el de instalar sysstat, got "${f.command}"`);
  } else {
    ok(`Lynis ACCT-9626: command en 2ª línea recuperado («${f.command}»)`);
  }

  // LA REGRESIÓN QUE ESTE BLOQUE FIJA A PARTIR DE AHORA.
  // Antes, TODO control con prefijo PKGS recibía el comando de actualización global del sistema:
  // `sudo apt upgrade`, con su botón de copiar. Para PKGS-7420 —"no tienes una herramienta de
  // auditoría de paquetes"— eso responde a otra pregunta, y el botón invitaba a ejecutar algo que
  // no resuelve el hallazgo. La tabla por prefijo se eliminó; esto comprueba que no vuelve.
  const pkgs = fromLynisRaw(
    { hardeningIndex: null, warnings: [], suggestions: [
      { id: "PKGS-7420", description: "Install a package audit tool" },
      { id: "PKGS-7346", description: "Purge old packages" },
    ] },
    "linux", "apt"
  );
  for (const control of ["PKGS-7420", "PKGS-7346"]) {
    const g = pkgs.find((x) => x.control === control);
    if (!g) { fail(`${control}: no generó finding`); continue; }
    if (/apt upgrade|apt-get upgrade/.test(g.command || "") || /apt upgrade/.test(g.fix || "")) {
      fail(`${control}: vuelve a proponer la actualización global («${g.command || g.fix}»)`);
    } else {
      ok(`${control}: ya no propone la actualización global del sistema`);
    }
  }

  // Y ningún fix puede volver a ser el marcador de posición por prefijo.
  const todos = fromLynisRaw(
    { hardeningIndex: null, warnings: [], suggestions: [
      { id: "BOOT-5122", description: "x" }, { id: "TOOL-5002", description: "x" },
      { id: "FIRE-4590", description: "x" }, { id: "ZZZZ-9999", description: "x" },
    ] },
    "linux", "apt"
  );
  const genericos = todos.filter((x) => /relacionada con/.test(x.fix || ""));
  if (genericos.length) {
    fail(`fix genérico "relacionada con" en: ${genericos.map((x) => x.control).join(", ")}`);
  } else {
    ok("ningún fix contiene el marcador de posición «relacionada con»");
  }
}

// ── Bloque 5 (opcional): trivy fs real ───────────────────────────────────────
function testRealTrivy(target) {
  log(`\n── trivy fs REAL sobre "${target}" ───────────────────────────────────`);
  let json;
  try {
    const out = execFileSync("trivy", ["fs", "--format", "json", "--quiet", "--scanners", "vuln", target], {
      timeout: 180000, maxBuffer: 128 * 1024 * 1024,
    });
    json = JSON.parse(out.toString());
  } catch (err) {
    const out = err.stdout ? err.stdout.toString() : "";
    if (out.trim()) { try { json = JSON.parse(out); } catch (_) { /* below */ } }
    if (!json) { log(`  (omitido: ${err.message.split("\n")[0]})`); return; }
  }

  const findings = fromTrivyJson(json, "HOST-CVE", "vulnerability", "trivy", { platform: process.platform });
  log(`  Findings generados: ${findings.length}`);
  const types = [...new Set((json.Results || []).map((r) => r.Type).filter(Boolean))];
  log(`  Types reportados por Trivy: ${types.join(", ") || "(ninguno)"}`);
  log("");
  for (const f of findings) {
    const flag = looksLikeCommand(f.fix) && f.isCommand !== true ? "  ⚠ REGRESIÓN" : "";
    log(`  ${f.id} · isCommand=${String(f.isCommand).padEnd(5)} · command=${f.command ? "«" + f.command + "»" : "null"}${flag}`);
    log(`      fix[0]: ${firstLine(f.fix)}`);
    assertConsistent(f.id, f);
  }
}

// ── Main ─────────────────────────────────────────────────────────────────────
function main() {
  log("═══════════════════════════════════════════════════════════════════");
  log(" COMMAND COVERAGE — invariante isCommand ↔ fix");
  log(`  Plataforma: ${process.platform}`);
  log("═══════════════════════════════════════════════════════════════════");

  testLangCmd();
  testOsTypes();
  testLangManual();
  testDeclaredNeverCommand();
  testLynisPkgs();

  const argv = process.argv.slice(2);
  const trivyIdx = argv.indexOf("--trivy");
  if (trivyIdx !== -1) {
    const target = argv[trivyIdx + 1] || ".";
    testRealTrivy(target);
  }

  log("\n═══════════════════════════════════════════════════════════════════");
  log(` Comprobaciones OK: ${checks} · Fallos: ${failures}`);
  log("═══════════════════════════════════════════════════════════════════");
  process.exit(failures > 0 ? 1 : 0);
}

main();
