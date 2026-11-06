"use strict";

/**
 * test-powershell-syntax.js — Los scripts de PowerShell que LoCoAudit GENERA compilan.
 *
 *   A) Estructural, en cualquier plataforma: unión por saltos de línea, llaves equilibradas, sin dos sentencias pegadas.
 *   B) Compilación real con [ScriptBlock]::Create(), solo si hay powershell o pwsh. Se salta con aviso explícito, nunca en silencio.
 * Uso: node test/manual/test-powershell-syntax.js
 */

const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");

let failed = 0;
let passed = 0;
let skipped = 0;

function ok(cond, label, detail) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}`); if (detail) console.log(`      ${detail}`); }
}

// ── Los scripts bajo prueba ──────────────────────────────────────────────────
// Se leen del módulo real, no se copian aquí.
const pendingSrc = fs.readFileSync(
  path.join(__dirname, "../../nodes/audit-host/modules/pending-updates.js"), "utf8");
const { PS_UTF8_PRELUDE } = require("../../lib/executor");

/** Extrae y evalúa una constante array-join del fuente, sin cargar el módulo entero. */
function scriptFromSource(src, nombre) {
  const re = new RegExp("const " + nombre + " = \\[([\\s\\S]*?)\\]\\.join\\((\"[^\"]*\")\\);");
  const m = src.match(re);
  if (!m) throw new Error(`no se encontró ${nombre}`);
  // eslint-disable-next-line no-new-func
  return { texto: new Function(`return [${m[1]}].join(${m[2]})`)(), separador: JSON.parse(m[2]) };
}

const winUpdate = scriptFromSource(pendingSrc, "WINDOWS_PS_SCRIPT");

// security-events.js usa una plantilla multilínea: se le pide el script al propio módulo.
const secModule = require("../../nodes/audit-host/modules/security-events");

// Discos e inventario de Windows exportan su script: se lee del módulo.
const { WINDOWS_DISK_PS_SCRIPT } = require("../../nodes/audit-host/modules/disk-storage");
const { WINDOWS_SW_PS_SCRIPT } = require("../../nodes/audit-host/modules/sw-inventory");

const SCRIPTS = [
  { nombre: "pending-updates · WINDOWS_PS_SCRIPT", texto: winUpdate.texto },
  { nombre: "executor · PS_UTF8_PRELUDE", texto: PS_UTF8_PRELUDE },
  { nombre: "disk-storage · WINDOWS_DISK_PS_SCRIPT", texto: WINDOWS_DISK_PS_SCRIPT },
  { nombre: "sw-inventory · WINDOWS_SW_PS_SCRIPT", texto: WINDOWS_SW_PS_SCRIPT },
];
if (typeof secModule.scriptEventosWindows === "function") {
  SCRIPTS.push({
    nombre: "security-events · scriptEventosWindows(24)",
    texto: secModule.scriptEventosWindows(24),
  });
} else {
  console.log("  (scriptEventosWindows no está exportado: no se compila aquí)");
}

console.log("\n── A · Invariantes estructurales (sin PowerShell) ────────────────\n");

// La causa raíz, fijada directamente: unir con espacios pega sentencias.
ok(winUpdate.separador === "\n",
   "WINDOWS_PS_SCRIPT se une con saltos de línea, no con espacios",
   `separador actual: ${JSON.stringify(winUpdate.separador)}`);

// La forma exacta que fallaba; `[^\S\n]` y no `\s`, que también casaría con el salto de línea.
ok(!/'Stop'[^\S\n]+try[^\S\n]*\{/.test(winUpdate.texto),
   "no queda `$ErrorActionPreference='Stop' try {` en una sola línea",
   JSON.stringify(winUpdate.texto.split("\n").slice(0, 2)));

for (const { nombre, texto } of SCRIPTS) {
  const llaves = (texto.match(/\{/g) || []).length - (texto.match(/\}/g) || []).length;
  ok(llaves === 0, `[${nombre}] llaves equilibradas`, `diferencia: ${llaves}`);

  const parens = (texto.match(/\(/g) || []).length - (texto.match(/\)/g) || []).length;
  ok(parens === 0, `[${nombre}] paréntesis equilibrados`, `diferencia: ${parens}`);

  // Ninguna sentencia seguida de palabra clave de bloque (`} catch {` y `} else {` sí valen).
  const pegadas = texto.split("\n").filter((l) => {
    const t = l.trim();
    if (!t || t.startsWith("}")) return false;
    return /[^;{}\s]\s+(try|if|foreach|while|switch|function)\s*[({]/.test(t);
  });
  ok(pegadas.length === 0,
     `[${nombre}] ninguna línea pega una sentencia a una palabra clave de bloque`,
     JSON.stringify(pegadas));
}

console.log("\n── B · Compilación real con [ScriptBlock]::Create() ──────────────\n");

/** powershell o pwsh, o null. Con `where`/`which` para no depender de este proyecto. */
function findPowerShell() {
  const buscar = process.platform === "win32" ? "where" : "which";
  for (const c of ["pwsh", "powershell"]) {
    try {
      const out = execSync(`${buscar} ${c}`, { stdio: ["ignore", "pipe", "ignore"] }).toString().trim();
      if (out) return c;
    } catch (_) { /* no está: se prueba el siguiente */ }
  }
  return null;
}

const shell = findPowerShell();

if (!shell) {
  skipped = SCRIPTS.length;
  console.log("  ⚠ Ni pwsh ni powershell en este equipo: la compilación real NO se ha ejecutado.");
  console.log("    El nivel A sí ha corrido. En Windows y en cualquier equipo con pwsh, este");
  console.log("    bloque compila los scripts de verdad y es el que caza los errores de sintaxis");
  console.log("    que las invariantes no cubren.");
} else {
  console.log(`  Compilando con: ${shell}\n`);
  for (const { nombre, texto } of SCRIPTS) {
    // Se compila sin ejecutar; el script va por fichero para evitar el escapado de la línea de órdenes.
    const tmp = path.join(os.tmpdir(), `lcaudit-syntax-${process.pid}-${Math.random().toString(16).slice(2)}.ps1`);
    fs.writeFileSync(tmp, "﻿" + texto, "utf8");
    const comprobador = path.join(os.tmpdir(), `lcaudit-check-${process.pid}-${Math.random().toString(16).slice(2)}.ps1`);
    fs.writeFileSync(comprobador, "﻿" + [
      "$ErrorActionPreference = 'Stop'",
      `$src = Get-Content -Raw -LiteralPath '${tmp}'`,
      "$errs = $null",
      "[void][System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$null, [ref]$errs)",
      "if ($errs -and $errs.Count -gt 0) { $errs | ForEach-Object { $_.Message }; exit 1 }",
      "exit 0",
    ].join("\n"), "utf8");

    let salida = "";
    let rc = 0;
    try {
      salida = execSync(
        `${shell} -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "${comprobador}"`,
        { stdio: ["ignore", "pipe", "pipe"], timeout: 30000 }
      ).toString();
    } catch (err) {
      rc = err.status == null ? 1 : err.status;
      salida = ((err.stdout && err.stdout.toString()) || "") +
               ((err.stderr && err.stderr.toString()) || "");
    } finally {
      fs.rmSync(tmp, { force: true });
      fs.rmSync(comprobador, { force: true });
    }

    ok(rc === 0, `[${nombre}] compila sin errores de sintaxis`, salida.trim().split("\n")[0]);
  }
}

console.log(`\n${passed} pasados · ${failed} fallidos${skipped ? ` · ${skipped} sin comprobar (falta PowerShell)` : ""}\n`);
process.exit(failed > 0 ? 1 : 0);
