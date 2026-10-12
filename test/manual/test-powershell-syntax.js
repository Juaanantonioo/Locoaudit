"use strict";

/**
 * test-powershell-syntax.js — Los scripts de PowerShell que LoCoAudit GENERA compilan.
 *
 * Bug de un informe real de Windows: `$ErrorActionPreference='Stop' try { … }` ("Token 'try' inesperado"). WINDOWS_PS_SCRIPT
 * unía un array con " " y el script nunca compilaba, así que la consulta a Windows Update fallaba siempre.
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
// Se leen del módulo real, no se copian aquí: una copia se queda vieja y el test
// pasaría sobre un script que ya no es el que se ejecuta.
const pendingSrc = fs.readFileSync(
  path.join(__dirname, "../../nodes/audit-host/modules/pending-updates.js"), "utf8");
const { PS_UTF8_PRELUDE } = require("../../lib/executor");

/** Extrae una constante array-join del fuente y la evalúa. Sin require del módulo entero: en
 *  macOS/Linux no hace falta cargar sus dependencias solo para leer una cadena. */
function scriptFromSource(src, nombre) {
  const re = new RegExp("const " + nombre + " = \\[([\\s\\S]*?)\\]\\.join\\((\"[^\"]*\")\\);");
  const m = src.match(re);
  if (!m) throw new Error(`no se encontró ${nombre}`);
  // eslint-disable-next-line no-new-func
  return { texto: new Function(`return [${m[1]}].join(${m[2]})`)(), separador: JSON.parse(m[2]) };
}

const winUpdate = scriptFromSource(pendingSrc, "WINDOWS_PS_SCRIPT");

// security-events.js construye el suyo con una plantilla multilínea, no con join: se le pide
// al módulo, que es quien lo genera de verdad.
const secModule = require("../../nodes/audit-host/modules/security-events");

const SCRIPTS = [
  { nombre: "pending-updates · WINDOWS_PS_SCRIPT", texto: winUpdate.texto },
  { nombre: "executor · PS_UTF8_PRELUDE", texto: PS_UTF8_PRELUDE },
];
if (typeof secModule.buildWinEventsScript === "function") {
  SCRIPTS.push({
    nombre: "security-events · buildWinEventsScript(24)",
    texto: secModule.buildWinEventsScript(24),
  });
} else {
  console.log("  (buildWinEventsScript no está exportado: no se compila aquí)");
}

console.log("\n── A · Invariantes estructurales (sin PowerShell) ────────────────\n");

// La causa raíz, fijada directamente: unir con espacios pega sentencias.
ok(winUpdate.separador === "\n",
   "WINDOWS_PS_SCRIPT se une con saltos de línea, no con espacios",
   `separador actual: ${JSON.stringify(winUpdate.separador)}`);

// Y la forma exacta que falló.
// `[^\S\n]` y no `\s`: \s incluye el salto de línea, así que la versión arreglada —donde
// 'Stop' y try están en líneas distintas— también casaba y el test fallaba en verde.
ok(!/'Stop'[^\S\n]+try[^\S\n]*\{/.test(winUpdate.texto),
   "no queda `$ErrorActionPreference='Stop' try {` en una sola línea",
   JSON.stringify(winUpdate.texto.split("\n").slice(0, 2)));

for (const { nombre, texto } of SCRIPTS) {
  const llaves = (texto.match(/\{/g) || []).length - (texto.match(/\}/g) || []).length;
  ok(llaves === 0, `[${nombre}] llaves equilibradas`, `diferencia: ${llaves}`);

  const parens = (texto.match(/\(/g) || []).length - (texto.match(/\)/g) || []).length;
  ok(parens === 0, `[${nombre}] paréntesis equilibrados`, `diferencia: ${parens}`);

  // Ninguna línea puede tener una sentencia seguida de una palabra clave de bloque: es
  // exactamente la firma del bug. `} catch {` y `} else {` sí son válidas y se excluyen.
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
    // Se compila SIN ejecutar: ScriptBlock::Create parsea y lanza si la sintaxis es inválida.
    // El script va por fichero para no pelearse con el escapado de la línea de comandos, que es
    // justo la clase de problema que este test existe para detectar.
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
