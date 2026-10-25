"use strict";

/**
 * test-homedir-injection.js: un nombre de carpeta del home no puede ejecutar órdenes.
 * Crea carpetas llamadas `$(touch${IFS}SENTINEL)` y con comillas invertidas, y comprueba que
 * clasificarCarpeta(), ejecutarAFichero() y ejecutarTrivyFs() (con un trivy falso) no ejecutan nada.
 * No aplica a Windows. Uso: node test/manual/test-homedir-injection.js
 */

const fs   = require("fs");
const os   = require("os");
const path = require("path");

let failed = 0, passed = 0;
function ok(cond, label, detail) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}`); if (detail) console.log(`      ${detail}`); }
}

if (process.platform === "win32") {
  console.log("Windows: cmd.exe no interpreta $(...), el caso no aplica. Sin comprobar.");
  process.exit(0);
}

const tmp  = fs.mkdtempSync(path.join(os.tmpdir(), "lcaudit-test-homeinj-"));
const home = path.join(tmp, "home");
const bin  = path.join(tmp, "bin");
fs.mkdirSync(home);
fs.mkdirSync(bin);

// El testigo se crea en el directorio de trabajo del shell, que será `tmp`.
const TRAP     = "$(touch${IFS}SENTINEL)";
const TRAP_BQ  = "`touch${IFS}SENTINEL_BQ`";
const sentinel = path.join(tmp, "SENTINEL");
const sentBq   = path.join(tmp, "SENTINEL_BQ");
fs.mkdirSync(path.join(home, TRAP));
fs.mkdirSync(path.join(home, TRAP_BQ));
fs.mkdirSync(path.join(home, "normal"));
process.chdir(tmp);

// trivy falso: apunta el último argumento (la carpeta) y escribe un JSON válido en el -o.
const argsLog = path.join(tmp, "trivy-args.log");
fs.writeFileSync(path.join(bin, "trivy"),
  "#!/usr/bin/env node\n" +
  "const fs = require('fs');\n" +
  "const a = process.argv.slice(2);\n" +
  "if (a[0] === '--version') { console.log('Version: 0.0.0-fake'); process.exit(0); }\n" +
  `fs.appendFileSync(${JSON.stringify(argsLog)}, JSON.stringify(a) + '\\n');\n` +
  "const o = a[a.indexOf('-o') + 1];\n" +
  "fs.writeFileSync(o, JSON.stringify({ Results: [] }));\n",
  { mode: 0o755 });
process.env.PATH = `${bin}${path.delimiter}${process.env.PATH}`;
process.env.HOME = home;
delete process.env.SUDO_USER;

const { clasificarCarpeta }   = require("../../nodes/audit-host/modules/local-fs");
const { ejecutarAFichero }    = require("../../lib/executor");
const { ejecutarTrivyFs }    = require("../../nodes/audit-host/modules/trivy-fs");

(async () => {
  console.log("\n── 1 · clasificarCarpeta() sobre la carpeta trampa ─────────────────────\n");
  const cls = clasificarCarpeta(path.join(home, TRAP));
  clasificarCarpeta(path.join(home, TRAP_BQ));
  ok(!fs.existsSync(sentinel), "$(...) en el nombre no se ejecuta");
  ok(!fs.existsSync(sentBq), "comillas invertidas en el nombre no se ejecutan");
  ok(cls && cls.local === true, `la carpeta se clasifica como local (${cls && cls.detail})`);

  console.log("\n── 2 · ejecutarAFichero() con array de argumentos ──────────────────────\n");
  const lit = "$(touch${IFS}SENTINEL); `id` \"x\" 'y'";
  const parsed = await ejecutarAFichero((file) => [
    process.execPath, "-e",
    "require('fs').writeFileSync(process.argv[1], JSON.stringify({ v: process.argv[2] }))",
    file, lit,
  ], 10000);
  ok(parsed && parsed.v === lit, "el argumento llega literal al programa", JSON.stringify(parsed));
  ok(!fs.existsSync(sentinel), "y no se ejecuta nada");

  console.log("\n── 3 · ejecutarTrivyFs() sobre el home falso ──────────────────────────\n");
  const res = await ejecutarTrivyFs({});
  ok(!res.skipped, "el escaneo termina", res.reason);
  ok(!fs.existsSync(sentinel) && !fs.existsSync(sentBq), "ninguna carpeta trampa ejecuta su orden");
  const calls = fs.existsSync(argsLog)
    ? fs.readFileSync(argsLog, "utf8").trim().split("\n").map((l) => JSON.parse(l))
    : [];
  const targets = calls.map((a) => a[a.length - 1]);
  ok(targets.includes(path.join(home, TRAP)), "trivy recibe el nombre con $(...) como un único argumento", JSON.stringify(targets));
  ok(targets.includes(path.join(home, TRAP_BQ)), "y el de comillas invertidas también");
  ok(calls.every((a) => a[a.length - 2] === "--"), "la carpeta va detrás de \"--\"");
  const scanned = ((res.scan || {}).children || {}).scanned || [];
  ok(scanned.length === 3, `se escanean las tres carpetas (${scanned.length})`);

  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${passed} ok · ${failed} fallo(s)`);
  process.exit(failed ? 1 : 0);
})().catch((err) => { console.error(err); process.exit(1); });
