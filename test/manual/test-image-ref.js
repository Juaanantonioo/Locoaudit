"use strict";

/**
 * test-image-ref.js: qué referencia de imagen llega a la línea de órdenes de trivy.
 * Comprueba isValidImageRef() y que una referencia con shell no ejecuta nada.
 * Uso: node test/manual/test-image-ref.js
 */

const fs   = require("fs");
const os   = require("os");
const path = require("path");

let failed = 0, passed = 0;
function ok(cond, label, detail) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}`); if (detail) console.log(`      ${detail}`); }
}

// ── trivy falso en un PATH propio, ANTES de cargar ningún módulo ────────────────────────────
const isWin   = process.platform === "win32";
const tmp     = fs.mkdtempSync(path.join(os.tmpdir(), "lcaudit-test-imgref-"));
const witness = path.join(tmp, "trivy-was-called");
const pwned   = path.join(tmp, "pwned");
if (!isWin) {
  fs.writeFileSync(path.join(tmp, "trivy"),
    "#!/bin/sh\n" +
    `echo called >> "${witness}"\n` +
    'echo \'{"ArtifactName":"x","Results":[]}\'\n',
    { mode: 0o755 });
  process.env.PATH = `${tmp}${path.delimiter}${process.env.PATH}`;
}

const { isValidImageRef, runTrivyImage } = require("../../nodes/audit-image/modules/cve-checker");

// ── 1 · isValidImageRef ─────────────────────────────────────────────────────────────────────
console.log("\n── 1 · isValidImageRef(): qué es una referencia de imagen ────────\n");

const VALIDAS = [
  "nginx",
  "nginx:latest",
  "library/nginx:1.27-alpine",
  "ghcr.io/aquasecurity/trivy:0.58.1",
  "ghcr.io:443/user/repo:1.2",
  "localhost:5000/mi_app__v2:dev",
  "registry.example.com/a/b/c",
  "nginx@sha256:" + "a".repeat(64),
  "nginx:1.27@sha256:" + "0123456789abcdef".repeat(4),
  "sha256:" + "b".repeat(64),   // el ID que da docker images para una imagen sin nombre
  "4f2b6e7d8c9a",
];
for (const r of VALIDAS) ok(isValidImageRef(r), `acepta ${r.length > 50 ? r.slice(0, 50) + "…" : r}`);

const INVALIDAS = [
  "",
  "nginx; id",
  "nginx && id",
  "nginx | id",
  "nginx`id`",
  "nginx$(id)",
  "nginx > /tmp/x",
  "nginx latest",
  "-q",
  "--server=http://evil",
  "nginx\nid",
  "Nginx",                       // el repositorio va en minúsculas
  "nginx:" + "t".repeat(200),
  "\"nginx\"",
  "nginx & calc.exe",
  "nginx%PATH%",
];
for (const r of INVALIDAS) ok(!isValidImageRef(r), `rechaza ${JSON.stringify(r).slice(0, 50)}`);

// ── 2 · runTrivyImage con una referencia inyectada ──────────────────────────────────────────
async function main() {
  console.log("\n── 2 · runTrivyImage() no lanza la orden inyectada ──────────────\n");
  if (isWin) {
    console.log("  (omitido en Windows: el trivy falso es un script de sh)");
  } else {
    const ref = `lca-dummy; echo INJECTED > "${pwned}"; #`;
    const r = await runTrivyImage([{ id: ref, repository: "", tag: "" }], 5000);
    ok(!fs.existsSync(pwned), "la orden inyectada no se ejecutó");
    ok(!fs.existsSync(witness), "trivy no llegó a lanzarse");
    ok(r && Array.isArray(r.failed) && r.failed.length === 1, "la imagen sale en failed", JSON.stringify(r && r.failed));
    ok(r && r.failed && /^INVALID_REF:/.test(r.failed[0].error), "con motivo INVALID_REF", JSON.stringify(r && r.failed));

    const okRef = await runTrivyImage([{ id: "nginx:latest", repository: "", tag: "" }], 5000);
    ok(fs.existsSync(witness), "una referencia válida sí lanza trivy");
    ok(okRef && okRef.failed && okRef.failed.length === 0, "y no sale como fallida", JSON.stringify(okRef && okRef.failed));
  }

  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${passed} ok · ${failed} fallo(s)\n`);
  process.exit(failed ? 1 : 0);
}

main().catch((err) => { console.error(err); process.exit(1); });
