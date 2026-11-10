"use strict";

/**
 * test-trivy-sueltos.js — La pasada de secretos revisa los ficheros sueltos del home, no solo sus carpetas.
 * Usa un `trivy` falso en el PATH que anota qué recibe, así que no hace falta Trivy instalado.
 * Uso: node test/manual/test-trivy-sueltos.js
 */

const fs = require("fs");
const os = require("os");
const path = require("path");

let failed = 0;
let passed = 0;

function ok(cond, label, detail) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}`); if (detail) console.log(`      ${detail}`); }
}

if (process.platform === "win32") {
  console.log("  (se omite en Windows: el trivy falso es un script de shell)");
  process.exit(0);
}

const base = fs.mkdtempSync(path.join(os.tmpdir(), "lcaudit-sueltos-"));
const bin = path.join(base, "bin");
const home = path.join(base, "home");
const registro = path.join(base, "objetivos.txt");
fs.mkdirSync(bin);
fs.mkdirSync(path.join(home, "Documentos"), { recursive: true });

// Trivy falso: apunta el objetivo (lo que va tras "--") y deja un JSON con un resultado por objetivo.
fs.writeFileSync(path.join(bin, "trivy"), `#!/bin/sh
if [ "$1" = "--version" ]; then echo "Version: 0.0.0-falso"; exit 0; fi
out=""; prev=""; obj=""; tras=0
for a in "$@"; do
  if [ "$tras" = 1 ]; then obj="$a"; fi
  [ "$a" = "--" ] && tras=1
  [ "$prev" = "-o" ] && out="$a"
  prev="$a"
done
echo "$obj" >> "${registro}"
nombre=$(basename "$obj")
printf '{"SchemaVersion":2,"Results":[{"Target":"%s","Class":"secret"}]}' "$nombre" > "$out"
`, { mode: 0o755 });

fs.writeFileSync(path.join(home, "claves_aws.txt"), "AWS_ACCESS_KEY_ID=fixture\n");
fs.writeFileSync(path.join(home, "id_rsa_copia"), "clave de prueba\n");
fs.writeFileSync(path.join(home, ".env"), "TOKEN=fixture\n");
fs.writeFileSync(path.join(home, "Documentos", "notas.txt"), "nada\n");
fs.symlinkSync(path.join(home, ".env"), path.join(home, "enlace.env"));

const antes = { PATH: process.env.PATH, HOME: process.env.HOME, SUDO_USER: process.env.SUDO_USER };
process.env.PATH = `${bin}${path.delimiter}${process.env.PATH}`;
process.env.HOME = home;
delete process.env.SUDO_USER;

const { ejecutarTrivySecretos, ficherosSueltos, MAX_SUELTOS } = require("../../nodes/audit-host/modules/trivy-fs");

(async () => {
  console.log("\n── Ficheros sueltos de la raíz del home ──────────────────────────\n");

  const r = await ejecutarTrivySecretos({});
  const objetivos = fs.readFileSync(registro, "utf8").split("\n").filter(Boolean);

  ok(!r.skipped, "la pasada de secretos termina", r.reason);
  ok(objetivos.includes(path.join(home, "claves_aws.txt")), "un fichero suelto cualquiera llega a Trivy (claves_aws.txt)");
  ok(objetivos.includes(path.join(home, "id_rsa_copia")), "un fichero sin extensión también (id_rsa_copia)");
  ok(objetivos.includes(path.join(home, ".env")), "los de la lista antigua siguen revisándose (.env)");
  ok(!objetivos.includes(path.join(home, "enlace.env")), "un enlace simbólico no se sigue");
  ok(objetivos.includes(path.join(home, "Documentos")), "las carpetas siguen revisándose por separado");

  const sueltos = (r.scan && r.scan.rootFiles) || [];
  ok(sueltos.includes("claves_aws.txt") && sueltos.includes("id_rsa_copia"),
     "scan.rootFiles anota los ficheros revisados", JSON.stringify(sueltos));

  const res = (r.Results || []).find((x) => x.Target === "claves_aws.txt");
  ok(res && res.__root === home, "el resultado lleva como raíz la carpeta del fichero", res && res.__root);

  console.log("\n── Tope por carpeta ──────────────────────────────────────────────\n");

  const muchos = path.join(base, "muchos");
  fs.mkdirSync(muchos);
  for (let i = 0; i < MAX_SUELTOS + 5; i++) fs.writeFileSync(path.join(muchos, `f${String(i).padStart(4, "0")}.txt`), "x");
  const t = ficherosSueltos(muchos, "muchos");
  ok(t.items.length === MAX_SUELTOS && t.sobran === 5,
     `de ${MAX_SUELTOS + 5} ficheros se revisan ${MAX_SUELTOS} y se cuentan 5 como no revisados`,
     `items ${t.items.length}, sobran ${t.sobran}`);
  ok(t.items[0].name === "muchos/f0000.txt", "el nombre lleva el prefijo de la carpeta y el orden es alfabético", t.items[0].name);
  ok(ficherosSueltos(path.join(base, "no-existe"), "").items.length === 0, "una carpeta ilegible no rompe nada");

  process.env.PATH = antes.PATH;
  process.env.HOME = antes.HOME;
  if (antes.SUDO_USER !== undefined) process.env.SUDO_USER = antes.SUDO_USER;
  fs.rmSync(base, { recursive: true, force: true });

  console.log(`\n${passed} pasados · ${failed} fallidos\n`);
  process.exit(failed > 0 ? 1 : 0);
})();
