"use strict";

/**
 * test-network-recommendations.js — Las recomendaciones de puertos abiertos, por sistema.
 *   1. No se deshabilita un X.socket inexistente (systemd 255 rechazaría la orden entera).
 *   2. macOS no recibe órdenes de Linux.
 *   3. El nombre de la unidad depende de la distribución (ssh/sshd, apache2/httpd, smbd/smb).
 *   4. En Windows, el puerto 23 no remite al cliente Telnet.
 *   5. Endurecer SSH avisa antes de desactivar PasswordAuthentication.
 *   6. Telnet en Debian va por inetd, no por telnet.service.
 *
 * Uso: node test/manual/test-network-recommendations.js
 */

const fs   = require("fs");
const os   = require("os");
const path = require("path");
const { execSync } = require("child_process");

const { systemdDisable, getFixForProcess } = require("../../lib/process-fix");
const { getFixForPort } = require("../../nodes/audit-network/modules/network-utils");
const { PORT_CATALOG }  = require("../../nodes/audit-network/modules/port-catalog");

let failed = 0, passed = 0, skipped = 0;
function ok(cond, label, detail) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}`); if (detail) console.log(`      ${detail}`); }
}

// ── 1 · La orden de systemd, contra systemctl de verdad ───────────────────────────────────────
console.log("\n── 1 · systemdDisable(): funciona con y sin .socket ──────────────\n");

const cmd = systemdDisable("nginx");
ok(/^sudo systemctl disable --now nginx\.service && \{ sudo systemctl disable --now nginx\.socket 2>\/dev\/null \|\| true; \}$/.test(cmd),
   "el .service va primero y el .socket no puede hacer fallar la línea", cmd);

let systemctl = null;
try { systemctl = execSync("command -v systemctl", { stdio: ["ignore", "pipe", "ignore"] }).toString().trim(); } catch (_) {}
if (!systemctl || process.platform !== "linux") {
  console.log("  ⊘ sin systemctl en este equipo: se omite la prueba contra systemd real");
  skipped++;
} else {
  // Un árbol de unidades propio con --root: no toca el sistema que ejecuta el test.
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "lcaudit-test-systemd-"));
  const units = path.join(root, "usr/lib/systemd/system");
  fs.mkdirSync(units, { recursive: true });
  // Con --root y sin systemd en marcha, systemctl no crea los directorios .wants de los targets.
  for (const w of ["multi-user.target.wants", "sockets.target.wants"]) {
    fs.mkdirSync(path.join(root, "etc/systemd/system", w), { recursive: true });
  }
  fs.writeFileSync(path.join(units, "demo.service"),
    "[Unit]\nDescription=demo\n[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=multi-user.target\n");
  const run = (c) => { try { execSync(c, { stdio: "ignore", shell: "/bin/bash" }); return 0; } catch (e) { return e.status || 1; } };
  // lstat y no existsSync: el enlace es absoluto y fuera de --root no se resolvería.
  const linkExists = (rel) => { try { fs.lstatSync(path.join(root, rel)); return true; } catch (_) { return false; } };
  const enabled = () => linkExists("etc/systemd/system/multi-user.target.wants/demo.service");
  // Con --root no se admite --now: se prueba solo deshabilitar.
  const enRoot = (c) => c.replace(/sudo systemctl disable --now/g, `systemctl --root=${root} disable`);

  run(`systemctl --root=${root} enable demo.service`);
  // La forma con .socket depende de la versión de systemd: se registra, no se exige.
  const version = (() => { try { return execSync("systemctl --version", { stdio: ["ignore", "pipe", "ignore"] }).toString().split("\n")[0]; } catch (_) { return "?"; } })();
  const antigua = run(`systemctl --root=${root} disable demo.service demo.socket`);
  console.log(`  · ${version}: la forma anterior ${antigua !== 0 && enabled() ? "FALLA y deja el servicio habilitado" : "deshabilita el servicio"}`);
  run(`systemctl --root=${root} enable demo.service`);

  const nueva = run(enRoot(systemdDisable("demo")));
  ok(nueva === 0 && !enabled(), "la forma nueva, sin .socket, deshabilita el servicio y termina con 0");

  fs.writeFileSync(path.join(units, "demo.socket"),
    "[Unit]\nDescription=demo\n[Socket]\nListenStream=12345\n[Install]\nWantedBy=sockets.target\n");
  for (const w of ["multi-user.target.wants", "sockets.target.wants"]) {
    fs.mkdirSync(path.join(root, "etc/systemd/system", w), { recursive: true });
  }
  run(`systemctl --root=${root} enable demo.service demo.socket`);
  const conSocket = run(enRoot(systemdDisable("demo")));
  const socketOn = linkExists("etc/systemd/system/sockets.target.wants/demo.socket");
  ok(conSocket === 0 && !enabled() && !socketOn, "con .socket, deshabilita las dos unidades");
  fs.rmSync(root, { recursive: true, force: true });
}

// ── 2 · macOS nunca recibe órdenes de Linux ───────────────────────────────────────────────────
console.log("\n── 2 · Ninguna recomendación de macOS o Windows usa systemctl ────\n");

const LINUX_ONLY = /systemctl|\/etc\/mysql|apt |dnf |pacman /;
for (const plat of ["darwin", "win32"]) {
  const malos = Object.keys(PORT_CATALOG).map(Number)
    .filter((p) => LINUX_ONLY.test(getFixForPort(p, plat) || ""));
  ok(malos.length === 0, `${plat}: ningún puerto del catálogo propone órdenes de Linux`, JSON.stringify(malos));
}
for (const proc of ["mysqld", "mariadb", "postgres", "redis", "mongod", "nginx", "smbd", "sshd", "apache"]) {
  ok(!LINUX_ONLY.test(getFixForProcess(proc, "darwin") || ""), `macOS · ${proc}: sin órdenes de Linux`,
     getFixForProcess(proc, "darwin"));
}

// ── 3 · El nombre de la unidad según la distribución ──────────────────────────────────────────
console.log("\n── 3 · Nombre de la unidad por gestor de paquetes ────────────────\n");

const UNIDADES = [
  ["sshd",    "apt",    /ssh\.service/,     /sshd\.service/],
  ["sshd",    "pacman", /sshd\.service/,    /\bssh\.service/],
  ["sshd",    "dnf",    /sshd\.service/,    /\bssh\.service/],
  ["apache2", "apt",    /apache2\.service/, /httpd\.service/],
  ["httpd",   "dnf",    /httpd\.service/,   /apache2\.service/],
  ["smbd",    "pacman", /smb\.service/,     /smbd\.service/],
];
for (const [proc, mgr, debe, noDebe] of UNIDADES) {
  const t = getFixForProcess(proc, "linux", mgr);
  ok(debe.test(t) && !noDebe.test(t), `${proc} con ${mgr}`, t);
}
const sinGestor = getFixForProcess("sshd", "linux", null);
ok(/ssh\.service/.test(sinGestor) && /sshd/.test(sinGestor.split("\n")[1] || ""),
   "sin gestor conocido: nombre de Debian y una nota con el de Arch y Fedora", sinGestor);

// ── 4 · Telnet ────────────────────────────────────────────────────────────────────────────────
console.log("\n── 4 · Telnet ────────────────────────────────────────────────────\n");

const tWin = getFixForPort(23, "win32");
ok(!/cliente Telnet/i.test(tWin) && /netstat -ano \| findstr :23/.test(tWin),
   "Windows: identifica el programa que abre el 23, no el cliente Telnet", tWin);
ok(/sudo apt remove --purge telnetd/.test(getFixForPort(23, "linux", "apt")) &&
   !/telnet\.service/.test(getFixForPort(23, "linux", "apt")),
   "Debian: desinstala telnetd en vez de una unidad telnet.service inexistente");
ok(/sudo dnf remove telnet-server/.test(getFixForPort(23, "linux", "dnf")), "Fedora: desinstala telnet-server");

// ── 5 · SSH: no dejar al usuario fuera ────────────────────────────────────────────────────────
console.log("\n── 5 · SSH avisa antes de desactivar las contraseñas ─────────────\n");

for (const plat of ["linux", "darwin"]) {
  const t = getFixForPort(22, plat, "apt");
  ok(/PasswordAuthentication no/.test(t) && /Sin una clave configurada/.test(t),
     `${plat}: PasswordAuthentication no va con el aviso de quedarse sin acceso`);
  ok(/sshd -T/.test(t), `${plat}: comprueba la configuración efectiva con sshd -T`);
}

console.log(`\n${passed} ok · ${failed} fallo(s)` + (skipped ? ` · ${skipped} omitido(s)` : "") + "\n");
process.exit(failed ? 1 : 0);
