"use strict";

/**
 * test-lynis-i18n.js — Traducción de Lynis al castellano.
 *
 * Lynis escribe sus sugerencias en inglés. LoCoAudit las traduce con una tabla ESTÁTICA indexada
 * por ID de control (lib/lynis-i18n.js), y este test fija las tres propiedades que la hacen
 * utilizable en un informe de auditoría:
 *
 *   1. DETERMINISMO. Nada de LLM: es opcional y no determinista, y dos ejecuciones sobre el mismo
 *      .dat darían dos informes distintos. Un informe que no se puede reproducir no vale como
 *      evidencia.
 *   2. NUNCA SE QUEDA MUDA. Sin entrada en la tabla sale el texto original en inglés con una nota
 *      que lo dice. Nunca una cadena vacía y nunca el ID pelado: "AUTH-9286" no informa a nadie.
 *   3. COBERTURA HONESTA. La tabla cubre los controles vistos en los informes de referencia, no
 *      el catálogo entero de Lynis (300+). El informe enseña cuántos ha traducido de cuántos ha
 *      encontrado, en vez de presumir cobertura total.
 *
 * Uso:
 *   node test/manual/test-lynis-i18n.js
 */

const { LYNIS_ES, LYNIS_ES_IDS, lynisText, lynisFix, lynisCoverage, lynisControlUrl,
        pickLynisDiscriminators } = require("../../lib/lynis-i18n");
const { installCmd } = require("../../lib/pkg-manager");
const { fromLynisRaw } = require("../../lib/normalizer");

let failed = 0;
let passed = 0;

function ok(cond, label, detail) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}`); if (detail) console.log(`      ${detail}`); }
}

// Los controles que aparecen de verdad en los informes de referencia. Windows no aporta ninguno:
// Lynis no corre ahí.
const DEBIAN = `ACCT-9622 ACCT-9626 ACCT-9628 AUTH-9230 AUTH-9262 AUTH-9282 AUTH-9286 AUTH-9328
BANN-7126 BANN-7130 BOOT-5122 BOOT-5180 BOOT-5264 DEB-0280 DEB-0810 DEB-0831 DEB-0880 FILE-6310
FILE-7524 FINT-4350 HRDN-7222 HRDN-7230 LOGG-2154 LOGG-2190 NAME-4028 NETW-3200 PKGS-7346
PKGS-7370 PKGS-7394 PKGS-7410 PKGS-7420 PRNT-2307 PROC-3614 STRG-1846 TOOL-5002 USB-1000`.split(/\s+/);
const MACOS = `FIRE-4590 HOME-9304 HTTP-6640 HTTP-6643 NAME-4404 NETW-2704 NETW-2705 PKGS-7398`
  .split(/\s+/);
const TODOS = [...DEBIAN, ...MACOS];

console.log("\n── 1 · Cobertura exacta de los informes de referencia ────────────\n");

const cov = lynisCoverage(TODOS);
console.log(`  ${cov.translated}/${cov.total} controles traducidos`);

ok(TODOS.length === 44, `los informes aportan 44 controles`, String(TODOS.length));
ok(cov.total === 44, "lynisCoverage los cuenta todos", String(cov.total));
ok(cov.missing.length === 0,
   "los 44 están en la tabla", JSON.stringify(cov.missing));

// Sin controles de más: cada entrada tiene que responder a algo visto de verdad. Traducir a
// ciegas el catálogo entero sería inventar texto sobre comprobaciones que nadie ha ejecutado.
const sobrantes = LYNIS_ES_IDS.filter((id) => !TODOS.includes(id));
ok(sobrantes.length === 0,
   "y ninguno de más: la tabla no traduce a ciegas", JSON.stringify(sobrantes));

console.log("\n── 2 · Las traducciones son utilizables ──────────────────────────\n");

const vacios = LYNIS_ES_IDS.filter((id) => !LYNIS_ES[id].es || LYNIS_ES[id].es.trim().length < 20);
ok(vacios.length === 0, "ninguna traducción vacía ni de una palabra", JSON.stringify(vacios));

// El ID no puede aparecer dentro del texto: la tarjeta ya lo lleva como metadato, y repetirlo
// dentro de la frase es el ruido que se quitó al dejar de encabezar el título con el código.
const conCodigo = LYNIS_ES_IDS.filter((id) => LYNIS_ES[id].es.includes(id));
ok(conCodigo.length === 0, "ninguna traducción repite el código del control", JSON.stringify(conCodigo));

// Sin inglés colado.
const RE_EN = /\b(the|should|enable|disable|install|configure|check|missing|found|hardening)\b/i;
const conIngles = LYNIS_ES_IDS.filter((id) => RE_EN.test(LYNIS_ES[id].es));
ok(conIngles.length === 0, "ninguna traducción se ha quedado en inglés", JSON.stringify(conIngles));

console.log("\n── 3 · Sin entrada, nunca se queda muda ──────────────────────────\n");

const desconocido = lynisText("ZZZZ-9999", "Some brand new Lynis control");
ok(desconocido.text === "Some brand new Lynis control",
   "control sin traducir → texto original en inglés", desconocido.text);
ok(desconocido.translated === false, "y marcado como no traducido");

// El peor caso: ni traducción ni original. Ni cadena vacía ni el ID a secas.
const nada = lynisText("ZZZZ-9999", "");
ok(nada.text.length > 10, "sin original tampoco devuelve cadena vacía", JSON.stringify(nada.text));
ok(nada.text !== "ZZZZ-9999", "ni el ID pelado", nada.text);
ok(nada.text.includes("ZZZZ-9999") && /Lynis/.test(nada.text),
   "sino una frase que dice qué es", nada.text);
ok(nada.translated === false, "y también marcado como no traducido");

// Insensible a mayúsculas y espacios: el ID viene del .dat y no siempre está limpio.
ok(lynisText(" usb-1000 ", "x").translated === true,
   "el ID se normaliza (minúsculas y espacios)");

console.log("\n── 4 · Determinista: mismas entradas, mismas salidas ─────────────\n");

// La razón de no usar el LLM, comprobada: mil llamadas, un solo resultado.
const primera = TODOS.map((id) => lynisText(id, "original").text).join("|");
let estable = true;
for (let i = 0; i < 1000; i++) {
  if (TODOS.map((id) => lynisText(id, "original").text).join("|") !== primera) { estable = false; break; }
}
ok(estable, "1000 pasadas dan exactamente el mismo texto");

console.log("\n── 5 · Integración: el finding lleva la traducción y el flag ─────\n");

const raw = {
  hardeningIndex: 70, version: "3.1.4", testsDone: 251,
  warnings: [],
  suggestions: [
    { id: "USB-1000", description: "Disable drivers like USB storage when not used", detail: null, solution: null },
    { id: "ZZZZ-9999", description: "Brand new control never seen before", detail: null, solution: null },
    { id: "AUTH-9286", description: "Configure minimum password age in /etc/login.defs", detail: null, solution: null },
    { id: "AUTH-9286", description: "Configure maximum password age in /etc/login.defs", detail: null, solution: null },
  ],
};
const f = fromLynisRaw(raw, "linux", "apt");

const usb = f.find((x) => x.control === "USB-1000");
ok(usb.translated === true, "USB-1000 sale traducido");
ok(/almacenamiento USB/i.test(usb.title), "y su título está en castellano", usb.title);
ok(usb.evidence.includes("Disable drivers like USB storage"),
   "el original de Lynis se conserva en la evidencia");

const zz = f.find((x) => x.control === "ZZZZ-9999");
ok(zz.translated === false, "el desconocido sale marcado como no traducido");
ok(zz.title === "Brand new control never seen before", "con su título original", zz.title);
ok(/no está traducido/i.test(zz.evidence),
   "y una nota en la evidencia que lo explica", zz.evidence);

// Un mismo control con dos sugerencias distintas: la traducción es la misma, así que lo que las
// distingue tiene que llegar al título o las dos tarjetas parecen duplicadas.
const auth = f.filter((x) => x.control === "AUTH-9286");
ok(auth.length === 2, "AUTH-9286 produce dos findings", String(auth.length));
ok(new Set(auth.map((x) => x.title)).size === 2,
   "y sus títulos siguen siendo distintos", JSON.stringify(auth.map((x) => x.title)));
ok(auth.every((x) => /caducidad/i.test(x.title)),
   "los dos llevan la traducción del control");
// El matiz es ahora "mínima"/"máxima" y no la frase inglesa entera: el paréntesis dejó de
// volcar la descripción de Lynis y extrae solo lo que distingue una entrada de la otra.
ok(auth.some((x) => /\(mínima\)/.test(x.title)) && auth.some((x) => /\(máxima\)/.test(x.title)),
   "y cada uno el matiz que lo distingue, en castellano",
   JSON.stringify(auth.map((x) => x.title)));
ok(auth.every((x) => !/minimum|maximum|login\.defs/i.test(x.title)),
   "sin arrastrar el inglés original al título", JSON.stringify(auth.map((x) => x.title)));

// El caso normal —un control, una tarjeta— NO se ensucia con el paréntesis.
ok(!usb.title.includes("("), "un control que sale una sola vez conserva el título limpio", usb.title);

console.log("\n── 6 · Los fixes van por CONTROL, no por prefijo ─────────────────\n");

// Los cinco casos medidos sobre informes reales en los que la tabla POR PREFIJO daba la solución
// de otro problema. Cada uno con lo que la solución correcta tiene que mencionar.
const CASOS = [
  { id: "BOOT-5122", plat: "linux",  debe: /grub-mkpasswd|superusers/i,
    noDebe: /servicios que arrancan|systemctl list-unit-files/i,
    nota: "GRUB sin contraseña → contraseña de GRUB, no 'revisar servicios de arranque'" },
  // PKGS-7420 es "Detect toolkit to automatically download and apply upgrades" (Lynis 3.1.8). La
  // versión anterior de este caso exigía debsecan, que es la herramienta de OTRO control (PKGS-7398).
  { id: "PKGS-7420", plat: "linux",  debe: /unattended-upgrades|dnf-automatic/i,
    noDebe: /apt upgrade|debsecan/i,
    nota: "sin actualizaciones automáticas → unattended-upgrades, no 'apt upgrade' ni debsecan" },
  { id: "PKGS-7398", plat: "darwin", debe: /Trivy/i,
    noDebe: /brew upgrade|actualizar los paquetes/i,
    nota: "sin herramienta de auditoría → no 'brew upgrade'" },
  // FIRE-4590 sale cuando Lynis NO encuentra un cortafuegos activo (FIREWALL_ACTIVE=0, en el
  // código de Lynis 3.1.8 y en el informe real de macOS: "Configure a firewall/packet filter").
  // La versión anterior de este caso exigía activar el REGISTRO, que es otro problema.
  { id: "FIRE-4590", plat: "darwin", debe: /--getglobalstate/i,
    noDebe: /setloggingmode/i,
    nota: "sin cortafuegos activo → comprobar y activar el cortafuegos, no su registro" },
  // Controles que el diccionario tenía cruzados o con el significado de otro control. Cada uno con
  // el texto que Lynis emite de verdad (tests_* de 3.1.8 o informes reales de test/fixtures/lynis).
  { id: "HTTP-6640", plat: "linux",  debe: /mod_evasive/i, noDebe: /ModSecurity/i,
    nota: "HTTP-6640 es 'Install Apache mod_evasive', no ModSecurity" },
  { id: "HTTP-6643", plat: "linux",  debe: /ModSecurity/i, noDebe: /mod_evasive/i,
    nota: "HTTP-6643 es 'Install Apache modsecurity', no mod_evasive" },
  { id: "LOGG-2190", plat: "linux",  debe: /lsof \+L1/, noDebe: /logrotate/i,
    nota: "LOGG-2190 es 'Check what deleted files are still in use', no la rotación de logs" },
  { id: "STRG-1846", plat: "linux",  debe: /firewire/i, noDebe: /squashfs/i,
    nota: "STRG-1846 es 'Check if firewire storage is disabled', no squashfs" },
  { id: "PKGS-7394", plat: "linux",  debe: /apt-show-versions/, noDebe: /unattended/i,
    nota: "PKGS-7394 es 'Install package apt-show-versions'" },
  { id: "PRNT-2307", plat: "linux",  debe: /chmod 640 \/etc\/cups\/cupsd\.conf/, noDebe: /Listen localhost/i,
    nota: "PRNT-2307 son los permisos del fichero de CUPS; escuchar en red es PRNT-2308" },
  { id: "HOME-9304", plat: "linux",  debe: /chmod 750/, noDebe: /chmod 600/,
    nota: "HOME-9304 son los permisos de los directorios personales (750), no de sus ficheros" },
  { id: "DEB-0880",  plat: "linux",  debe: /fail2ban/, noDebe: /apt-show-versions/,
    nota: "DEB-0880 es fail2ban (parche de Debian, informe real de Lynis 3.0.8)" },
  { id: "DEB-0280",  plat: "linux",  debe: /libpam-tmpdir/, noDebe: /apt-listbugs/,
    nota: "DEB-0280 es libpam-tmpdir" },
  { id: "DEB-0831",  plat: "linux",  debe: /needrestart/, noDebe: /debsums/,
    nota: "DEB-0831 es needrestart" },
  { id: "TOOL-5002", plat: "linux",  debe: /configuraci[oó]n de un equipo|repetible/i,
    noDebe: /rkhunter|chkrootkit|aide/i,
    nota: "gestión de configuración → no herramientas de detección de intrusiones" },
  { id: "ACCT-9626", plat: "linux",  debe: /sysstat/i,
    noDebe: /auditd/i,
    nota: "sysstat → sysstat, no auditd" },
];

for (const c of CASOS) {
  const r = lynisFix(c.id, c.plat, "apt", installCmd);
  const texto = `${r.fix || ""} ${r.command || ""}`;
  ok(!!r.fix, `[${c.id}] tiene fix en ${c.plat}`, JSON.stringify(r));
  ok(c.debe.test(texto), `[${c.id}] la solución menciona lo que toca — ${c.nota}`, texto.slice(0, 120));
  ok(!c.noDebe.test(texto), `[${c.id}] y ya NO la solución de otro problema`, texto.slice(0, 120));
}

// La regla general: ningún fix puede ser el marcador de posición de la tabla por prefijo.
const conPlaceholder = LYNIS_ES_IDS.filter((id) => {
  for (const plat of ["linux", "darwin"]) {
    const r = lynisFix(id, plat, "apt", installCmd);
    if (r.fix && /relacionada con/i.test(r.fix)) return true;
  }
  return false;
});
ok(conPlaceholder.length === 0,
   "ningún fix de los 44 contiene «relacionada con»", JSON.stringify(conPlaceholder));

// Y ninguno puede quedar en cadena vacía: o hay texto, o no hay campo.
const vaciosFix = LYNIS_ES_IDS.filter((id) => {
  const r = lynisFix(id, "linux", "apt", installCmd);
  return r.fix !== null && String(r.fix).trim().length < 20;
});
ok(vaciosFix.length === 0, "ningún fix es una cadena vacía o de una palabra", JSON.stringify(vaciosFix));

console.log("\n── 7 · Sin fix: no se inventa uno, se da la ficha ────────────────\n");

// NETW-2705 ("Couldn't find 2 responsive nameservers") en una red doméstica no admite acción.
// Antes este bloque usaba PROC-3614 como ejemplo, pero ese control SÍ admite acción: Lynis lo emite
// cuando encuentra procesos bloqueados esperando E/S (estado D), no cuando "no pudo comprobar".
const proc = lynisFix("NETW-2705", "linux", "apt", installCmd);
ok(proc.fix === null, "NETW-2705 no emite fix", JSON.stringify(proc.fix));
ok(proc.noAction === true, "y se marca como 'no admite acción', no como 'nos falta escribirlo'");

// El nombre del paquete depende de la distribución: con pacman no se puede proponer `auditd`.
const auditPac = lynisFix("ACCT-9628", "linux", "pacman", installCmd);
ok(auditPac.command === "sudo pacman -S --noconfirm audit",
   "ACCT-9628 con pacman instala `audit`, no `auditd`", JSON.stringify(auditPac.command));
const acctPac = lynisFix("ACCT-9622", "linux", "pacman", installCmd);
ok(acctPac.fix && acctPac.command === null,
   "ACCT-9622 con pacman: hay texto, pero sin orden (el nombre en Arch no está confirmado)", JSON.stringify(acctPac));
const pwqDnf = lynisFix("AUTH-9262", "linux", "dnf", installCmd);
ok(pwqDnf.command === "sudo dnf install -y libpwquality",
   "AUTH-9262 con dnf instala `libpwquality`", JSON.stringify(pwqDnf.command));

// Un control que sí admite acción pero cuyo paso es solo de Linux: en macOS no se inventa.
const soloLinux = lynisFix("BOOT-5122", "darwin", "brew", installCmd);
ok(soloLinux.fix === null, "un paso solo de Linux NO se ofrece en macOS");
ok(soloLinux.noAction === false, "y NO se marca como 'no admite acción': sí la admite, en Linux");

// La ficha oficial, que es lo que ocupa el sitio del fix ausente.
ok(lynisControlUrl("PROC-3614") === "https://cisofy.com/lynis/controls/PROC-3614/",
   "lynisControlUrl compone la ficha oficial del control");
ok(lynisControlUrl("no-es-un-id") === null, "y no inventa URL para un id que no lo parece");

console.log("\n── 8 · Cobertura: tres cifras, no una ────────────────────────────\n");

const cov44 = lynisCoverage(TODOS, "linux");
console.log(`  ${cov44.translated}/${cov44.total} traducidos · ${cov44.withFix} con solución · ` +
            `${cov44.noAction} sin acción posible · ${cov44.missingFix} sin paso escrito`);

ok(cov44.withFix + cov44.noAction + cov44.missingFix === cov44.translated,
   "las tres cifras suman los traducidos: ningún control queda sin clasificar");
// La distinción que se pidió: "no admite acción" y "no lo hemos escrito" son cosas distintas y
// colapsarlas daría "N sin cubrir" mezclando lo que no existe con lo que falta por hacer.
ok(cov44.noAction > 0, "hay controles marcados como 'sin acción posible'", String(cov44.noAction));
ok(Array.isArray(cov44.noActionIds) && cov44.noActionIds.length === cov44.noAction,
   "y se listan por ID, no solo se cuentan", JSON.stringify(cov44.noActionIds));
ok(cov44.missingFixIds.length === cov44.missingFix,
   "igual que los que faltan por escribir");

// Procedencia: qué está probado contra hardware y qué viene de documentación.
console.log(`  verificados en sistema real (${cov44.verified.real.length}): ${cov44.verified.real.join(", ")}`);
console.log(`  desde documentación (${cov44.verified.doc.length}): ${cov44.verified.doc.length} controles`);
ok(cov44.verified.real.length + cov44.verified.doc.length === cov44.translated,
   "cada control traducido declara su procedencia");
ok(cov44.verified.real.length > 0, "y al menos uno está comprobado contra un sistema real");

console.log("\n── 9 · El desambiguador no cuela inglés ──────────────────────────\n");

// Los tres controles que se repiten en los informes de referencia. Antes, el paréntesis volcaba
// la descripción entera de Lynis y metía inglés en un título en castellano.
const GRUPOS = [
  { nombre: "AUTH-9286", entradas: [
      { description: "Configure minimum password age in /etc/login.defs", detail: null },
      { description: "Configure maximum password age in /etc/login.defs", detail: null },
    ], espera: ["mínima", "máxima"] },
  { nombre: "NETW-3200", entradas: [
      { description: "Determine if protocol 'dccp' is really needed on this system", detail: null },
      { description: "Determine if protocol 'sctp' is really needed on this system", detail: null },
      { description: "Determine if protocol 'rds' is really needed on this system", detail: null },
    ], espera: ["dccp", "sctp", "rds"] },
  { nombre: "FILE-6310 (macOS: el discriminador es el campo 3)", entradas: [
      { description: "Symlinked mount point needs to be checked manually", detail: "/home" },
      { description: "Symlinked mount point needs to be checked manually", detail: "/tmp" },
      { description: "Symlinked mount point needs to be checked manually", detail: "/var" },
    ], espera: ["/home", "/tmp", "/var"] },
];

for (const g of GRUPOS) {
  const elegidos = pickLynisDiscriminators(g.entradas);
  ok(!!elegidos, `[${g.nombre}] se encuentra un discriminador`);
  if (!elegidos) continue;
  const textos = elegidos.map((e) => e.text);
  ok(JSON.stringify(textos) === JSON.stringify(g.espera),
     `[${g.nombre}] → ${JSON.stringify(textos)}`, JSON.stringify(textos));
  ok(new Set(textos).size === textos.length, `[${g.nombre}] y son todos distintos`);
  ok(elegidos.every((e) => e.translated), `[${g.nombre}] ninguno arrastra inglés sin traducir`);
}

// /etc/login.defs aparece en las DOS entradas de AUTH-9286: no distingue nada y no puede salir.
const authDisc = pickLynisDiscriminators(GRUPOS[0].entradas);
ok(authDisc.every((e) => !/etc\/login\.defs/.test(e.text)),
   "una ruta de configuración compartida NO se usa como discriminador",
   JSON.stringify(authDisc.map((e) => e.text)));

// Último recurso: sin nada reconocible, la frase original, MARCADA como inglés.
const sinPista = pickLynisDiscriminators([
  { description: "Some entirely opaque suggestion alpha", detail: null },
  { description: "Some entirely opaque suggestion beta", detail: null },
]);
ok(!!sinPista, "sin patrón reconocible se recurre a la frase original");
ok(sinPista.every((e) => e.translated === false),
   "y viene marcada como no traducida, para que el título lo diga");

console.log(`\n${passed} pasados · ${failed} fallidos\n`);
process.exit(failed > 0 ? 1 : 0);
