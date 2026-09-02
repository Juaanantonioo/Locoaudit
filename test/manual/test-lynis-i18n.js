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

const { LYNIS_ES, LYNIS_ES_IDS, lynisText, lynisCoverage } = require("../../lib/lynis-i18n");
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

const vacios = LYNIS_ES_IDS.filter((id) => !LYNIS_ES[id] || LYNIS_ES[id].trim().length < 20);
ok(vacios.length === 0, "ninguna traducción vacía ni de una palabra", JSON.stringify(vacios));

// El ID no puede aparecer dentro del texto: la tarjeta ya lo lleva como metadato, y repetirlo
// dentro de la frase es el ruido que se quitó al dejar de encabezar el título con el código.
const conCodigo = LYNIS_ES_IDS.filter((id) => LYNIS_ES[id].includes(id));
ok(conCodigo.length === 0, "ninguna traducción repite el código del control", JSON.stringify(conCodigo));

// Sin inglés colado.
const RE_EN = /\b(the|should|enable|disable|install|configure|check|missing|found|hardening)\b/i;
const conIngles = LYNIS_ES_IDS.filter((id) => RE_EN.test(LYNIS_ES[id]));
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
ok(auth.some((x) => /minimum/i.test(x.title)) && auth.some((x) => /maximum/i.test(x.title)),
   "y cada uno el matiz que lo distingue");

// El caso normal —un control, una tarjeta— NO se ensucia con el paréntesis.
ok(!usb.title.includes("("), "un control que sale una sola vez conserva el título limpio", usb.title);

console.log(`\n${passed} pasados · ${failed} fallidos\n`);
process.exit(failed > 0 ? 1 : 0);
