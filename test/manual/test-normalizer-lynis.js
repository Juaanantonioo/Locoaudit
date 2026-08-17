"use strict";

/**
 * test-normalizer-lynis.js — Reestructuración de la salida de Lynis.
 *
 * Antes, TODAS las sugerencias colapsaban en un único finding que listaba diez
 * códigos y remitía a ejecutar 'lynis show suggestions' en una terminal. El
 * contenido existía en payload.raw.lynis y se perdía en la normalización.
 *
 * Este test fija, sobre ficheros .dat REALES (no sintéticos):
 *   - un finding por entrada, sin colapsar IDs repetidos;
 *   - avisos y sugerencias separados, con el aviso pesando más;
 *   - el campo 3 aprovechado (como evidencia y como comando);
 *   - el campo 4 mapeado solo con vocabulario conocido;
 *   - el aviso y la sugerencia del mismo control fusionados en evidence/fix;
 *   - la severidad como criterio de LoCoAudit, no como valor por defecto.
 *
 * Uso:
 *   node test/manual/test-normalizer-lynis.js
 */

const fs = require("fs");
const path = require("path");
const { parseLynisReport } = require("../../nodes/audit-host/modules/lynis");
const { fromLynisRaw } = require("../../lib/normalizer");
const { summarize, isActionable, lynisSeverity } = require("../../lib/severity-map");

const FIXTURES = path.join(__dirname, "..", "fixtures", "lynis");

let failed = 0;
let passed = 0;
let skipped = 0;

function ok(cond, label, detail) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}`); if (detail) console.log(`      ${detail}`); }
}

/**
 * Carga un fixture. Los .dat son capturas de máquinas concretas y no todas
 * están en el repo: el de CachyOS lo aporta quien tenga esa máquina. Ausente →
 * se salta el bloque, no se falla (mismo criterio que los fixtures de nmap).
 */
function loadFixture(name) {
  const file = path.join(FIXTURES, name);
  if (!fs.existsSync(file)) return null;
  return parseLynisReport(fs.readFileSync(file, "utf8"));
}

function byControl(findings, control) {
  return findings.filter((f) => f.control === control);
}

// ══ 1 · macOS ═══════════════════════════════════════════════════════════════

console.log("\n── 1 · Fixture macOS: un finding por entrada ─────────────────────\n");

const macRaw = loadFixture("report-macos.dat");

if (!macRaw) {
  console.log("  ⊘ test/fixtures/lynis/report-macos.dat no está — bloque omitido");
  skipped++;
} else {
  const entries = macRaw.warnings.length + macRaw.suggestions.length;
  const mac = fromLynisRaw(macRaw, "darwin", "brew");

  ok(macRaw.warnings.length === 2 && macRaw.suggestions.length === 16,
     `el .dat trae 2 avisos y 16 sugerencias`,
     `leídos ${macRaw.warnings.length} y ${macRaw.suggestions.length}`);

  // 18 entradas − 2 fusiones (NETW-2704 y NETW-2705 traen aviso Y sugerencia).
  ok(mac.length === 16, `18 entradas → 16 findings (2 fusiones)`, `salieron ${mac.length}`);

  // Ninguna entrada se pierde: la descripción de cada una tiene que aparecer en
  // el título o en el remedio de algún finding (las fusionadas van en el fix).
  const textos = mac.map((f) => `${f.title}\n${f.fix || ""}`).join("\n");
  const perdidas = [...macRaw.warnings, ...macRaw.suggestions]
    .filter((e) => !textos.includes(e.description));
  ok(perdidas.length === 0,
     `las ${entries} entradas del .dat llegan al payload`,
     perdidas.map((e) => e.id).join(", "));

  // FILE-6310 aparece 3 veces con la MISMA descripción: solo el campo 3 las
  // distingue. Con el ID como clave colapsaban en una.
  const file6310 = byControl(mac, "FILE-6310");
  ok(file6310.length === 3, "FILE-6310 ×3 no colapsa", `salieron ${file6310.length}`);
  const detalles = file6310.map((f) => f.detail).sort();
  ok(JSON.stringify(detalles) === JSON.stringify(["/home", "/tmp", "/var"]),
     "los tres FILE-6310 conservan su campo 3 (/home, /tmp, /var)",
     JSON.stringify(detalles));
  ok(new Set(file6310.map((f) => f.id)).size === 3,
     "los tres tienen id de finding distinto",
     file6310.map((f) => f.id).join(", "));

  // Fusión aviso + sugerencia del mismo control.
  const netw2704 = byControl(mac, "NETW-2704");
  ok(netw2704.length === 1, "NETW-2704 (aviso + sugerencia) → UN finding", `salieron ${netw2704.length}`);
  if (netw2704.length === 1) {
    const f = netw2704[0];
    ok(f.lynisType === "warning", "la fusión conserva el tipo aviso");
    ok(/does not respond/i.test(f.evidence), "la evidencia es el AVISO", f.evidence);
    ok(/Check connection to this nameserver/i.test(f.fix || ""),
       "el remedio es la SUGERENCIA del mismo control", f.fix);
    ok(f.severity === "info",
       "NETW-2704 sigue en info: el override por ID manda en los avisos", f.severity);
  }

  // Grupos y etiquetas.
  ok(mac.every((f) => f.controlGroup && f.subcategory),
     "todo finding lleva prefijo y etiqueta en español");
  const auth = byControl(mac, "AUTH-9262")[0];
  ok(auth && auth.subcategory === "Autenticación y contraseñas",
     "AUTH → 'Autenticación y contraseñas'", auth && auth.subcategory);

  // El título es legible, no el código.
  ok(mac.every((f) => !/^Lynis:/.test(f.title)),
     "ningún título empieza por el código del control");
  ok(auth && auth.title === "Install a PAM module for password strength testing like pam_cracklib or pam_passwdqc or libpam-passwdqc",
     "el título es la descripción del control");

  // Campo 4 con prosa libre → se ignora (no hay actionType).
  const file7524 = byControl(mac, "FILE-7524")[0];
  ok(file7524 && !file7524.actionType,
     "'text:Use chmod to change file permissions' (prosa) NO produce actionType");
  ok(file7524 && /See screen output/.test(file7524.evidence || ""),
     "pero su campo 3 sí llega a la evidencia", file7524 && file7524.evidence);

  // Severidad y volumen.
  const s = summarize(mac);
  ok(s.actionable.total === 2,
     `accionables = 2 (AUTH-9262 y FIRE-4590)`, `salieron ${s.actionable.total}`);
  const acc = mac.filter(isActionable).map((f) => f.control).sort();
  ok(JSON.stringify(acc) === JSON.stringify(["AUTH-9262", "FIRE-4590"]),
     "y son exactamente esos dos", acc.join(", "));
  ok(mac.every((f) => f.severitySource === "locoaudit"),
     "toda severidad de Lynis se declara como criterio de LoCoAudit");
}

// ══ 2 · CachyOS (fixture opcional) ══════════════════════════════════════════

console.log("\n── 2 · Fixture CachyOS: IDs repetidos y campo 3 ejecutable ───────\n");

const archRaw = loadFixture("report-cachyos.dat");

if (!archRaw) {
  console.log("  ⊘ test/fixtures/lynis/report-cachyos.dat no está — bloque omitido");
  console.log("      Para generarlo, en esa máquina:");
  console.log("      lynis audit system --quick --quiet --no-colors \\");
  console.log("        --log-file /tmp/lynis.log --report-file /tmp/locoaudit-lynis-report.dat");
  skipped++;
} else {
  const arch = fromLynisRaw(archRaw, "linux", "pacman");

  const auth9286 = byControl(arch, "AUTH-9286");
  ok(auth9286.length >= 2,
     "AUTH-9286 aparece más de una vez y no colapsa", `salieron ${auth9286.length}`);
  ok(new Set(auth9286.map((f) => f.title)).size === auth9286.length,
     "cada AUTH-9286 conserva su descripción propia",
     auth9286.map((f) => f.title).join(" | "));

  const netw3200 = byControl(arch, "NETW-3200");
  ok(netw3200.length >= 2, "NETW-3200 tampoco colapsa", `salieron ${netw3200.length}`);

  // Campo 3 ejecutable → comando copiable.
  const boot = byControl(arch, "BOOT-5264")[0];
  if (boot) {
    ok(boot.isCommand && /systemd-analyze security/.test(boot.command || ""),
       "BOOT-5264: el campo 3 se convierte en comando copiable", boot.command);
    ok(/systemd-analyze security/.test(boot.fix || ""),
       "y aparece como paso de resolución");
  } else {
    console.log("  ⊘ BOOT-5264 no está en este .dat");
    skipped++;
  }

  // Campo 4 con token conocido.
  const krnl = byControl(arch, "KRNL-5830")[0];
  if (krnl) {
    ok(krnl.lynisType === "warning", "KRNL-5830 es un AVISO, separado de las sugerencias");
    ok(krnl.actionType === "reboot", "'text:reboot' → actionType 'reboot'", krnl.actionType);
    ok(/[Rr]einicia/.test(krnl.fix || ""),
       "y el primer paso dice que hay que reiniciar", krnl.fix);
    ok(!/sysctl\.conf/.test(krnl.fix || ""),
       "ya NO manda a editar /etc/sysctl.conf, que era el paso equivocado");
  } else {
    console.log("  ⊘ KRNL-5830 no está en este .dat");
    skipped++;
  }

  // Campo 4 SIN prefijo: en este .dat aparecen dos valores de prosa suelta
  // ("Install a tool like rkhunter…", "Change sysctl value or disable test
  // (skip-test=KRNL-6000:<sysctl-key>)"). El segundo lleva dos puntos dentro,
  // así que sirve de prueba de que no basta con buscar ':' para decidir.
  const sinPrefijo = (archRaw.suggestions || []).filter(
    (e) => e.solution && !/^[a-z]+:/.test(e.solution)
  );
  ok(sinPrefijo.length >= 1,
     `el .dat trae ${sinPrefijo.length} campo(s) 4 en prosa suelta, sin prefijo`);
  ok(arch.filter((f) => f.actionType).length === 1,
     "solo el token conocido produce actionType; la prosa suelta se descarta",
     arch.filter((f) => f.actionType).map((f) => f.control).join(", "));

  // Toda entrada cae en un grupo con etiqueta: si aparece un prefijo nuevo,
  // este test lo saca a la luz en vez de dejarlo en el cajón genérico.
  const sinEtiqueta = arch.filter((f) => f.subcategory === "Otros controles de Lynis");
  ok(sinEtiqueta.length === 0,
     "ningún control cae en el cajón 'Otros controles de Lynis'",
     sinEtiqueta.map((f) => f.control).join(", "));

  const s = summarize(arch);
  console.log(`      volumen CachyOS: ${arch.length} findings · ` +
              `${s.actionable.total} accionables · ${s.informative.total} informativos`);
}

// ══ 3 · Criterio de severidad, sin fixture ══════════════════════════════════

console.log("\n── 3 · La severidad es criterio de LoCoAudit, no valor por defecto ─\n");

ok(lynisSeverity("FIRE-9999", "warning") === "high",
   "tramo A · aviso → alto (prefijo desconocido en la tabla por ID)");
ok(lynisSeverity("FIRE-9999", "suggestion") === "low",
   "tramo A · sugerencia → bajo");
ok(lynisSeverity("KRNL-5830", "warning") === "medium",
   "tramo B · aviso → medio", lynisSeverity("KRNL-5830", "warning"));
ok(lynisSeverity("KRNL-9999", "suggestion") === "info",
   "tramo B · sugerencia → info");
ok(lynisSeverity("TOOL-5002", "suggestion") === "info",
   "tramo C · sugerencia → info aunque el mapa por ID diga 'low'");
ok(lynisSeverity("NETW-2704", "warning") === "info",
   "el override por ID gana en avisos (falso positivo de ISP doméstico)");
ok(lynisSeverity("ZZZZ-0000", "warning") === "medium",
   "prefijo desconocido → tramo intermedio, no 'low' por defecto");

const sevA = lynisSeverity("AUTH-0000", "warning");
const sevB = lynisSeverity("AUTH-0000", "suggestion");
ok(sevA !== sevB, "un aviso nunca pesa lo mismo que una sugerencia del mismo tramo",
   `${sevA} vs ${sevB}`);

// ══ Resumen ═════════════════════════════════════════════════════════════════

console.log(`\n${"─".repeat(66)}`);
console.log(`  ${passed} pasados · ${failed} fallidos · ${skipped} omitidos`);
console.log(`${"─".repeat(66)}\n`);

process.exit(failed > 0 ? 1 : 0);
