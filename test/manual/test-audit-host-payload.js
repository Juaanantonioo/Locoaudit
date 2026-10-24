"use strict";

/**
 * test-audit-host-payload.js — El nodo emite payload aunque Trivy omita una parte.
 * Carga el nodo real con un RED falso y solo sustituye los módulos de Trivy.
 *
 * Uso:
 *   node test/manual/test-audit-host-payload.js
 */

const path = require("path");

let failed = 0;
let passed = 0;

function ok(cond, label, detail) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}`); if (detail) console.log(`      ${detail}`); }
}

// ── Sustitución de trivy-fs ──────────────────────────────────────────────────
// Se inyecta en require.cache antes de cargar el nodo; systemPackagesSupport es el real.
const TRIVY_PATH = require.resolve("../../nodes/audit-host/modules/trivy-fs");
const trivyReal = require(TRIVY_PATH);

let trivyStubResult = null;
let trivyStubOpts = null;      // últimas opciones recibidas: prueba qué se le pidió
require.cache[TRIVY_PATH].exports = Object.assign({}, trivyReal, {
  runTrivyFs: async (opts) => { trivyStubOpts = opts; return trivyStubResult; },
  // La pasada de secretos no es lo que se prueba aquí: sin stub ejecutaría el Trivy del equipo que corre el test.
  runTrivySecrets: async () => ({ skipped: true, kind: "disabled", reason: "stub" }),
});

// ── Sustitución de trivy-rootfs ──────────────────────────────────────────────
// systemPackagesSupport() es el real: se prueba al mirar scanMeta.systemPackages.
const ROOTFS_PATH = require.resolve("../../lib/trivy-rootfs");
const rootfsReal = require(ROOTFS_PATH);

let rootfsStubResult = null;
let rootfsLlamado = false;
require.cache[ROOTFS_PATH].exports = Object.assign({}, rootfsReal, {
  runTrivyRootfs: async () => { rootfsLlamado = true; return rootfsStubResult; },
});

// commandExists se fuerza a true para que decida el stub y no el equipo que ejecuta el test.
const EXEC_PATH = require.resolve("../../lib/executor");
const execReal = require(EXEC_PATH);
require.cache[EXEC_PATH].exports = Object.assign({}, execReal, {
  commandExists: async (cmd) => (cmd === "trivy" ? "/usr/bin/trivy" : execReal.commandExists(cmd)),
});

/** Rootfs con éxito, con la forma que devuelve lib/trivy-rootfs.js. */
function rootfsOk(extra) {
  return Object.assign({
    os: { family: "debian", name: "13.6", eosl: false },
    pkgNum: 2056,
    trivyVersion: "0.74.0",
    total: 3,
    fixable: [{
      pkg: "openssl", installedVersion: "3.0.1", fixedVersion: "3.0.2",
      maxSeverity: "HIGH",
      cves: [{ id: "CVE-OS-1", severity: "HIGH", title: null }],
    }],
    fixableVulnCount: 1,
    unfixed: { total: 2, bySeverity: { MEDIUM: 1, LOW: 1 } },
    scan: { mode: "rootfs", target: "/", skipDirs: [], durationMs: 240000 },
    durationMs: 240000,
  }, extra || {});
}

// ── RED falso: lo mínimo que usa el nodo ─────────────────────────────────────
function cargarNodo() {
  const nodePath = require.resolve("../../nodes/audit-host/audit-host");
  delete require.cache[nodePath];
  const registrar = require(nodePath);

  let ctor = null;
  registrar({
    nodes: {
      createNode(node) {
        node.on = (evt, fn) => { node._handler = fn; };
        node.status = (s) => { node._status = s; };
        node.warn = (m) => { (node._warns = node._warns || []).push(m); };
        // Stub de node.log, por donde va el aviso de un módulo omitido que no es fallo.
        node.log = (m) => { (node._logs = node._logs || []).push(m); };
      },
      getNode: () => null,
      registerType: (_name, fn) => { ctor = fn; },
    },
  });
  return ctor;
}

/** Ejecuta el nodo con una config y devuelve { msg, err, status, warns }. */
async function ejecutar(config) {
  const Ctor = cargarNodo();
  const node = {};
  Ctor.call(node, config);

  const msg = {};
  let enviado = null;
  let err = null;
  await new Promise((resolve) => {
    node._handler(
      msg,
      (m) => { enviado = m; },
      (e) => { err = e || null; resolve(); }
    );
  });
  return { msg: enviado, err, status: node._status, warns: node._warns || [], logs: node._logs || [] };
}

// Módulos nativos apagados: lo que se prueba es el gate, no la recolección.
const CONFIG_BASE = {
  enableCpu: false, enableDisk: false, enableSw: false,
  enableLynis: false, enableTrivy: true, securityEvents: false,
  // Explícito porque el módulo va activo por defecto.
  trivySystemPkgs: false,
  enableSecrets: false,
};

(async () => {
  console.log("\n── 1 · 'unsupported' NO aborta: el payload sale ──────────────────\n");

  for (const reason of ["Trivy no soporta pacman", "rootfs solo aplica en Linux"]) {
    trivyStubResult = { skipped: true, kind: "unsupported", reason };
    const r = await ejecutar(CONFIG_BASE);

    ok(r.err === null, `[${reason}] no se reporta error`, r.err && r.err.message);
    ok(r.msg !== null && r.msg.payload !== undefined,
       `[${reason}] se emite payload`,
       "send() no llegó a llamarse: el dashboard se quedaría con datos viejos");
    if (r.msg && r.msg.payload) {
      const sp = r.msg.payload.scanMeta.systemPackages;
      ok(sp && typeof sp.status === "string",
         `[${reason}] scanMeta.systemPackages presente (status="${sp && sp.status}")`);
      // El motivo sale del módulo de paquetes del sistema, no del de la carpeta personal.
      ok(sp && typeof sp.reason === "string" && sp.reason.includes("desactivado"),
         `[${reason}] scanMeta.systemPackages lleva SU motivo, no el de trivy-fs`,
         `obtenido ${JSON.stringify(sp && sp.reason)}`);
      ok(Array.isArray(r.msg.payload.findings),
         `[${reason}] findings es un array`);
      ok(r.msg.payload.findings.some((f) => f.id === "HOST-CVE-SKIP"),
         `[${reason}] el análisis omitido queda declarado como finding informativo`,
         JSON.stringify(r.msg.payload.findings.map((f) => f.id)));
    }
    // Por `log` y no por `warn`: 'unsupported' es un límite del sistema, no un fallo.
    ok(r.logs.some((w) => w.includes("omitido")),
       `[${reason}] queda anotado en el log del nodo`,
       JSON.stringify({ warns: r.warns, logs: r.logs }));
    ok(!r.warns.some((w) => w.includes("omitido")),
       `[${reason}] y NO en amarillo: no es un fallo`, JSON.stringify(r.warns));
  }

  console.log("\n── 2 · 'not-installed' y 'error' SÍ abortan ──────────────────────\n");

  trivyStubResult = { skipped: true, kind: "not-installed", reason: "trivy not installed" };
  let r = await ejecutar(CONFIG_BASE);
  ok(r.err !== null, "not-installed → se reporta error");
  ok(r.msg === null, "not-installed → no se emite payload");
  ok(r.err && /no se encontró instalado/.test(r.err.message),
     "not-installed → el mensaje manda a instalar Trivy");

  trivyStubResult = {
    skipped: true, kind: "error", walkError: true,
    reason: "Trivy no pudo recorrer /Users/x/Library: operation timed out",
  };
  r = await ejecutar(CONFIG_BASE);
  ok(r.err !== null, "error → se reporta error");
  ok(r.msg === null, "error → no se emite payload");
  ok(r.status && r.status.text === "Carpeta inaccesible",
     "error de recorrido → estado 'Carpeta inaccesible'", JSON.stringify(r.status));

  console.log("\n── 3 · scanMeta.systemPackages se emite con el interruptor OFF ───\n");

  // Sin activar nada, el informe debe decir que los paquetes del sistema no se miraron.
  trivyStubResult = { Results: [], scan: { mode: "fs-by-children", target: "/home/x" } };
  r = await ejecutar(Object.assign({}, CONFIG_BASE, { trivySystemPkgs: false }));

  ok(r.err === null && r.msg !== null, "escaneo normal → payload emitido");
  const sp = r.msg && r.msg.payload.scanMeta.systemPackages;
  ok(!!sp, "scanMeta.systemPackages presente aunque el interruptor esté apagado");
  ok(sp && "manager" in sp && "managerLabel" in sp,
     `gestor detectado sin ejecutar rootfs (manager=${sp && sp.manager})`);
  ok(sp && sp.status !== "scanned",
     `el estado NO dice "analizado" cuando no se analizó (status="${sp && sp.status}")`);

  console.log("\n── 4 · El resumen segmentado llega al payload ────────────────────\n");

  ok(r.msg && r.msg.payload.summary.actionable !== undefined,
     "summary.actionable presente");
  ok(r.msg && r.msg.payload.summary.informative !== undefined,
     "summary.informative presente");
  const s = r.msg && r.msg.payload.summary;
  ok(s && s.actionable.total + s.informative.total ===
       Object.values(s.counts).reduce((a, b) => a + b, 0),
     "actionable + informative == total de counts");

  console.log("\n── 5 · Los dos módulos aportan, cada uno con su fuente ───────────\n");

  // El payload trae ambas procedencias: carpeta personal y sistema.
  const HOME_RESULT = {
    Target: "proyectos/api/package-lock.json", Class: "lang-pkgs", Type: "npm",
    Vulnerabilities: [{
      VulnerabilityID: "CVE-HOME-1", PkgName: "lodash", PkgPath: null,
      InstalledVersion: "4.17.11", FixedVersion: "4.17.21", Severity: "HIGH",
    }],
  };
  const OS_RESULT = {
    Target: "/ (debian 12.5)", Class: "os-pkgs", Type: "debian",
    Vulnerabilities: [{
      VulnerabilityID: "CVE-OS-1", PkgName: "openssl", PkgPath: null,
      InstalledVersion: "3.0.11-1", FixedVersion: "3.0.14-1", Severity: "CRITICAL",
    }],
  };

  // Dos módulos independientes, cada uno con su resultado.
  trivyStubResult = {
    Results: [HOME_RESULT],
    scan: {
      mode: "fs-by-children", target: "/home/ana", durationMs: 31671,
      resolvedFrom: "env", trivyVersion: "0.72.0",
      children: { scanned: [{ name: "proyectos", results: 1 }], skipped: [] },
    },
  };
  rootfsStubResult = rootfsOk();
  r = await ejecutar(Object.assign({}, CONFIG_BASE, { trivySystemPkgs: true }));

  const porOrigen = (r.msg ? r.msg.payload.findings : []).reduce((a, f) => {
    a[f.origin || "-"] = (a[f.origin || "-"] || 0) + 1; return a;
  }, {});
  console.log("  findings por origin:", JSON.stringify(porOrigen));

  const sp5 = r.msg && r.msg.payload.scanMeta.systemPackages;

  ok(r.err === null && r.msg !== null, "payload emitido");
  ok(porOrigen.declared >= 1, "los findings del HOME siguen ahí (origin 'declared')", JSON.stringify(porOrigen));
  ok(porOrigen.installed >= 1, "los findings del SISTEMA están presentes (origin 'installed')", JSON.stringify(porOrigen));
  // Las cifras de alcance salen solo del informe de Trivy.
  ok(sp5 && sp5.status === "scanned", "status 'scanned'", sp5 && sp5.status);
  ok(sp5 && sp5.packages === 2056, "packages = 2056, del informe de Trivy", sp5 && String(sp5.packages));
  ok(sp5 && sp5.osFamily === "debian" && sp5.osName === "13.6",
     "la familia y la versión del SO vienen del informe", JSON.stringify(sp5 && [sp5.osFamily, sp5.osName]));
  ok(sp5 && sp5.trivyVersion === "0.74.0", "la versión de Trivy viaja con el resultado");
  ok(sp5 && sp5.durationMs === 240000, "la duración REAL del rootfs llega al dashboard",
     sp5 && String(sp5.durationMs));
  ok(sp5 && sp5.unfixedVulns === 2, "el recuento sin corrección viaja aparte del corregible");
  ok(sp5 && sp5.requested === true,
     "scanMeta.systemPackages.requested = true (lo pidió el usuario)");

  // Lo no corregible se agrega en un único hallazgo informativo con el total.
  const unfixed = (r.msg ? r.msg.payload.findings : []).filter((f) => f.id === "HOST-OS-CVE-UNFIXED");
  ok(unfixed.length === 1, "un ÚNICO finding HOST-OS-CVE-UNFIXED", `encontrados ${unfixed.length}`);
  ok(unfixed[0] && unfixed[0].severity === "info",
     "severidad info: no hay acción posible, y la severidad mide urgencia de acción");
  ok(unfixed[0] && unfixed[0].fix === null, "sin campo fix: no hay nada que ofrecer");
  ok(unfixed[0] && unfixed[0].title.startsWith("2 vulnerabilidades"),
     "el título lleva el total real, no un número escrito a mano", unfixed[0] && unfixed[0].title);

  // Y el corregible, agrupado POR PAQUETE.
  const porPaquete = (r.msg ? r.msg.payload.findings : []).filter((f) => f.id.startsWith("HOST-OS-PKG-"));
  ok(porPaquete.length === 1 && porPaquete[0].id === "HOST-OS-PKG-openssl",
     "un finding por PAQUETE, con el nombre en el id", JSON.stringify(porPaquete.map((f) => f.id)));

  console.log("\n── 6 · Los dos escaneos son independientes ───────────────────────\n");

  // A trivy-fs no le llega ninguna opción del rootfs.
  trivyStubOpts = null;
  rootfsLlamado = false;
  r = await ejecutar(Object.assign({}, CONFIG_BASE, {
    trivySystemPkgs: true, trivyTarget: "~/proyectos",
  }));

  ok(trivyStubOpts && trivyStubOpts.target === "~/proyectos",
     "el target configurado llega al módulo de la carpeta",
     JSON.stringify(trivyStubOpts));
  ok(trivyStubOpts && trivyStubOpts.systemPackages === undefined,
     "a trivy-fs ya NO se le pasa systemPackages: no es asunto suyo",
     JSON.stringify(trivyStubOpts));
  ok(rootfsLlamado === true, "y el rootfs se lanza por su cuenta, desde el despacho");
  ok(trivyStubOpts && trivyStubOpts.pkgManager !== undefined,
     "el gestor ya detectado se le pasa al módulo (no lo detecta dos veces)");

  console.log("\n── 7 · macOS: 'no se pudo comprobar', nunca 'cero' ───────────────\n");

  // Trivy no reconoce el SO: la carpeta se escanea y los paquetes salen como no realizados.
  trivyStubResult = {
    Results: [HOME_RESULT],
    scan: {
      mode: "fs-by-children", target: "/Users/ana", durationMs: 31671,
      resolvedFrom: "env", trivyVersion: "0.72.0",
      children: { scanned: [{ name: "Proyectos", results: 1 }], skipped: [] },
    },
  };
  rootfsStubResult = {
    skipped: true, kind: "os-unsupported",
    reason: "Trivy no ha detectado la familia del sistema operativo",
    durationMs: 1200,
  };
  r = await ejecutar(Object.assign({}, CONFIG_BASE, { trivySystemPkgs: true }));

  const sp7 = r.msg && r.msg.payload.scanMeta.systemPackages;
  console.log(`  status: ${sp7 && sp7.status} · findings: ${r.msg && r.msg.payload.findings.length}`);

  ok(r.err === null && r.msg !== null, "payload emitido pese al rootfs no aplicable");
  ok(r.msg && r.msg.payload.findings.length >= 1, "los findings del home siguen ahí");
  ok(sp7 && sp7.kind === "os-unsupported", "el kind del módulo llega al dashboard", sp7 && sp7.kind);
  ok(sp7 && sp7.reason === "Trivy no ha detectado la familia del sistema operativo",
     "el motivo real viaja hasta el dashboard");
  // Sin cifras de paquetes: un 0 se leería como "ninguno vulnerable".
  ok(sp7 && sp7.packages === null && sp7 && sp7.unfixedVulns === null,
     "sin cifras: null, no cero. Cero sería un dato y aquí no hay dato",
     JSON.stringify(sp7 && [sp7.packages, sp7.unfixedVulns]));

  // Y la mitad legible: un finding marcado como comprobación no realizada.
  const skip7 = (r.msg ? r.msg.payload.findings : []).filter((f) => f.skipped === true);
  ok(skip7.some((f) => f.id === "HOST-OS-CVE-SKIP"),
     "sale un finding HOST-OS-CVE-SKIP con skipped:true",
     JSON.stringify(skip7.map((f) => f.id)));
  ok(!(r.msg ? r.msg.payload.findings : []).some((f) => f.id === "HOST-OS-CVE-UNFIXED"),
     "y NO sale el agregado de 'sin corrección': eso afirmaría un cero no medido");

  ok(r.msg && r.msg.payload.raw.trivy.scan.children.scanned.length === 1,
     "scan.children del home intacto (lo usan las pills del bloque de alcance)");

  console.log("\n── 8 · Apagado por el usuario ≠ comprobación caída ───────────────\n");

  // El dato distingue un módulo desactivado de una comprobación caída.
  trivyStubResult = { skipped: true, kind: "disabled", reason: "irrelevante" };
  rootfsStubResult = { skipped: true, kind: "disabled", reason: "irrelevante" };
  r = await ejecutar(Object.assign({}, CONFIG_BASE, {
    enableLynis: false, enableTrivy: false, trivySystemPkgs: false,
  }));

  const skips = (r.msg ? r.msg.payload.findings : []).filter((f) => f.skipped);
  console.log("  findings skipped:", JSON.stringify(skips.map((f) => f.id + "/" + f.kind)));

  ok(skips.length > 0, "los módulos apagados siguen dejando constancia");
  ok(skips.every((f) => f.kind === "disabled"),
     "todos llevan kind 'disabled' en el finding, no solo en el resultado del módulo",
     JSON.stringify(skips.map((f) => f.kind)));
  // `skipped:true` solo dice que falta el dato; el motivo va aparte.
  ok(skips.every((f) => typeof f.kind === "string" && f.kind.length > 0),
     "createFinding conserva el kind (antes se perdía y llegaba undefined)");

  // Y un fallo real sigue distinguiéndose.
  rootfsStubResult = {
    skipped: true, kind: "os-unsupported",
    reason: "Trivy no ha detectado la familia del sistema operativo", durationMs: 400,
  };
  r = await ejecutar(Object.assign({}, CONFIG_BASE, {
    enableLynis: false, enableTrivy: false, trivySystemPkgs: true,
  }));
  const mix = (r.msg ? r.msg.payload.findings : []).filter((f) => f.skipped);
  const apagados = mix.filter((f) => f.kind === "disabled");
  const caidos   = mix.filter((f) => f.kind !== "disabled");
  console.log("  mezcla:", JSON.stringify(mix.map((f) => f.id + "/" + f.kind)));

  ok(apagados.length === 3, "3 apagados (lynis, trivy-fs, trivy-secrets)", String(apagados.length));
  ok(caidos.length === 1 && caidos[0].id === "HOST-OS-CVE-SKIP",
     "1 caído (trivy-rootfs), separable del resto", JSON.stringify(caidos.map((f) => f.id)));
  ok(apagados.length + caidos.length === mix.length, "la partición es exhaustiva");

  console.log("\n── 9 · scanMeta.modules: los NUEVE módulos, con su estado ────────\n");

  const mods = r.msg && r.msg.payload.scanMeta.modules;
  console.log("  " + (mods || []).map((m) => m.id + "=" + m.status).join(" · "));

  ok(Array.isArray(mods) && mods.length === 9,
     "los 9 módulos del nodo aparecen siempre, se ejecuten o no", String(mods && mods.length));
  // Cubre también los módulos que no dejan finding al apagarse (cpu, disco, inventario...).
  ok(mods.every((m) => ["ok", "failed", "not-applicable", "not-requested"].includes(m.status)),
     "cuatro estados, ninguno fuera de la lista",
     JSON.stringify([...new Set(mods.map((m) => m.status))]));
  ok(mods.every((m) => typeof m.label === "string" && m.label.length),
     "cada uno trae su etiqueta legible, para no escribirla en el HTML");
  ok(mods.find((m) => m.id === "lynis").status === "not-requested",
     "lynis apagado → 'not-requested', NO 'failed'");
  // 'os-unsupported' es un límite de la plataforma (macOS, Windows), no un fallo.
  ok(mods.find((m) => m.id === "trivy-rootfs").status === "not-applicable",
     "trivy-rootfs con os-unsupported → 'not-applicable', NO 'failed'",
     mods.find((m) => m.id === "trivy-rootfs").status);
  // Y un fallo de verdad SÍ sale 'failed': la distinción tiene que funcionar en los dos sentidos.
  rootfsStubResult = { skipped: true, kind: "error", reason: "trivy reventó", durationMs: 10 };
  const rFallo = await ejecutar(Object.assign({}, CONFIG_BASE, {
    enableLynis: false, enableTrivy: false, trivySystemPkgs: true,
  }));
  const modsFallo = rFallo.msg.payload.scanMeta.modules;
  ok(modsFallo.find((m) => m.id === "trivy-rootfs").status === "failed",
     "trivy-rootfs con kind 'error' → 'failed'",
     modsFallo.find((m) => m.id === "trivy-rootfs").status);

  // pending-updates sigue activo en CONFIG_BASE y cubre el caso "se ejecutó".
  ok(mods.find((m) => m.id === "pending-updates").status === "ok",
     "y el que se ejecutó → 'ok'", mods.find((m) => m.id === "pending-updates").status);

  // Los módulos que no dejan finding al apagarse constan igual.
  const sinFinding = ["cpu-memory", "disk-storage", "sw-inventory", "security-events"];
  ok(sinFinding.every((id) => mods.find((m) => m.id === id).status === "not-requested"),
     "los 4 módulos que no dejan hallazgo al apagarse constan igual",
     JSON.stringify(sinFinding.map((id) => id + "=" + mods.find((m) => m.id === id).status)));
  ok(!(r.msg ? r.msg.payload.findings : []).some((f) => f.id.startsWith("HOST-CPU")),
     "y en efecto no han dejado ningún finding: por eso scanMeta es la fuente");

  console.log("\n── 10 · Windows: reinicio pendiente ≠ sistema al día ─────────────\n");

  // `IsInstalled=0` no incluye las actualizaciones pendientes de reinicio: no es "Sistema al día".
  const { normalizeHost: nh } = require("../../lib/normalizer");
  const baseWin = {
    skipped: false, platform: "win32", source: "Microsoft.Update.Session",
    securityDetection: "full", securityCount: 0, unclassifiedCount: 0, total: 0, updates: [],
  };
  const conReinicio = (v) => nh({ pendingUpdates: { ...baseWin, rebootPending: v } },
                                { platform: "win32", pkgManager: "winget" })[0];

  const fReboot = conReinicio(true);
  console.log(`  reboot=true  → ${fReboot.severity} · ${fReboot.title}`);
  ok(!/al día/i.test(fReboot.title),
     "con reinicio pendiente el título NO dice 'al día'", fReboot.title);
  ok(/reinici/i.test(fReboot.title), "sino que lo menciona", fReboot.title);
  ok(fReboot.severity === "medium",
     "y no se queda en 'info': hasta reiniciar, la corrección no está aplicada", fReboot.severity);
  ok(/YA INSTALADAS/.test(fReboot.evidence), "la evidencia lo explica", fReboot.evidence.slice(0, 90));
  // Va primero: leerlo después del "no hay nada pendiente" deja la conclusión al revés.
  ok(fReboot.evidence.indexOf("YA INSTALADAS") < fReboot.evidence.indexOf("No hay actualizaciones"),
     "y va ANTES del 'no hay pendientes', que es lo que matiza");

  const fLimpio = conReinicio(false);
  console.log(`  reboot=false → ${fLimpio.severity} · ${fLimpio.title}`);
  ok(/al día/i.test(fLimpio.title), "sin reinicio pendiente sí puede decir 'al día'", fLimpio.title);
  ok(fLimpio.severity === "info", "y vuelve a 'info'");

  // El tercer estado: no se pudo leer el registro. No saber no es saber que no.
  const fNull = conReinicio(null);
  console.log(`  reboot=null  → ${fNull.severity} · ${fNull.title}`);
  ok(!/al día/i.test(fNull.title),
     "con el registro ilegible tampoco afirma 'al día'", fNull.title);
  ok(/No se ha podido comprobar/i.test(fNull.evidence),
     "y dice que esa parte no se ha comprobado", fNull.evidence.slice(-120));

  // Con lista NO vacía, el aviso va igual: son dos cosas distintas.
  const fAmbos = nh({ pendingUpdates: { ...baseWin, total: 2, securityCount: 1, rebootPending: true,
      updates: [{ name: "KB1", security: true }, { name: "KB2", security: false }] } },
    { platform: "win32", pkgManager: "winget" })[0];
  ok(/ya instaladas que no se aplicarán/i.test(fAmbos.evidence),
     "con actualizaciones pendientes Y reinicio, se avisa de las dos cosas",
     fAmbos.evidence.slice(-120));

  // Linux no tiene este concepto y no puede verse afectado.
  const fLinux = nh({ pendingUpdates: { skipped: false, platform: "linux", manager: "apt",
      source: "apt", total: 0, updates: [], securityDetection: "none" } }, { platform: "linux" })[0];
  ok(/al día/i.test(fLinux.title), "Linux con 0 pendientes sigue diciendo 'al día'", fLinux.title);

  console.log(`\n${passed} pasados · ${failed} fallidos\n`);
  process.exit(failed > 0 ? 1 : 0);
})();
