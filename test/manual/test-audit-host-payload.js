"use strict";

/**
 * test-audit-host-payload.js — El nodo emite payload cuando debe.
 *
 * Fija el arreglo del bug que dejaba el dashboard en blanco:
 *
 *   audit-host.js trataba CUALQUIER trivy.skipped como fatal salvo el literal
 *   "trivy not installed". Como el `return` del gate va antes del send(msg), un
 *   límite conocido de la herramienta —Trivy no analiza pacman— abortaba la
 *   auditoría entera y el dashboard se quedaba enseñando la ejecución anterior.
 *   Reproducido en las dos plataformas, con dos textos distintos para el mismo
 *   caso: "rootfs solo aplica en Linux" (macOS) y "Trivy no soporta pacman" (Arch).
 *
 * Se carga el nodo real con un RED falso y solo se sustituye trivy-fs, para que
 * el gate, el normalizador y la construcción del payload sean los de producción.
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
// Se inyecta en require.cache ANTES de cargar el nodo. systemPackagesSupport se
// mantiene el real: es la función bajo prueba en el payload.
const TRIVY_PATH = require.resolve("../../nodes/audit-host/modules/trivy-fs");
const trivyReal = require(TRIVY_PATH);

let trivyStubResult = null;
let trivyStubOpts = null;      // últimas opciones recibidas: prueba qué se le pidió
require.cache[TRIVY_PATH].exports = Object.assign({}, trivyReal, {
  runTrivyFs: async (opts) => { trivyStubOpts = opts; return trivyStubResult; },
});

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
  return { msg: enviado, err, status: node._status, warns: node._warns || [] };
}

// Módulos nativos apagados: lo que se prueba es el gate, no la recolección.
const CONFIG_BASE = {
  enableCpu: false, enableDisk: false, enableSw: false,
  enableLynis: false, enableTrivy: true, securityEvents: false,
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
      ok(sp && sp.reason === reason,
         `[${reason}] el motivo real viaja hasta el dashboard`);
      ok(Array.isArray(r.msg.payload.findings),
         `[${reason}] findings es un array (vacío, no roto)`);
    }
    ok(r.warns.some((w) => w.includes("omitido")),
       `[${reason}] queda anotado en el log del nodo`);
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

  // El caso real de CachyOS: nadie activó nada, y aun así el usuario tiene
  // derecho a saber que sus paquetes de sistema no se han mirado.
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

  console.log("\n── 5 · systemPackages SUMA: no se pierden los findings del home ──\n");

  // El interruptor sustituía el escaneo del home en vez de añadirse. Aquí se
  // comprueba de punta a punta que el payload trae AMBAS procedencias.
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

  trivyStubResult = {
    Results: [HOME_RESULT, OS_RESULT],
    scan: {
      mode: "fs-by-children", target: "/home/ana", durationMs: 31671,
      resolvedFrom: "env", trivyVersion: "0.72.0",
      children: { scanned: [{ name: "proyectos", results: 1 }], skipped: [] },
      system: { attempted: true, status: "scanned", reason: null, mode: "rootfs",
                target: "/", durationMs: 240000, results: 1 },
    },
  };
  r = await ejecutar(Object.assign({}, CONFIG_BASE, { trivySystemPkgs: true }));

  const porOrigen = (r.msg ? r.msg.payload.findings : []).reduce((a, f) => {
    a[f.origin || "-"] = (a[f.origin || "-"] || 0) + 1; return a;
  }, {});
  console.log("  findings por origin:", JSON.stringify(porOrigen));

  ok(r.err === null && r.msg !== null, "payload emitido");
  ok(porOrigen.declared >= 1, "los findings del HOME siguen ahí (origin 'declared')", JSON.stringify(porOrigen));
  ok(porOrigen.installed >= 1, "los findings del SISTEMA se han sumado (origin 'installed')", JSON.stringify(porOrigen));
  ok(r.msg && r.msg.payload.scanMeta.systemPackages.results === 1,
     "scanMeta.systemPackages.results refleja lo aportado por el rootfs");
  ok(r.msg && r.msg.payload.scanMeta.systemPackages.requested === true,
     "scanMeta.systemPackages.requested = true (lo pidió el usuario)");

  console.log("\n── 6 · \"Carpeta a auditar\" se respeta con systemPackages activo ──\n");

  // Antes, `if (opts.systemPackages) return runTrivyRootfs()` iba ANTES de
  // resolver el objetivo: el campo del nodo quedaba anulado en silencio.
  trivyStubOpts = null;
  r = await ejecutar(Object.assign({}, CONFIG_BASE, {
    trivySystemPkgs: true, trivyTarget: "~/proyectos",
  }));

  ok(trivyStubOpts && trivyStubOpts.target === "~/proyectos",
     "el target configurado llega al módulo aunque systemPackages esté activo",
     JSON.stringify(trivyStubOpts));
  ok(trivyStubOpts && trivyStubOpts.systemPackages === true,
     "y systemPackages también: las dos opciones conviven, no se anulan");
  ok(trivyStubOpts && trivyStubOpts.pkgManager !== undefined,
     "el gestor ya detectado se le pasa al módulo (no lo detecta dos veces)");

  console.log("\n── 7 · systemPackages en macOS: el home queda intacto ────────────\n");

  // unsupported: el rootfs no aplica, pero el escaneo de la carpeta sí se hizo.
  trivyStubResult = {
    Results: [HOME_RESULT],
    scan: {
      mode: "fs-by-children", target: "/Users/ana", durationMs: 31671,
      resolvedFrom: "env", trivyVersion: "0.72.0",
      children: { scanned: [{ name: "Proyectos", results: 1 }], skipped: [] },
      system: { attempted: true, status: "unsupported",
                reason: "rootfs solo aplica en Linux", mode: "rootfs",
                target: "/", durationMs: null, results: 0 },
    },
  };
  r = await ejecutar(Object.assign({}, CONFIG_BASE, { trivySystemPkgs: true }));

  const sp7 = r.msg && r.msg.payload.scanMeta.systemPackages;
  console.log(`  status: ${sp7 && sp7.status} · findings: ${r.msg && r.msg.payload.findings.length}`);

  ok(r.err === null && r.msg !== null, "payload emitido pese al rootfs no aplicable");
  ok(r.msg && r.msg.payload.findings.length >= 1, "los findings del home siguen ahí");
  ok(sp7 && sp7.status === "not-applicable",
     "status 'not-applicable' en macOS (la plataforma manda sobre el resultado)", sp7 && sp7.status);
  ok(sp7 && sp7.reason === "rootfs solo aplica en Linux",
     "el motivo real viaja hasta el dashboard");
  ok(r.msg && r.msg.payload.raw.trivy.scan.children.scanned.length === 1,
     "scan.children del home intacto (lo usan las pills del bloque de alcance)");

  console.log(`\n${passed} pasados · ${failed} fallidos\n`);
  process.exit(failed > 0 ? 1 : 0);
})();
