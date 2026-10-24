"use strict";

/**
 * test-host-silent-failures.js: en audit-host un fallo de herramienta nunca sale igual que un resultado limpio.
 * Simula las herramientas (executor sustituido antes de requerir los módulos, y un trivy falso en el PATH).
 * Uso: node test/manual/test-host-silent-failures.js
 */

const fs = require("fs");
const os = require("os");
const path = require("path");

let failed = 0, passed = 0;
function ok(cond, label, detail) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}`); if (detail) console.log(`      ${detail}`); }
}

const ROOT = path.join(__dirname, "../..");
const IS_WIN = process.platform === "win32";

// ── executor: se sustituye antes de requerir nada; sin escenario delega en el real ─────
const executor = require(path.join(ROOT, "lib/executor"));
const execReal = { ...executor };
let esc = null;   // { exists(cmd), exec(cmd, timeout, opts) }
executor.commandExists = async (cmd) => (esc && esc.exists ? esc.exists(cmd) : execReal.commandExists(cmd));
executor.execCommand = async (cmd, t, opts) => (esc && esc.exec ? esc.exec(cmd, t, opts) : execReal.execCommand(cmd, t, opts));

function falla(msg, extra) {
  return Object.assign(new Error(msg), { stdout: "", stderr: "", code: 1 }, extra || {});
}
/** Un throw dentro de una sección cuenta como fallo y no corta el resto. */
async function seccion(nombre, fn) {
  try { await fn(); } catch (e) { ok(false, `${nombre}: lanzó`, e && e.stack ? e.stack.split("\n").slice(0, 2).join(" ") : String(e)); }
  esc = null;
  for (const k of Object.keys(lanza)) lanza[k] = false;
}

function conPlataforma(plat, fn) {
  const real = Object.getOwnPropertyDescriptor(process, "platform");
  Object.defineProperty(process, "platform", { value: plat, configurable: true });
  return Promise.resolve().then(fn).finally(() => Object.defineProperty(process, "platform", real));
}

const normalizer = require(path.join(ROOT, "lib/normalizer"));
const pending = require(path.join(ROOT, "nodes/audit-host/modules/pending-updates"));
const secEvents = require(path.join(ROOT, "nodes/audit-host/modules/security-events"));
const lynisMod = require(path.join(ROOT, "nodes/audit-host/modules/lynis"));
const trivyFs = require(path.join(ROOT, "nodes/audit-host/modules/trivy-fs"));

// ── stubs de módulos para el nodo audit-host ─────────────────────────────────
const lanza = {};   // módulo → true si debe rechazar
function stub(rel, fnName) {
  const p = require.resolve(path.join(ROOT, rel));
  const real = require(p);
  require.cache[p].exports = Object.assign({}, real, {
    [fnName]: (...a) => {
      if (lanza[fnName]) return Promise.reject(new Error(`${fnName} reventó`));
      return real[fnName](...a);
    },
  });
}
// cpu-memory es síncrono: su stub lanza de forma síncrona, como haría el real.
{
  const p = require.resolve(path.join(ROOT, "nodes/audit-host/modules/cpu-memory"));
  const real = require(p);
  require.cache[p].exports = { ...real, runSystemModule: () => { if (lanza.runSystemModule) throw new Error("os.cpus reventó"); return real.runSystemModule(); } };
}
stub("nodes/audit-host/modules/disk-storage", "getDiskInfo");
stub("nodes/audit-host/modules/trivy-fs", "runTrivyFs");
stub("nodes/audit-host/modules/security-events", "runSecurityEvents");

function ejecutarNodo(config) {
  const nodePath = require.resolve(path.join(ROOT, "nodes/audit-host/audit-host"));
  delete require.cache[nodePath];
  let ctor = null;
  require(nodePath)({
    nodes: {
      createNode(n) { n.on = (_e, fn) => { n._h = fn; }; n.status = (s) => { n._s = s; }; n.warn = () => {}; n.log = () => {}; },
      getNode: () => null,
      registerType: (_t, fn) => { ctor = fn; },
    },
  });
  const node = {};
  ctor.call(node, config);
  return new Promise((resolve) => {
    let enviado = null;
    node._h({}, (m) => { enviado = m; }, (e) => resolve({ msg: enviado, err: e || null, status: node._s }));
  });
}

const BASE = {
  enableCpu: true, enableDisk: true, enableSw: false, enableLynis: false, enableTrivy: false,
  securityEvents: true, enableUpdates: false, enableSecrets: false, trivySystemPkgs: false,
};

// Linux con journalctl sano y sin eventos: el caso "limpio" de referencia.
const JOURNAL_OK = {
  exists: (c) => (["journalctl", "who"].includes(c) ? "/usr/bin/" + c : null),
  exec: async (cmd, _t, opts) => {
    if (cmd.startsWith("journalctl")) return opts && opts.withStderr ? { stdout: "", stderr: "" } : "";
    if (cmd === "who") return "ana tty1 2026-10-24 09:00\n";
    if (cmd.startsWith("df")) return "Filesystem Type 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 ext4 1000 100 900 10% /\n";
    return execReal.execCommand(cmd, _t, opts);
  },
};

(async () => {
  console.log("\n── 1 · audit-host: un módulo que lanza no sale como ejecutado ─────\n");

  await seccion("audit-host", () => conPlataforma("linux", async () => {
    esc = JOURNAL_OK;
    let r = await ejecutarNodo(BASE);
    // El color depende de los datos reales del equipo (la memoria puede dar un high); lo que no puede salir es "incompleto".
    ok(r.err === null && r.status.shape === "dot" && !/sin completar/.test(r.status.text),
       "sin fallos el nodo no se marca como incompleto", JSON.stringify(r.status));
    // Los módulos apagados en BASE salen como 'disabled', que no es un fallo.
    ok(!r.msg.payload.findings.some((f) => f.skipped && f.kind !== "disabled"), "sin fallos no hay comprobaciones fallidas",
       JSON.stringify(r.msg.payload.findings.filter((f) => f.skipped).map((f) => [f.id, f.kind])));

    // Rechazos asíncronos solos: antes salían como ejecutados y en verde.
    lanza.getDiskInfo = lanza.runSecurityEvents = true;
    r = await ejecutarNodo(BASE);
    const m2 = Object.fromEntries(r.msg.payload.scanMeta.modules.map((m) => [m.id, m.status]));
    ok(m2["disk-storage"] === "failed" && m2["security-events"] === "failed" && m2["cpu-memory"] === "ok",
       "disco y eventos rechazan → failed; cpu sigue ok", JSON.stringify(m2));
    ok(r.status.fill !== "green" && r.status.shape === "ring" && /2 módulos sin completar/.test(r.status.text),
       "y el nodo se marca como incompleto, no en verde", JSON.stringify(r.status));

    lanza.runSystemModule = lanza.getDiskInfo = lanza.runSecurityEvents = true;
    r = await ejecutarNodo(BASE);
    ok(r.msg !== null, "con módulos que lanzan el nodo emite payload", r.err && r.err.message);
    const mods = Object.fromEntries(r.msg.payload.scanMeta.modules.map((m) => [m.id, m]));
    for (const id of ["cpu-memory", "disk-storage", "security-events"]) {
      ok(mods[id].status === "failed" && mods[id].ran === false && mods[id].kind === "error",
         `${id} que lanza → status failed, kind error`, JSON.stringify(mods[id]));
      ok(!r.msg.payload.scanMeta.modulesRun.includes(id), `${id} no aparece en modulesRun`);
    }
    const f = r.msg.payload.findings;
    for (const id of ["HOST-CPU-SKIP", "HOST-DISK-SKIP", "HOST-EVT-SKIP"]) {
      const x = f.find((y) => y.id === id);
      ok(x && x.skipped === true && x.kind === "error", `${id} con skipped:true y kind error`, JSON.stringify(x && [x.id, x.skipped, x.kind]));
    }
    ok(r.msg.payload.scanMeta.checksSkipped && r.msg.payload.scanMeta.checksSkipped.failed === 3,
       "los tres fallos llegan a checksSkipped", JSON.stringify(r.msg.payload.scanMeta.checksSkipped && r.msg.payload.scanMeta.checksSkipped.failed));
    ok(r.status.fill !== "green" && r.status.shape === "ring" && /3 módulos sin completar/.test(r.status.text),
       "con módulos fallidos el nodo queda en anillo y lo dice, no en verde", JSON.stringify(r.status));
    lanza.runSystemModule = lanza.getDiskInfo = lanza.runSecurityEvents = false;

    lanza.runTrivyFs = true;
    r = await ejecutarNodo({ ...BASE, enableTrivy: true });
    ok(r.err && /Trivy no pudo completar/.test(r.err.message) && r.status.fill === "red",
       "trivy-fs que lanza → rama TRIVY_FATAL (error y estado rojo)", JSON.stringify([r.err && r.err.message, r.status]));
    lanza.runTrivyFs = false;
    esc = null;
  }));

  console.log("\n── 2 · trivy-fs: todas o algunas carpetas del home fallan ─────────\n");

  if (IS_WIN) {
    console.log("  ⊘ Windows: el trivy falso es un script con shebang. Sin comprobar.");
  } else {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "lcaudit-test-silent-"));
    const home = path.join(tmp, "home");
    const bin = path.join(tmp, "bin");
    for (const d of [home, bin, path.join(home, "a"), path.join(home, "b")]) fs.mkdirSync(d, { recursive: true });
    const modo = path.join(tmp, "modo");
    // Falla en las carpetas que lista el fichero `modo`; en el resto escribe un JSON vacío.
    fs.writeFileSync(path.join(bin, "trivy"),
      "#!/usr/bin/env node\n" +
      "const fs = require('fs');\n" +
      "const a = process.argv.slice(2);\n" +
      "if (a[0] === '--version') { console.log('Version: 0.0.0-fake'); process.exit(0); }\n" +
      `const malas = fs.readFileSync(${JSON.stringify(modo)}, 'utf8').split(',');\n` +
      "const t = a[a.length - 1];\n" +
      "if (malas.some((m) => m && t.endsWith('/' + m))) { console.error('FATAL fake error'); process.exit(1); }\n" +
      "fs.writeFileSync(a[a.indexOf('-o') + 1], JSON.stringify({ Results: [] }));\n",
      { mode: 0o755 });
    const envReal = { PATH: process.env.PATH, HOME: process.env.HOME, SUDO_USER: process.env.SUDO_USER };
    process.env.PATH = `${bin}${path.delimiter}${process.env.PATH}`;
    process.env.HOME = home;
    delete process.env.SUDO_USER;

    fs.writeFileSync(modo, "a,b");
    let res = await trivyFs.runTrivyFs({});
    ok(res.skipped === true && res.kind === "error", "fallan todas las carpetas → skipped kind error",
       JSON.stringify({ skipped: res.skipped, kind: res.kind, children: res.scan && res.scan.children }));
    let f = normalizer.normalizeHost({ trivy: res }, { platform: "linux" });
    ok(f.some((x) => x.id === "HOST-CVE-SKIP" && x.skipped === true), "y sale HOST-CVE-SKIP", JSON.stringify(f.map((x) => x.id)));

    fs.writeFileSync(modo, "b");
    res = await trivyFs.runTrivyFs({});
    ok(!res.skipped && res.scan.children.scanned.length === 1, "falla una de dos → el escaneo sigue", JSON.stringify(res.scan && res.scan.children));
    f = normalizer.normalizeHost({ trivy: res }, { platform: "linux" });
    const par = f.find((x) => x.id === "HOST-CVE-PARTIAL");
    ok(par && par.skipped === true && par.kind === "error" && /~\/b/.test(par.evidence),
       "y sale HOST-CVE-PARTIAL (skipped, kind error) nombrando la carpeta", JSON.stringify(f.map((x) => [x.id, x.skipped, x.kind])));

    fs.writeFileSync(modo, "");
    res = await trivyFs.runTrivyFs({});
    f = normalizer.normalizeHost({ trivy: res }, { platform: "linux" });
    ok(!res.skipped && !f.some((x) => x.skipped), "sin fallos ni skip ni PARTIAL", JSON.stringify(f.map((x) => x.id)));

    console.log("\n── 7 · trivy-fs: SUDO_USER no pasa por una shell ──────────────────\n");
    const sentinel = path.join(tmp, "SENTINEL");
    const cwd = process.cwd();
    process.chdir(tmp);
    process.env.SUDO_USER = "nadie;touch SENTINEL";
    trivyFs.resolveUserHome();
    process.chdir(cwd);
    ok(!fs.existsSync(sentinel), "un SUDO_USER con ';' no ejecuta nada");

    for (const [k, v] of Object.entries(envReal)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    fs.rmSync(tmp, { recursive: true, force: true });
  }

  console.log("\n── 3 · pending-updates: salida parcial de un comando que falló ────\n");

  await seccion("pending-updates", () => conPlataforma("linux", async () => {
    const CASOS = [
      { mgr: "apt", basura: "Listing... Done\n", buena: "Listing...\nopenssl/stable-security 3.0.2 amd64 [upgradable from: 3.0.1]\n" },
      { mgr: "zypper", basura: "Loading repository data...\nReading installed packages...\n",
        buena: "S | Repository | Name | Current Version | Available Version | Arch\n--+---+---+---+---+---\nv | repo-oss | openssl | 3.0.1 | 3.0.2 | x86_64\n" },
      { mgr: "apk", basura: "WARNING: opening /var/cache: No such file\n", buena: "openssl-3.0.1-r0 < 3.0.2-r0\n" },
    ];
    for (const c of CASOS) {
      for (const [tipo, out] of [["basura", c.basura], ["buena", c.buena]]) {
        esc = { exec: async () => { throw falla("exit 100", { stdout: out, stderr: "E: algo falló" }); } };
        const r = await pending.getPendingUpdates({ pkgManager: c.mgr });
        if (tipo === "basura") {
          ok(r.skipped === true && r.kind === "error", `${c.mgr} falla sin paquetes legibles → skipped kind error`, JSON.stringify(r));
        } else {
          ok(!r.skipped && r.total === 1, `${c.mgr} falla pero su salida trae 1 paquete → se usa`, JSON.stringify(r));
        }
      }
      esc = { exec: async () => c.buena };
      const r = await pending.getPendingUpdates({ pkgManager: c.mgr });
      ok(!r.skipped && r.total === 1, `${c.mgr} sin error → igual que antes`);
    }
    esc = null;
  }));

  console.log("\n── 4 · security-events: consultas fallidas no son \"sin eventos\" ───\n");

  await seccion("security-events", () => conPlataforma("linux", async () => {
    const who = "ana tty1 2026-10-24 09:00\n";
    const linux = (journal) => ({
      exists: (c) => (["journalctl", "who"].includes(c) ? "/usr/bin/" + c : null),
      exec: async (cmd, t, opts) => (cmd === "who" ? who : journal(cmd, opts)),
    });

    esc = linux(() => { throw falla("Command failed: journalctl", { stderr: "Failed to open journal" }); });
    let r = await secEvents.runSecurityEvents(24);
    ok(r.skipped === true && r.kind === "error", "fallan las tres consultas de journalctl → skipped kind error", JSON.stringify([r.skipped, r.kind, r.sources]));
    let f = normalizer.fromSecurityEvents(r, "linux");
    ok(f.length === 1 && f[0].id === "HOST-EVT-SKIP" && !f.some((x) => x.id === "HOST-EVT-INF"),
       "→ HOST-EVT-SKIP, nunca \"Sin eventos de seguridad relevantes\"", JSON.stringify(f.map((x) => x.id)));

    esc = linux(() => { throw falla("Command failed", { stderr: "No journal files were opened due to insufficient permissions." }); });
    r = await secEvents.runSecurityEvents(24);
    ok(r.skipped === true && r.kind === "no-permission", "fallan por permisos → kind no-permission", JSON.stringify([r.skipped, r.kind]));

    esc = linux((_c, opts) => {
      const stderr = "Hint: You are currently not seeing messages from other users and the system.";
      return opts && opts.withStderr ? { stdout: "-- No entries --\n", stderr } : "-- No entries --\n";
    });
    r = await secEvents.runSecurityEvents(24);
    ok(r.skipped === true && r.kind === "no-permission",
       "journalctl sale con 0 pero avisa de que no ve el sistema → no-permission", JSON.stringify([r.skipped, r.kind, r.sources]));

    let n = 0;
    esc = linux((_c, opts) => {
      if (n++ === 0) return opts && opts.withStderr ? { stdout: "", stderr: "" } : "";
      throw falla("Command failed: journalctl");
    });
    r = await secEvents.runSecurityEvents(24);
    f = normalizer.fromSecurityEvents(r, "linux");
    ok(!r.skipped && r.sources.includes("journalctl") && f.some((x) => x.id === "HOST-EVT-SRC"),
       "una consulta funciona → journalctl cuenta, y las otras salen en HOST-EVT-SRC", JSON.stringify([r.skipped, r.sources, f.map((x) => x.id)]));

    esc = linux((_c, opts) => (opts && opts.withStderr ? { stdout: "", stderr: "" } : ""));
    r = await secEvents.runSecurityEvents(24);
    f = normalizer.fromSecurityEvents(r, "linux");
    ok(!r.skipped && f.length === 1 && f[0].id === "HOST-EVT-INF" && f[0].skipped !== true,
       "journalctl sano sin eventos → HOST-EVT-INF, como antes", JSON.stringify(f.map((x) => [x.id, x.skipped])));
    esc = null;
  }));

  await seccion("security-events macOS", () => conPlataforma("darwin", async () => {
    esc = {
      exists: (c) => (["log", "who"].includes(c) ? "/usr/bin/" + c : null),
      exec: async (cmd) => { if (cmd === "who") return "ana console Oct 24 09:00\n"; throw falla("log: Cannot run while sandboxed"); },
    };
    const r = await secEvents.runSecurityEvents(24);
    ok(r.skipped === true && r.kind === "error", "macOS: fallan las tres `log show` → skipped kind error", JSON.stringify([r.skipped, r.kind, r.sources]));
    esc = null;
  }));

  const skipF = normalizer.fromSecurityEvents({ skipped: true, reason: "x", windowHours: 24 }, "linux")[0];
  ok(skipF.skipped === true && skipF.kind === "error", "HOST-EVT-SKIP sin kind → skipped:true, kind error", JSON.stringify([skipF.skipped, skipF.kind]));
  const permF = normalizer.fromSecurityEvents({ skipped: true, kind: "no-permission", reason: "x", windowHours: 24 }, "linux")[0];
  ok(permF.kind === "no-permission", "HOST-EVT-SKIP respeta el kind que llega");

  console.log("\n── 5 · Ids únicos: eventos y secretos omitidos a la vez ───────────\n");

  const ambos = normalizer.normalizeHost({
    securityEvents: { skipped: true, kind: "error", reason: "x", windowHours: 24 },
    trivySecrets: { skipped: true, kind: "error", reason: "y" },
  }, { platform: "linux" });
  const ids = ambos.map((x) => x.id);
  ok(new Set(ids).size === ids.length && ids.includes("HOST-EVT-SKIP") && ids.includes("HOST-SEC-SKIP"),
     "HOST-EVT-SKIP y HOST-SEC-SKIP conviven sin repetir id (clave Vue)", JSON.stringify(ids));

  console.log("\n── 6 · lynis: timeout, informe incompleto y respaldo antiguo ──────\n");

  if (IS_WIN) {
    console.log("  ⊘ Windows: Lynis sale como 'unsupported' antes de ejecutarse. Sin comprobar.");
  } else {
    const fixtures = path.join(ROOT, "test/fixtures/lynis");
    for (const fx of fs.readdirSync(fixtures).filter((x) => x.endsWith(".dat"))) {
      // Los fixtures son informes reales completos: tienen que seguir valiendo.
      ok(/^report_datetime_end=\S/m.test(fs.readFileSync(path.join(fixtures, fx), "utf8")), `fixture ${fx} trae report_datetime_end`);
    }
    const COMPLETO = fs.readFileSync(path.join(fixtures, "report-cachyos.dat"), "utf8");
    const A_MEDIAS = "lynis_version=3.1.1\nwarning[]=AUTH-9286|Algo|-|-|\n";
    const repFile = (cmd) => /--report-file "([^"]+)"/.exec(cmd)[1];
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "lcaudit-test-lynis-"));
    const fallback = path.join(tmp, "lynis-report.dat");
    const lynis = (exec) => ({ exists: (c) => (c === "lynis" ? "/fake/lynis" : null), exec });

    await seccion("lynis", () => conPlataforma("linux", async () => {
      esc = lynis(async (cmd) => { fs.writeFileSync(repFile(cmd), A_MEDIAS); throw falla("killed", { killed: true, signal: "SIGTERM" }); });
      let r = await lynisMod.runLynis({ reportFallback: fallback });
      ok(r.skipped === true && r.kind === "timeout", "timeout con informe parcial escrito → kind timeout, se descarta", JSON.stringify(r));

      esc = lynis(async (cmd) => { fs.writeFileSync(repFile(cmd), A_MEDIAS); return ""; });
      r = await lynisMod.runLynis({ reportFallback: fallback });
      ok(r.skipped === true && r.kind === "error", "informe sin fecha de fin ni índice → kind error", JSON.stringify(r));

      esc = lynis(async (cmd) => { fs.writeFileSync(repFile(cmd), COMPLETO); throw falla("exit 1"); });
      r = await lynisMod.runLynis({ reportFallback: fallback });
      ok(!r.skipped && r.hardeningIndex === 67, "exit distinto de cero con informe completo → se usa, como antes", JSON.stringify(r.hardeningIndex));

      // Respaldo de una pasada anterior: una hora de antigüedad.
      fs.writeFileSync(fallback, COMPLETO);
      const viejo = (Date.now() - 3600 * 1000) / 1000;
      fs.utimesSync(fallback, viejo, viejo);
      esc = lynis(async () => "");
      r = await lynisMod.runLynis({ reportFallback: fallback });
      ok(r.skipped === true && r.kind === "error", "respaldo con mtime anterior a la ejecución → no se usa", JSON.stringify(r));

      esc = lynis(async () => { fs.writeFileSync(fallback, COMPLETO); return ""; });
      r = await lynisMod.runLynis({ reportFallback: fallback });
      ok(!r.skipped && r.hardeningIndex === 67, "respaldo escrito por esta ejecución → se usa", JSON.stringify(r.kind));
      esc = null;
    }));
    fs.rmSync(tmp, { recursive: true, force: true });
  }

  console.log(`\n${passed} pasados · ${failed} fallidos`);
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
