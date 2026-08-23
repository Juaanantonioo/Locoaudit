"use strict";

/**
 * test-security-events-win32.js — Test manual de la rama Windows de
 * security-events: parsers puros + normalizador, con fixtures sintéticas.
 * NO ejecuta PowerShell: se puede lanzar desde cualquier SO.
 *
 *   node test/manual/test-security-events-win32.js
 *
 * Cubre también la correlación entre las dos fuentes que describen el mismo
 * acceso cuando Node-RED va elevado (lib/win-logons.js), con una fixture calcada
 * de la medición real: un login SSH que producía 4 filas y 3 findings.
 *
 * Verificación adicional pendiente en la VM Windows (no automatizable aquí):
 *   - Node-RED sin admin  → finding HOST-SEC-WIN-PERM, sin crash
 *   - Node-RED como admin → eventos 4624/4625 reales, y UNA fila por acceso
 *   - 2-3 logins fallidos provocados → agregado low (HOST-SEC-WINF-001)
 *   - índice real de TargetLogonId/SubjectLogonId en los Properties del evento
 */

const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const {
  parseWinEventsJson,
  parseSshdLines,
  parseQueryUserLines,
  parseQwinstaLines,
  buildWinEventsScript,
  buildEventList,
} = require("../../nodes/audit-host/modules/security-events");
const { fromSecurityEvents } = require("../../lib/normalizer");
const { withTempFile } = require("../../lib/utils");
const { summarize } = require("../../lib/severity-map");
const { execCommand } = require("../../lib/executor");
const { SECURITY_EVENT_RULES } = require("../../lib/severity-map");

let passed = 0;
function check(name, fn) {
  fn();
  passed++;
  console.log(`  ✓ ${name}`);
}
const byId = (findings, prefix) => findings.filter((f) => f.id.startsWith(prefix));

// ── 1. parseWinEventsJson ───────────────────────────────────────────────────
console.log("parseWinEventsJson:");

check("varios eventos (arrays)", () => {
  const w = parseWinEventsJson(JSON.stringify({
    denied: false,
    logons: [
      { t: "2026-07-07 09:00:00", user: "bob", type: 10, ip: "192.168.1.50" },
      { t: "2026-07-07 09:05:00", user: "eve", type: 3, ip: "192.168.1.66" },
    ],
    localLogonCount: 7,
    failed: [{ t: "2026-07-07 08:00:00", user: "admin", type: 10, ip: "10.0.0.9" }],
    privileged: [{ t: "2026-07-07 09:00:05", user: "bob", remote: true, ip: "192.168.1.50" }],
  }));
  assert.strictEqual(w.securityLogDenied, false);
  assert.strictEqual(w.logons.remote.length, 2);
  assert.strictEqual(w.logons.remote[0].logonType, 10);
  assert.strictEqual(w.logons.localCount, 7);
  assert.strictEqual(w.failed[0].ip, "10.0.0.9");
  assert.strictEqual(w.privileged[0].remote, true);
});

check("1 evento → objeto (colapso de ConvertTo-Json) normalizado a array", () => {
  const w = parseWinEventsJson(JSON.stringify({
    denied: false,
    logons: { t: "2026-07-07 09:00:00", user: "bob", type: 10, ip: "192.168.1.50" },
    localLogonCount: 0,
    failed: { t: "2026-07-07 08:00:00", user: "admin", type: 3, ip: "10.0.0.9" },
    privileged: { t: "2026-07-07 09:00:05", user: "bob", remote: false, ip: "" },
  }));
  assert.strictEqual(w.logons.remote.length, 1);
  assert.strictEqual(w.failed.length, 1);
  assert.strictEqual(w.privileged.length, 1);
  assert.strictEqual(w.privileged[0].remote, false);
});

check("acceso denegado", () => {
  const w = parseWinEventsJson(JSON.stringify({
    denied: true, logons: [], localLogonCount: 0, failed: [], privileged: [],
  }));
  assert.strictEqual(w.securityLogDenied, true);
});

// ── 2. parseQueryUserLines / parseQwinstaLines ──────────────────────────────
console.log("parseQueryUserLines:");

check("consola + RDP + desconectada", () => {
  const out = [
    " USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME",
    ">juanan                console             1  Active      none   07/07/2026 9:00",
    " bob                   rdp-tcp#55          2  Active          .  07/07/2026 8:30",
    " carol                                     3  Disc      1+02:15  06/07/2026 22:00",
  ].join("\n");
  const s = parseQueryUserLines(out);
  assert.strictEqual(s.length, 3);
  assert.deepStrictEqual(
    s.map((x) => [x.user, x.origin]),
    [["juanan", null], ["bob", "RDP"], ["carol", null]]
  );
  assert.strictEqual(s[1].tty, "rdp-tcp#55");
  assert.strictEqual(s[1].since, "07/07/2026 8:30");
  assert.strictEqual(s[2].tty, null); // sin SESSIONNAME (desconectada)
});

check("qwinsta: solo filas con usuario", () => {
  const out = [
    " SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE",
    " services                                    0  Disc",
    ">console           juanan                    1  Active",
    " rdp-tcp#55        bob                       2  Active",
    " rdp-tcp                                 65536  Listen",
  ].join("\n");
  const s = parseQwinstaLines(out);
  assert.strictEqual(s.length, 2);
  assert.deepStrictEqual(
    s.map((x) => [x.user, x.origin]),
    [["juanan", null], ["bob", "RDP"]]
  );
});

// ── 3. Normalizador: rama win32 ─────────────────────────────────────────────
console.log("fromSecurityEvents (win32):");

const baseRaw = () => ({
  windowHours: 24,
  platform: "win32",
  sources: ["Get-WinEvent", "query user"],
  partial: [],
  ssh: { accepted: [], failed: [] },
  sudo: { ok: [], failed: [] },
  sessions: [],
  windows: {
    securityLogDenied: false,
    logons: { remote: [], localCount: 0 },
    failed: [],
    privileged: [],
  },
});

check("logins remotos → info individual; locales agregados solo si hay remotos", () => {
  const raw = baseRaw();
  raw.windows.logons.remote = [
    { user: "bob", ip: "192.168.1.50", logonType: 10, timestamp: "2026-07-07 09:00:00" },
  ];
  raw.windows.logons.localCount = 5;
  const f = fromSecurityEvents(raw);
  const rdp = byId(f, "HOST-SEC-WIN-RDP");
  assert.strictEqual(rdp.length, 1);
  assert.strictEqual(rdp[0].severity, SECURITY_EVENT_RULES.SSH_ACCEPTED);
  assert.strictEqual(byId(f, "HOST-SEC-WIN-LOC").length, 1);
});

check("locales omitidos si 0 remotos (filtrado de ruido)", () => {
  const raw = baseRaw();
  raw.windows.logons.localCount = 5;
  const f = fromSecurityEvents(raw);
  assert.strictEqual(byId(f, "HOST-SEC-WIN-LOC").length, 0);
  assert.strictEqual(byId(f, "HOST-SEC-INF").length, 1); // sin eventos relevantes
});

check("fallidos < umbral → low agregado", () => {
  const raw = baseRaw();
  raw.windows.failed = [1, 2, 3].map((i) => ({
    user: "admin", ip: `10.0.0.${i}`, logonType: 10, timestamp: null,
  }));
  const f = fromSecurityEvents(raw);
  const wf = byId(f, "HOST-SEC-WINF");
  assert.strictEqual(wf.length, 1);
  assert.strictEqual(wf[0].severity, SECURITY_EVENT_RULES.SSH_FAILED_FEW);
});

check("fallidos >= SSH_BRUTE_FORCE_THRESHOLD → high fuerza bruta (mismo umbral que SSH)", () => {
  const raw = baseRaw();
  const n = SECURITY_EVENT_RULES.SSH_BRUTE_FORCE_THRESHOLD;
  raw.windows.failed = Array.from({ length: n }, (_, i) => ({
    user: "admin", ip: "10.0.0.9", logonType: 3, timestamp: null,
  }));
  const f = fromSecurityEvents(raw);
  const wf = byId(f, "HOST-SEC-WINF");
  assert.strictEqual(wf[0].severity, SECURITY_EVENT_RULES.SSH_FAILED_MANY);
  assert.ok(/fuerza bruta/i.test(wf[0].title));
});

check("4672 remoto → high individual; local → info agregado", () => {
  const raw = baseRaw();
  raw.windows.privileged = [
    { user: "bob", remote: true, ip: "192.168.1.50", timestamp: "2026-07-07 09:00:05" },
    { user: "juanan", remote: false, ip: null, timestamp: "2026-07-07 08:00:00" },
    { user: "juanan", remote: false, ip: null, timestamp: "2026-07-07 10:00:00" },
  ];
  const f = fromSecurityEvents(raw);
  const pr = byId(f, "HOST-SEC-WIN-PRIV").filter((x) => x.id !== "HOST-SEC-WIN-PRIVL");
  assert.strictEqual(pr.length, 1);
  assert.strictEqual(pr[0].severity, SECURITY_EVENT_RULES.SSH_ACCEPTED_ROOT);
  const pl = f.filter((x) => x.id === "HOST-SEC-WIN-PRIVL");
  assert.strictEqual(pl.length, 1);
  assert.strictEqual(pl[0].severity, "info");
});

check("sesión RDP activa → info individual; locales → agregado", () => {
  const raw = baseRaw();
  raw.sessions = [
    { user: "juanan", tty: "console", since: "07/07/2026 9:00", origin: null },
    { user: "bob", tty: "rdp-tcp#55", since: "07/07/2026 8:30", origin: "RDP" },
  ];
  const f = fromSecurityEvents(raw);
  assert.strictEqual(byId(f, "HOST-SEC-SES-0").length, 1);
  assert.strictEqual(byId(f, "HOST-SEC-SES-LOC").length, 1);
});

check("acceso denegado → HOST-SEC-WIN-PERM info, sin 'sin eventos'", () => {
  const raw = baseRaw();
  raw.windows.securityLogDenied = true;
  const f = fromSecurityEvents(raw);
  const perm = byId(f, "HOST-SEC-WIN-PERM");
  assert.strictEqual(perm.length, 1);
  assert.strictEqual(perm[0].severity, "info");
  // El fix NO puede recomendar ejecutar Node-RED como administrador: es
  // justo lo que CLAUDE.md descarta ("Elevación UAC en Windows"). La vía con
  // mínimo privilegio es el grupo integrado de lectores del registro.
  assert.ok(!/Node-RED como administrador/i.test(perm[0].fix));
  assert.ok(/Event Log Readers|Lectores del registro de eventos/.test(perm[0].fix));
  assert.strictEqual(perm[0].command, "Add-LocalGroupMember -SID S-1-5-32-573 -Member $env:USERNAME");
  assert.strictEqual(perm[0].isCommand, true);
  // Regla del proyecto: `command` es SOLO la línea ejecutable; la nota va
  // detrás, en el fix, nunca dentro del comando copiable.
  assert.strictEqual(perm[0].fix.split("\n")[0], perm[0].command);
  assert.ok(perm[0].fix.split("\n").length > 1);
  assert.strictEqual(byId(f, "HOST-SEC-WIN-UAC").length, 0);
  assert.strictEqual(byId(f, "HOST-SEC-INF").length, 0);
});

check("no se emite el aviso UAC/4688: no se comprobaba nada real", () => {
  // Se emitía siempre que el canal Security fuera legible, sin mirar la
  // directiva, y su fix (auditpol) no afectaba a lo que el módulo lee:
  // Get-WinEvent nunca pide el 4688.
  const f = fromSecurityEvents(baseRaw());
  assert.strictEqual(byId(f, "HOST-SEC-WIN-UAC").length, 0);
  assert.ok(!f.some((x) => /auditpol/.test(x.fix || "")));
});

check("skipped (sin PowerShell) → HOST-SEC-SKIP", () => {
  const f = fromSecurityEvents({
    skipped: true,
    reason: "ni powershell ni pwsh disponibles",
    windowHours: 24,
    platform: "win32",
  });
  assert.strictEqual(f.length, 1);
  assert.strictEqual(f[0].id, "HOST-SEC-SKIP");
});

// ── 4. Script PowerShell ────────────────────────────────────────────────────
console.log("buildWinEventsScript:");

check("usa FilterHashtable + AddHours (sin fechas en texto, locale-safe)", () => {
  const s = buildWinEventsScript(48);
  assert.ok(s.includes("Get-WinEvent -FilterHashtable"));
  assert.ok(s.includes("AddHours(-48)"));
  assert.ok(s.includes("4624, 4625, 4672"));
  assert.ok(s.includes("NoMatchingEventsFound"));
  assert.ok(s.includes("denied"));
});

check("emite logonId de 4624 y 4672 (clave de correlación, antes se tiraba)", () => {
  const s = buildWinEventsScript(24);
  assert.ok(s.includes("logonId = (V $p 7)"));   // TargetLogonId del 4624
  assert.ok(s.includes("logonId = $logonId"));   // SubjectLogonId del 4672
});

check("filtro de cuentas de servicio: un solo sitio y sshd_<PID> por patrón", () => {
  const s = buildWinEventsScript(24);
  // El PID varía por conexión: tiene que ser patrón, no entrada literal.
  assert.ok(s.includes("$u -match '^sshd_\\d+$'"));
  assert.ok(!/\$svc = @\([^)]*sshd/.test(s));
  // Y la decisión vive en una función, no repetida en cada rama de Id.
  assert.strictEqual((s.match(/if \(Svc \$/g) || []).length, 3);
});

// ── 5. buildEventList (payload.securityEvents del dashboard) ────────────────
console.log("buildEventList:");

check("aplana, ordena desc y forma {windowHours, events, truncated}", () => {
  const raw = baseRaw();
  raw.windows.logons.remote = [
    { user: "bob", ip: "192.168.1.50", logonType: 10, timestamp: "2026-07-07 09:00:00" },
  ];
  raw.windows.failed = [
    { user: "admin", ip: "10.0.0.9", logonType: 3, timestamp: "2026-07-07 11:00:00" },
  ];
  raw.sessions = [{ user: "bob", tty: "rdp-tcp#55", since: "2026-07-07 08:30:00", origin: "RDP" }];
  const out = buildEventList(raw);
  assert.strictEqual(out.windowHours, 24);
  assert.strictEqual(out.truncated, false);
  assert.deepStrictEqual(out.events.map((e) => e.type), ["logon-failed", "logon-remote", "session"]);
  assert.ok(out.events.every((e) => "ts" in e && "type" in e && "user" in e && "origin" in e && "detail" in e));
});

check("unix: ssh/sudo → tipos ssh-accepted/ssh-failed/sudo/sudo-failed", () => {
  const out = buildEventList({
    windowHours: 24, platform: "darwin", sources: ["log"], partial: [],
    ssh: {
      accepted: [{ user: "juanan", ip: "192.168.1.2", method: "publickey", timestamp: "2026-07-07 10:00:00" }],
      failed: [{ user: "root", ip: "192.168.1.99", timestamp: "2026-07-07 10:05:00" }],
    },
    sudo: {
      ok: [{ user: "juanan", command: "/usr/bin/whoami", timestamp: "2026-07-07 09:00:00" }],
      failed: [{ user: "juanan", timestamp: "2026-07-07 09:01:00" }],
    },
    sessions: [],
  });
  assert.deepStrictEqual(
    out.events.map((e) => e.type),
    ["ssh-failed", "ssh-accepted", "sudo-failed", "sudo"] // desc por ts
  );
  assert.strictEqual(out.events[3].detail, "/usr/bin/whoami");
});

check("tope 200 + truncated: true", () => {
  const raw = baseRaw();
  raw.windows.failed = Array.from({ length: 250 }, (_, i) => ({
    user: "admin", ip: "10.0.0.9", logonType: 3, timestamp: `2026-07-07 10:${String(i % 60).padStart(2, "0")}:00`,
  }));
  const out = buildEventList(raw);
  assert.strictEqual(out.events.length, 200);
  assert.strictEqual(out.truncated, true);
});

check("skipped → events: [] y sessionsChecked: false", () => {
  const out = buildEventList({ skipped: true, reason: "x", windowHours: 12, platform: "win32" });
  // sessionsChecked=false: sin recolección no se preguntó a nadie, y el panel no
  // puede pintar "Sin sesiones remotas activas" sobre eso.
  assert.deepStrictEqual(out, { windowHours: 12, events: [], truncated: false, sessionsChecked: false });
});

check("sessionsChecked viaja al dashboard cuando sí se consultó", () => {
  const out = buildEventList({
    windowHours: 5, platform: "win32", sessionsChecked: true,
    sessions: [{ user: "ines", tty: "rdp-tcp#1", since: "2026-08-22 12:00", origin: "192.168.0.25" }],
    ssh: { accepted: [], failed: [] }, sudo: { ok: [], failed: [] },
  });
  assert.strictEqual(out.sessionsChecked, true);
  assert.strictEqual(out.events.filter((e) => e.type === "session").length, 1);
});

// ── 6. Correlación SSH ↔ canal Security (lib/win-logons.js) ─────────────────
//
// Con Node-RED SIN elevar solo se lee OpenSSH/Operational y no hay nada que
// correlacionar. Con Node-RED ELEVADO se leen los dos canales y un ÚNICO login
// SSH producía CUATRO filas y TRES findings. Fixture calcada de la medición
// real en Windows (solo la fecha es inventada: la evidencia daba las horas).
console.log("correlación SSH ↔ Security (evidencia real):");

// JSON tal cual lo emite el script PowerShell para ese login. El 4672 de
// sshd_13048 se incluye a propósito aunque el script ya lo filtre: así se
// comprueba también la red de seguridad de parseWinEventsJson.
const EVIDENCIA_PS = JSON.stringify({
  denied: false,
  logons: [{ t: "2026-08-22 18:51:02", user: "inesg", type: 3, ip: "-", logonId: "0x1A2B3C" }],
  localLogonCount: 0,
  failed: [],
  privileged: [
    { t: "2026-08-22 18:51:02", user: "inesg", remote: true, ip: "-", logonId: "0x1A2B3C" },
    { t: "2026-08-22 18:51:01", user: "sshd_13048", remote: false, ip: "", logonId: "0x1A2A00" },
  ],
  ssh: ["2026-08-22 18:51:07 Accepted password for inesg from 192.168.0.25 port 51234 ssh2"],
  sshLog: "",
});

/** Monta el `raw` de runSecurityEvents a partir del JSON del script. */
function rawDesdePs(jsonText) {
  const parsed = parseWinEventsJson(jsonText);
  return {
    windowHours: 24,
    platform: "win32",
    sources: ["Get-WinEvent(OpenSSH)", "Get-WinEvent(Security)"],
    partial: [],
    ssh: parseSshdLines(parsed.sshLines.join("\n")),
    sudo: { ok: [], failed: [] },
    sessions: [],
    sessionsChecked: true,
    windows: {
      securityLogDenied: false,
      logons: parsed.logons,
      failed: parsed.failed,
      privileged: parsed.privileged,
    },
  };
}

check("sshd_<PID> no es un usuario: fuera también en el parser", () => {
  const w = parseWinEventsJson(EVIDENCIA_PS);
  assert.strictEqual(w.privileged.length, 1);
  assert.strictEqual(w.privileged[0].user, "inesg");
});

check('IpAddress "-" de Windows → null (la columna ORIGEN pintaba "-")', () => {
  const w = parseWinEventsJson(EVIDENCIA_PS);
  assert.strictEqual(w.logons.remote[0].ip, null);
  assert.strictEqual(w.privileged[0].ip, null);
});

check("logonId llega hasta JS (4624 y 4672 comparten el de la sesión)", () => {
  const w = parseWinEventsJson(EVIDENCIA_PS);
  assert.strictEqual(w.logons.remote[0].logonId, "0x1A2B3C");
  assert.strictEqual(w.privileged[0].logonId, "0x1A2B3C");
});

check("evidencia real: 4 filas → 1, con la IP real y el método", () => {
  const out = buildEventList(rawDesdePs(EVIDENCIA_PS));
  assert.strictEqual(out.events.length, 1);
  const ev = out.events[0];
  assert.strictEqual(ev.type, "ssh-accepted");        // sobrevive la de SSH
  assert.strictEqual(ev.user, "inesg");
  assert.strictEqual(ev.origin, "192.168.0.25");      // el 4624 traía "-"
  assert.ok(/password/.test(ev.detail));
});

check("evidencia real: el privilegio no se pierde, se anota en la fila que queda", () => {
  const ev = buildEventList(rawDesdePs(EVIDENCIA_PS)).events[0];
  assert.strictEqual(ev.privileged, true);
  assert.ok(/privilegios de administrador \(4672\)/.test(ev.detail));
  // El 4672 habla de la CUENTA, no de la sesión: Windows lo emite porque la
  // cuenta está en el grupo Administradores, aunque no se eleve nada. Decir
  // "la sesión obtuvo privilegios" sugería lo contrario a quien entró por SSH
  // sin elevar nada en ningún momento.
  assert.ok(/cuenta/i.test(ev.detail));
  assert.ok(!/la sesión (obtuvo|tenía|estaba)/i.test(ev.detail));
});

check("evidencia real: 3 findings → 1, y el 4672 consta en su evidencia", () => {
  const f = fromSecurityEvents(rawDesdePs(EVIDENCIA_PS));
  assert.strictEqual(f.length, 1);
  // Antes salía como HOST-SEC-SSH-001 en info: el 4672 correlacionado dice que
  // la cuenta es administradora, y eso es una identidad privilegiada entrando
  // desde la red — el mismo nivel que un root por SSH en Unix y que el mismo
  // hecho llegando por RDP. El protocolo ya no decide la severidad.
  assert.strictEqual(f[0].id, "HOST-SEC-SSH-R-001");
  assert.strictEqual(f[0].severity, SECURITY_EVENT_RULES.SSH_ACCEPTED_ROOT);
  assert.strictEqual(byId(f, "HOST-SEC-WIN-RDP").length, 0);
  // Y NO se emite además PRIV-001: sería el mismo hecho dos veces, que es lo
  // que la deduplicación evita. La señal alta la da ya la vía SSH.
  assert.strictEqual(byId(f, "HOST-SEC-WIN-PRIV").length, 0);
  assert.ok(/4672/.test(f[0].evidence));
  assert.ok(/LogonId 0x1A2B3C/.test(f[0].evidence));
});

check("SSH Windows SIN 4672 sigue en info: no todo acceso es privilegiado", () => {
  const raw = rawDesdePs(EVIDENCIA_PS);
  raw.windows.privileged = [];          // misma sesión, cuenta sin privilegios
  const f = fromSecurityEvents(raw);
  const ssh = f.filter((x) => /^HOST-SEC-SSH-/.test(x.id));
  assert.strictEqual(ssh.length, 1);
  assert.strictEqual(ssh[0].id, "HOST-SEC-SSH-001");
  assert.strictEqual(ssh[0].severity, SECURITY_EVENT_RULES.SSH_ACCEPTED);
  assert.ok(!/4672/.test(ssh[0].evidence));
});

check("el predicado es uno: root en Unix sigue dando exactamente lo de siempre", () => {
  const f = fromSecurityEvents({
    windowHours: 24, platform: "linux", sources: ["journalctl"], partial: [],
    ssh: { accepted: [{ user: "root", ip: "192.168.1.9", method: "password", timestamp: "2026-08-22 10:00:00" }], failed: [] },
    sudo: { ok: [], failed: [] }, sessions: [],
  });
  const r = f.filter((x) => /^HOST-SEC-SSH-R-/.test(x.id));
  assert.strictEqual(r.length, 1);
  assert.strictEqual(r[0].title, "Acceso SSH como root detectado");
  assert.strictEqual(r[0].severity, SECURITY_EVENT_RULES.SSH_ACCEPTED_ROOT);
  // Sin canal Security no hay 4672 que citar: la evidencia queda como siempre.
  assert.ok(!/4672/.test(r[0].evidence));
});

// ── El caso contrario: la señal que NO se puede perder al deduplicar ────────
const rawIntruso = () => ({
  windowHours: 24, platform: "win32", sources: ["Get-WinEvent(Security)"], partial: [],
  ssh: { accepted: [], failed: [] }, sudo: { ok: [], failed: [] },
  sessions: [], sessionsChecked: true,
  windows: {
    securityLogDenied: false,
    logons: { remote: [{ user: "mallory", ip: "10.0.0.66", logonType: 10, logonId: "0x99", timestamp: "2026-08-22 03:14:00" }], localCount: 0 },
    failed: [],
    privileged: [{ user: "mallory", remote: true, ip: "10.0.0.66", logonId: "0x99", timestamp: "2026-08-22 03:14:00" }],
  },
});

check("mismo hecho, mismo riesgo: SSH y RDP con cuenta admin coinciden", () => {
  // La incoherencia que esto corrige: el protocolo de acceso decidía el nivel.
  const porSsh = fromSecurityEvents(rawDesdePs(EVIDENCIA_PS));
  const porRdp = fromSecurityEvents(rawIntruso());
  const altoSsh = porSsh.filter((x) => x.severity === "high");
  const altoRdp = porRdp.filter((x) => x.severity === "high");
  assert.strictEqual(altoSsh.length, 1);
  assert.strictEqual(altoRdp.length, 1);
  assert.strictEqual(altoSsh[0].severity, altoRdp[0].severity);
  // Y los dos elevan el riesgo global igual (isActionable: info no eleva).
  const sSsh = summarize(porSsh.map((x) => Object.assign({ scope: "host" }, x)));
  const sRdp = summarize(porRdp.map((x) => Object.assign({ scope: "host" }, x)));
  assert.strictEqual(sSsh.maxSeverity, "high");
  assert.strictEqual(sRdp.maxSeverity, "high");
  assert.ok(sSsh.actionable.total >= 1 && sRdp.actionable.total >= 1);
});

check("ningún texto del 4672 dice que la sesión estuviera elevada", () => {
  const raw = rawIntruso();
  const textos = [
    ...fromSecurityEvents(raw).flatMap((f) => [f.title, f.evidence, f.fix || ""]),
    ...buildEventList(raw).events.map((e) => e.detail || ""),
    ...fromSecurityEvents(rawDesdePs(EVIDENCIA_PS)).map((f) => f.evidence),
  ];
  const sospechoso = textos.filter((t) => /sesión (con privilegios|obtuvo|elevada|administrativa)/i.test(t));
  assert.deepStrictEqual(sospechoso, []);
  // Y los que sí hablan del 4672 dicen de qué hablan: de la cuenta.
  const del4672 = textos.filter((t) => /4672/.test(t));
  assert.ok(del4672.length >= 3);
  for (const t of del4672) assert.ok(/cuenta/i.test(t), t);
});

check("4672 remoto SIN acceso SSH → sigue saliendo, y con severidad alta", () => {
  const f = fromSecurityEvents(rawIntruso());
  const priv = f.filter((x) => x.id === "HOST-SEC-WIN-PRIV-001");
  assert.strictEqual(priv.length, 1);
  assert.strictEqual(priv[0].severity, SECURITY_EVENT_RULES.SSH_ACCEPTED_ROOT);
  assert.strictEqual(priv[0].severity, "high");
  assert.strictEqual(byId(f, "HOST-SEC-WIN-RDP").length, 1);
  const tipos = buildEventList(rawIntruso()).events.map((e) => e.type);
  assert.deepStrictEqual(tipos, ["logon-remote", "logon-privileged"]);
});

check("ventana de 10 s: 8 s colapsa, 25 s no (son dos accesos distintos)", () => {
  const cerca = rawIntruso();
  cerca.ssh.accepted = [{ user: "mallory", ip: "10.0.0.66", method: "password", timestamp: "2026-08-22 03:14:08" }];
  assert.deepStrictEqual(buildEventList(cerca).events.map((e) => e.type), ["ssh-accepted"]);

  const lejos = rawIntruso();
  lejos.ssh.accepted = [{ user: "mallory", ip: "10.0.0.66", method: "password", timestamp: "2026-08-22 03:14:25" }];
  assert.deepStrictEqual(
    buildEventList(lejos).events.map((e) => e.type).sort(),
    ["logon-privileged", "logon-remote", "ssh-accepted"]
  );
});

check("IP distinta → no se colapsa aunque coincidan usuario y hora", () => {
  const raw = rawIntruso();
  raw.ssh.accepted = [{ user: "mallory", ip: "172.16.0.5", method: "password", timestamp: "2026-08-22 03:14:03" }];
  assert.strictEqual(buildEventList(raw).events.length, 3);
});

check("otro usuario → no se colapsa", () => {
  const raw = rawIntruso();
  raw.ssh.accepted = [{ user: "bob", ip: "10.0.0.66", method: "password", timestamp: "2026-08-22 03:14:03" }];
  assert.strictEqual(buildEventList(raw).events.length, 3);
});

check("fallidos: 4625 y el intento SSH del mismo hecho cuentan una vez", () => {
  const raw = rawIntruso();
  raw.windows.logons.remote = [];
  raw.windows.privileged = [];
  raw.windows.failed = [
    { user: "mallory", ip: "10.0.0.66", logonType: 3, timestamp: "2026-08-22 03:20:00" },
    { user: "mallory", ip: "10.0.0.66", logonType: 3, timestamp: "2026-08-22 03:20:30" },
  ];
  raw.ssh.failed = [{ user: "mallory", ip: "10.0.0.66", timestamp: "2026-08-22 03:20:04" }];
  const tipos = buildEventList(raw).events.map((e) => e.type).sort();
  assert.deepStrictEqual(tipos, ["logon-failed", "ssh-failed"]);   // 3 eventos → 2
  const f = fromSecurityEvents(raw);
  // El 4625 emparejado no vuelve a contar en el agregado de fuerza bruta.
  assert.ok(/^1 inicio\(s\)/.test(byId(f, "HOST-SEC-WINF")[0].title));
  assert.ok(/^1 intento\(s\)/.test(byId(f, "HOST-SEC-SSHF")[0].title));
});

check("IPv4 mapeada en IPv6 (::ffff:) se reconoce como la misma IP", () => {
  const raw = rawIntruso();
  raw.ssh.accepted = [{ user: "mallory", ip: "::ffff:10.0.0.66", method: "password", timestamp: "2026-08-22 03:14:03" }];
  assert.deepStrictEqual(buildEventList(raw).events.map((e) => e.type), ["ssh-accepted"]);
});

check("sin hora usable no se colapsa por usuario a secas (ante la duda, fila de más)", () => {
  const raw = rawIntruso();
  raw.windows.logons.remote[0].timestamp = null;
  raw.windows.logons.remote[0].ip = null;
  raw.ssh.accepted = [{ user: "mallory", ip: "10.0.0.66", method: "password", timestamp: "2026-08-22 03:14:03" }];
  assert.strictEqual(buildEventList(raw).events.filter((e) => e.type === "logon-remote").length, 1);
});

check("Linux/macOS: sin canal Security la correlación no toca nada", () => {
  const out = buildEventList({
    windowHours: 24, platform: "linux", sources: ["journalctl"], partial: [],
    ssh: {
      accepted: [{ user: "juanan", ip: "192.168.1.2", method: "publickey", timestamp: "2026-07-07 10:00:00" }],
      failed: [],
    },
    sudo: { ok: [], failed: [] }, sessions: [],
  });
  assert.strictEqual(out.events.length, 1);
  assert.strictEqual(out.events[0].detail, "Login SSH correcto (publickey)");
  assert.ok(!("privileged" in out.events[0]));
});


// ── 7. Invocación de PowerShell: guardarraíl del límite de línea de comandos ─
//
// Regresión real: el script se pasaba con -EncodedCommand, o sea entero dentro
// de la línea de comandos, que Windows limita a 8191 caracteres. UTF-16LE +
// base64 lo multiplica por ~2,67. El script creció con los últimos cambios y
// cruzó el umbral: 3109 caracteres → 8292 de base64, 101 de más. Dejó de
// ejecutarse ENTERO, y con él se perdían a la vez el canal Security y el de
// OpenSSH, así que no salía ni un evento SSH. Silencioso: nada avisó.
//
// Con -File el límite no aplica. Este test deja constancia de los números y
// falla si alguien devuelve la invocación a la línea de comandos.
console.log("invocación de PowerShell (límite de 8191 caracteres):");

const WIN_CMDLINE_LIMIT = 8191;
const SRC_SECURITY_EVENTS = path.join(__dirname, "..", "..", "nodes", "audit-host", "modules", "security-events.js");

check("el script NO cabría en una línea de comandos, y por eso va por -File", () => {
  const script = buildWinEventsScript(24);
  const b64 = Buffer.from(script, "utf16le").toString("base64");
  const margen = WIN_CMDLINE_LIMIT - b64.length;
  console.log(
    `      script ${script.length} car · base64 ${b64.length} car · límite ${WIN_CMDLINE_LIMIT}` +
    ` · margen ${margen >= 0 ? "+" : ""}${margen}`
  );

  // La invocación real, tal cual está escrita en el módulo. Se busca la línea
  // que construye el comando (no los comentarios, que sí nombran la opción
  // abandonada a propósito para que conste por qué).
  const src = fs.readFileSync(SRC_SECURITY_EVENTS, "utf8");
  const invocacion = src.split("\n").filter((l) => l.includes("${psCmd}"));
  assert.strictEqual(invocacion.length, 1, "debería haber UNA sola invocación de PowerShell");

  const porLineaDeComandos = /-EncodedCommand|-Command\b/.test(invocacion[0]);
  if (porLineaDeComandos && b64.length > WIN_CMDLINE_LIMIT) {
    assert.fail(
      `La invocación vuelve a meter el script en la línea de comandos y no cabe: ` +
      `${b64.length} caracteres de base64 contra un límite de ${WIN_CMDLINE_LIMIT}. ` +
      `Windows no ejecutará NADA y se perderán los dos canales a la vez.`
    );
  }
  assert.ok(!porLineaDeComandos, "el script no puede viajar por la línea de comandos");
  assert.ok(/-File "/.test(invocacion[0]), "el script se pasa por fichero, con la ruta entrecomillada");
  // Los flags que ya estaban siguen estando: sin perfil, no interactivo, sin
  // política de ejecución que bloquee un .ps1 recién escrito.
  for (const flag of ["-NoProfile", "-NonInteractive", "-ExecutionPolicy Bypass"]) {
    assert.ok(invocacion[0].includes(flag), `falta ${flag}`);
  }
});

check("el script sigue siendo ASCII puro (si deja de serlo, el BOM es lo que salva)", () => {
  const script = buildWinEventsScript(24);
  const noAscii = [...script].filter((c) => c.charCodeAt(0) > 127);
  assert.deepStrictEqual(noAscii, []);
});

// ── 8. Fichero temporal: se borra SIEMPRE ───────────────────────────────────
console.log("withTempFile (lib/utils.js):");

const asyncChecks = [];
function checkAsync(name, fn) {
  asyncChecks.push([name, fn]);
}

checkAsync("camino feliz: existe durante, borrado después", async () => {
  let visto = null;
  const devuelto = await withTempFile("$x = 1", { prefix: "lcaudit-test-", ext: ".ps1" }, async (f) => {
    visto = f;
    assert.ok(fs.existsSync(f));
    return "resultado";
  });
  assert.strictEqual(devuelto, "resultado");
  assert.strictEqual(fs.existsSync(visto), false);
});

checkAsync("la función lanza: el error sube Y el temporal se borra", async () => {
  let visto = null;
  await assert.rejects(
    () => withTempFile("$x = 1", { prefix: "lcaudit-test-", ext: ".ps1" }, async (f) => {
      visto = f;
      throw new Error("boom");
    }),
    /boom/
  );
  assert.ok(visto);
  assert.strictEqual(fs.existsSync(visto), false);
});

checkAsync("timeout real del proceso hijo: el temporal se borra igual", async () => {
  // Proceso que no termina, matado por el timeout de execCommand. Es el camino
  // que más importa: si el borrado dependiera del final feliz, cada auditoría
  // que expirase dejaría un .ps1 en %TEMP%.
  let visto = null;
  await assert.rejects(
    () => withTempFile("$x = 1", { prefix: "lcaudit-test-", ext: ".ps1" }, async (f) => {
      visto = f;
      return execCommand(`"${process.execPath}" -e "setTimeout(function(){}, 5000)"`, 300);
    })
  );
  assert.ok(visto);
  assert.strictEqual(fs.existsSync(visto), false);
});

checkAsync("nombre aleatorio y no reutilizado", async () => {
  const nombres = [];
  for (let i = 0; i < 5; i++) {
    await withTempFile("x", { prefix: "lcaudit-test-", ext: ".ps1" }, async (f) => {
      nombres.push(path.basename(f));
      assert.strictEqual(path.dirname(f), os.tmpdir());
    });
  }
  assert.strictEqual(new Set(nombres).size, 5);
  for (const n of nombres) assert.ok(/^lcaudit-test-[0-9a-f]{24}\.ps1$/.test(n), n);
});

checkAsync("BOM de UTF-8 al principio cuando se pide", async () => {
  await withTempFile("$x = 1", { prefix: "lcaudit-test-", ext: ".ps1", bom: true }, async (f) => {
    const buf = fs.readFileSync(f);
    assert.deepStrictEqual([...buf.slice(0, 3)], [0xef, 0xbb, 0xbf]);
    assert.strictEqual(fs.readFileSync(f, "utf8").replace(/^﻿/, ""), "$x = 1");
  });
  // Sin bom: ni un byte de más.
  await withTempFile("$x = 1", { prefix: "lcaudit-test-", ext: ".ps1" }, async (f) => {
    assert.strictEqual(fs.readFileSync(f, "utf8"), "$x = 1");
  });
});

checkAsync("no escribe sobre una ruta que ya exista (O_EXCL contra enlaces)", async () => {
  // No se puede forzar la colisión con el nombre aleatorio, así que se comprueba
  // la propiedad directamente: escribir con flag 'wx' sobre algo existente falla
  // en vez de seguir el enlace y machacar el destino.
  const cebo = path.join(os.tmpdir(), `lcaudit-test-cebo-${Date.now()}.ps1`);
  fs.writeFileSync(cebo, "original");
  try {
    await assert.rejects(
      () => fs.promises.writeFile(cebo, "suplantado", { encoding: "utf8", mode: 0o600, flag: "wx" }),
      /EEXIST/
    );
    assert.strictEqual(fs.readFileSync(cebo, "utf8"), "original");
  } finally {
    fs.rmSync(cebo, { force: true });
  }
});

checkAsync("no deja restos: ningún lcaudit-winevents-*.ps1 en tmp", async () => {
  const restos = fs.readdirSync(os.tmpdir()).filter((f) => /^lcaudit-(winevents|test)-.*\.ps1$/.test(f));
  assert.deepStrictEqual(restos, []);
});


(async () => {
  for (const [name, fn] of asyncChecks) {
    await fn();
    passed++;
    console.log(`  ✓ ${name}`);
  }
  console.log(`\n${passed} comprobaciones OK`);
})().catch((err) => {
  console.error(err);
  process.exit(1);
});

