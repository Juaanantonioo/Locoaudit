"use strict";

/**
 * test-security-events-win32.js — Test manual de la rama Windows de
 * security-events: parsers puros + normalizador, con fixtures sintéticas.
 * NO ejecuta PowerShell: se puede lanzar desde cualquier SO.
 *
 *   node test/manual/test-security-events-win32.js
 *
 * Verificación adicional pendiente en la VM Windows (no automatizable aquí):
 *   - Node-RED sin admin  → finding HOST-SEC-WIN-PERM, sin crash
 *   - Node-RED como admin → eventos 4624/4625 reales
 *   - 2-3 logins fallidos provocados → agregado low (HOST-SEC-WINF-001)
 */

const assert = require("assert");
const {
  parseWinEventsJson,
  parseQueryUserLines,
  parseQwinstaLines,
  buildWinEventsScript,
  buildEventList,
} = require("../../nodes/audit-host/modules/security-events");
const { fromSecurityEvents } = require("../../lib/normalizer");
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
  assert.ok(/administrador/.test(perm[0].fix));
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

check("skipped → events: []", () => {
  const out = buildEventList({ skipped: true, reason: "x", windowHours: 12, platform: "win32" });
  assert.deepStrictEqual(out, { windowHours: 12, events: [], truncated: false });
});

console.log(`\n${passed} comprobaciones OK`);
