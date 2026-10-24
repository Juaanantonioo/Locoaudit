"use strict";

// Qué proceso tiene abierto cada puerto (lsof, netstat, tasklist). Si falla, el puerto sale sin enriquecer.

const { execCommand, commandExists } = require("../../../lib/executor");

const ENRICH_TIMEOUT_MS = 5000;

// Salida de `lsof -i TCP:<port> -n -P -sTCP:LISTEN`: cabecera y procesos debajo.
function parseLsof(stdout) {
  const lines = stdout.trim().split("\n").filter(Boolean);
  if (lines.length < 2) return { pid: null, process: null, binds: [] };

  const parts = lines[1].trim().split(/\s+/);
  const processName = parts[0] || null;
  const pid = parts[1] ? parseInt(parts[1], 10) : null;

  // La dirección de escucha separa lo solo-local de lo expuesto; puede haber varias (IPv4 e IPv6).
  const binds = [];
  for (const line of lines.slice(1)) {
    const m = line.match(/(\S+):(?:\d+|\w+)\s+\(LISTEN\)/);
    if (m && !binds.includes(m[1])) binds.push(m[1]);
  }

  return {
    pid:     isNaN(pid) ? null : pid,
    process: processName,
    binds,
  };
}

// Loopback tal como lo escriben lsof y netstat: localhost, 127.x, [::1].
function isLoopbackBind(addr) {
  const a = String(addr || "").replace(/^\[|\]$/g, "").toLowerCase();
  return a === "localhost" || a === "::1" || /^127\./.test(a);
}

// netstat -ano en Windows: "  TCP  0.0.0.0:80  0.0.0.0:0  LISTENING  1234".
function parseNetstatPid(stdout, port) {
  const portStr = `:${port}`;
  for (const line of stdout.split("\n")) {
    const upper = line.toUpperCase();
    if (!upper.includes(portStr) || !upper.includes("LISTENING")) continue;
    const parts = line.trim().split(/\s+/);
    const pid = parseInt(parts[parts.length - 1], 10);
    return isNaN(pid) ? null : pid;
  }
  return null;
}

// Direcciones de las líneas LISTENING, sin el :puerto.
function parseNetstatBinds(stdout, port) {
  const portStr = `:${port}`;
  const binds = [];
  for (const line of stdout.split("\n")) {
    const upper = line.toUpperCase();
    if (!upper.includes("LISTENING")) continue;
    const parts = line.trim().split(/\s+/);
    const local = parts[1] || "";
    if (!local.endsWith(portStr)) continue;
    const addr = local.slice(0, -portStr.length);
    if (addr && !binds.includes(addr)) binds.push(addr);
  }
  return binds;
}

// tasklist en CSV: el nombre del proceso es el primer campo de la segunda línea.
function parseTasklist(stdout) {
  const lines = stdout.trim().split("\n").filter(Boolean);
  if (lines.length < 2) return null;
  const firstField = lines[1].split(",")[0];
  return firstField ? firstField.replace(/"/g, "").trim() || null : null;
}

// macOS y Linux, con lsof.
async function enrichUnix(port) {
  try {
    const stdout = await execCommand(
      `lsof -i TCP:${port} -n -P -sTCP:LISTEN`,
      ENRICH_TIMEOUT_MS
    );
    const { pid, process: procName, binds } = parseLsof(stdout);
    if (!pid && !procName) return {};
    return {
      pid:       pid      ?? undefined,
      process:   procName ?? undefined,
      // Sin datos de bind queda undefined: no se afirma lo que no se sabe.
      bind:      binds.length > 0 ? binds.join(", ") : undefined,
      localOnly: binds.length > 0 ? binds.every(isLoopbackBind) : undefined,
    };
  } catch (_) {
    return {};
  }
}

// Windows: netstat para el PID y tasklist para el nombre.
async function enrichWindows(port) {
  try {
    const netstatOut = await execCommand(
      `netstat -ano | findstr :${port}`,
      ENRICH_TIMEOUT_MS
    );
    const pid = parseNetstatPid(netstatOut, port);
    if (!pid) return {};

    const binds = parseNetstatBinds(netstatOut, port);

    const taskOut = await execCommand(
      `tasklist /FI "PID eq ${pid}" /FO CSV`,
      ENRICH_TIMEOUT_MS
    );
    const procName = parseTasklist(taskOut);

    return {
      pid,
      process:   procName ?? undefined,
      bind:      binds.length > 0 ? binds.join(", ") : undefined,
      localOnly: binds.length > 0 ? binds.every(isLoopbackBind) : undefined,
    };
  } catch (_) {
    return {};
  }
}

// Cortafuegos presente y activo, sin sudo. Nunca lanza: si no se puede consultar, active es null y va el error.
async function detectFirewall(platform) {
  const plat = platform || process.platform;
  const FW_TIMEOUT_MS = 4000;

  // Algunas órdenes salen con error al estar apagado ("not running", "inactive"): esa salida sí es un dato.
  async function consultar(name, cmd, leer) {
    let out;
    try {
      out = await execCommand(cmd, FW_TIMEOUT_MS);
    } catch (err) {
      // firewalld avisa de "not running" por stderr.
      const active = leer(`${err.stdout || ""}\n${err.stderr || ""}`, true);
      if (active !== null) return { name, active };
      return { name, active: null, error: String((err.stderr || err.message || "sin detalle")).trim().slice(0, 200) };
    }
    const active = leer(String(out), false);
    return active === null
      ? { name, active: null, error: "respuesta no reconocida" }
      : { name, active };
  }

  try {
    if (plat === "linux") {
      if (await commandExists("ufw")) {
        return await consultar("ufw", "grep -i '^ENABLED' /etc/ufw/ufw.conf",
          (s) => (/ENABLED\s*=\s*"?yes/i.test(s) ? true : /ENABLED\s*=\s*"?no/i.test(s) ? false : null));
      }
      if (await commandExists("firewall-cmd")) {
        return await consultar("firewalld", "firewall-cmd --state",
          (s) => (/not running/i.test(s) ? false : /running/i.test(s) ? true : null));
      }
      if (await commandExists("nft")) {
        return await consultar("nftables", "systemctl is-active nftables",
          (s) => (s.trim() === "active" ? true : /^(inactive|failed|unknown|activating|deactivating)$/.test(s.trim()) ? false : null));
      }
      return { name: null, active: false };
    }

    if (plat === "darwin") {
      return await consultar("alf", "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate",
        (s) => (/enabled/i.test(s) ? true : /disabled/i.test(s) ? false : null));
    }

    if (plat === "win32") {
      return await consultar("windows", "netsh advfirewall show currentprofile state",
        (s, conError) => (/\bON\b/i.test(s) || /activad/i.test(s) ? true
          : !conError && s.trim() ? false : null));
    }
  } catch (err) {
    return { name: null, active: null, error: String((err && err.message) || err).slice(0, 200) };
  }

  return { name: null, active: false };
}

// En paralelo con allSettled: el puerto que falle se devuelve sin enriquecer.
async function enrichPorts(openPorts) {
  if (!Array.isArray(openPorts) || openPorts.length === 0) return [];

  const enrich = process.platform === "win32" ? enrichWindows : enrichUnix;

  const results = await Promise.allSettled(
    openPorts.map((p) => enrich(p.port))
  );

  return openPorts.map((p, i) => {
    const enrichment = results[i].status === "fulfilled" ? results[i].value : {};
    return { ...p, ...enrichment };
  });
}

module.exports = { enrichPorts, detectFirewall };
