"use strict";

/**
 * Quién tiene abierto cada puerto, con lsof, netstat y tasklist. "El 3306 está abierto" es una
 * alerta; "lo tiene abierto mysqld", o peor, "python3", ya es algo que se puede accionar. Si el
 * comando falla, el puerto sale sin enriquecer: este módulo nunca tumba al nodo.
 */

const { execCommand, commandExists } = require("../../../lib/executor");

const ENRICH_TIMEOUT_MS = 5000;

/** Salida de `lsof -i TCP:<port> -n -P -sTCP:LISTEN`: cabecera y, debajo, los procesos. */
function parseLsof(stdout) {
  const lines = stdout.trim().split("\n").filter(Boolean);
  if (lines.length < 2) return { pid: null, process: null, binds: [] };

  const parts = lines[1].trim().split(/\s+/);
  const processName = parts[0] || null;
  const pid = parts[1] ? parseInt(parts[1], 10) : null;

  // La columna NAME de cada LISTEN es "dirección:puerto (LISTEN)", y esa dirección separa el
  // servicio solo-local del expuesto. Un mismo servicio puede escuchar en varias, IPv4 e IPv6.
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

/** Loopback, en todas las formas que escriben lsof y netstat: localhost, 127.0.0.1, [::1]. */
function isLoopbackBind(addr) {
  const a = String(addr || "").replace(/^\[|\]$/g, "").toLowerCase();
  return a === "localhost" || a === "::1" || /^127\./.test(a);
}

/** netstat -ano en Windows: "  TCP  0.0.0.0:80  0.0.0.0:0  LISTENING  1234". */
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

/** Las direcciones de las líneas LISTENING, sin el sufijo :puerto. */
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

/** tasklist en CSV: la fila de datos va debajo de la cabecera y abre con el nombre del proceso. */
function parseTasklist(stdout) {
  const lines = stdout.trim().split("\n").filter(Boolean);
  if (lines.length < 2) return null;
  const firstField = lines[1].split(",")[0];
  return firstField ? firstField.replace(/"/g, "").trim() || null : null;
}

/** macOS y Linux, con lsof. */
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
      // localOnly solo si todas las direcciones son loopback. Sin datos de bind queda
      // undefined: no se sabe, no se afirma.
      bind:      binds.length > 0 ? binds.join(", ") : undefined,
      localOnly: binds.length > 0 ? binds.every(isLoopbackBind) : undefined,
    };
  } catch (_) {
    return {};
  }
}

/** Windows, con netstat para el PID y tasklist para el nombre. */
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

/**
 * Qué cortafuegos hay y si está activo, todo sin sudo: ufw se lee de su fichero de configuración,
 * firewalld y nftables preguntando por su estado, y macOS y Windows con su comando propio. Nunca
 * lanza: ante cualquier fallo, { name: null, active: false }.
 */
async function detectFirewall(platform) {
  const plat = platform || process.platform;
  const FW_TIMEOUT_MS = 4000;

  try {
    if (plat === "linux") {
      if (await commandExists("ufw")) {
        try {
          const conf = await execCommand("grep -i '^ENABLED' /etc/ufw/ufw.conf", FW_TIMEOUT_MS);
          return { name: "ufw", active: /yes/i.test(conf) };
        } catch (_) {
          return { name: "ufw", active: false };
        }
      }
      if (await commandExists("firewall-cmd")) {
        try {
          const st = await execCommand("firewall-cmd --state", FW_TIMEOUT_MS);
          return { name: "firewalld", active: /running/i.test(st) };
        } catch (_) {
          return { name: "firewalld", active: false };
        }
      }
      if (await commandExists("nft")) {
        try {
          const st = await execCommand("systemctl is-active nftables", FW_TIMEOUT_MS);
          return { name: "nftables", active: st.trim() === "active" };
        } catch (_) {
          return { name: "nftables", active: false };
        }
      }
      return { name: null, active: false };
    }

    if (plat === "darwin") {
      try {
        const st = await execCommand(
          "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate",
          FW_TIMEOUT_MS
        );
        return { name: "alf", active: /enabled/i.test(st) };
      } catch (_) {
        return { name: "alf", active: false };
      }
    }

    if (plat === "win32") {
      try {
        const st = await execCommand("netsh advfirewall show currentprofile state", FW_TIMEOUT_MS);
        return { name: "windows", active: /\bON\b/i.test(st) || /activad/i.test(st) };
      } catch (_) {
        return { name: "windows", active: false };
      }
    }
  } catch (_) { /* nunca bloquear la auditoría por esto */ }

  return { name: null, active: false };
}

// ── API pública ───────────────────────────────────────────────────────────────

/**
 * Enriquece un array de puertos abiertos con información de proceso.
 * Los puertos se procesan en paralelo con Promise.allSettled; si un puerto
 * falla, el resto continúa y ese puerto se devuelve sin enriquecer.
 *
 * @param {PortResult[]} openPorts  Array de puertos devuelto por runNmap()
 * @returns {Promise<EnrichedPort[]>}
 */
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
