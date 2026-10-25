"use strict";

// Qué proceso tiene abierto cada puerto (lsof, netstat, tasklist). Si falla, el puerto sale sin enriquecer.

const { ejecutar, existeComando } = require("../../../lib/executor");

const ENRICH_TIMEOUT_MS = 5000;

// Salida de `lsof -i TCP:<port> -n -P -sTCP:LISTEN`: cabecera y procesos debajo.
function leerLsof(stdout) {
  const lines = stdout.trim().split("\n").filter(Boolean);
  if (lines.length < 2) return { pid: null, process: null, binds: [] };

  const parts = lines[1].trim().split(/\s+/);
  const processName = parts[0] || null;
  let pid;
  if (parts[1]) {
    pid = parseInt(parts[1], 10);
  } else {
    pid = null;
  }

  // La dirección de escucha separa lo solo-local de lo expuesto; puede haber varias (IPv4 e IPv6).
  const binds = [];
  for (const line of lines.slice(1)) {
    const m = line.match(/(\S+):(?:\d+|\w+)\s+\(LISTEN\)/);
    if (m && !binds.includes(m[1])) binds.push(m[1]);
  }

  let idProceso;
  if (isNaN(pid)) {
    idProceso = null;
  } else {
    idProceso = pid;
  }
  return {
    pid:     idProceso,
    process: processName,
    binds,
  };
}

// Loopback tal como lo escriben lsof y netstat: localhost, 127.x, [::1].
function escuchaEnLoopback(addr) {
  const a = String(addr || "").replace(/^\[|\]$/g, "").toLowerCase();
  return a === "localhost" || a === "::1" || /^127\./.test(a);
}

// netstat -ano en Windows: "  TCP  0.0.0.0:80  0.0.0.0:0  LISTENING  1234".
function leerPidNetstat(stdout, port) {
  const portStr = `:${port}`;
  for (const line of stdout.split("\n")) {
    const upper = line.toUpperCase();
    if (!upper.includes(portStr) || !upper.includes("LISTENING")) continue;
    const parts = line.trim().split(/\s+/);
    const pid = parseInt(parts[parts.length - 1], 10);
    if (isNaN(pid)) {
      return null;
    } else {
      return pid;
    }
  }
  return null;
}

// Direcciones de las líneas LISTENING, sin el :puerto.
function leerEscuchasNetstat(stdout, port) {
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
function leerTasklist(stdout) {
  const lines = stdout.trim().split("\n").filter(Boolean);
  if (lines.length < 2) return null;
  const firstField = lines[1].split(",")[0];
  if (firstField) {
    return firstField.replace(/"/g, "").trim() || null;
  } else {
    return null;
  }
}

// macOS y Linux, con lsof.
async function completarUnix(port) {
  try {
    const stdout = await ejecutar(
      `lsof -i TCP:${port} -n -P -sTCP:LISTEN`,
      ENRICH_TIMEOUT_MS
    );
    const { pid, process: procName, binds } = leerLsof(stdout);
    if (!pid && !procName) return {};
    let enlace;
    let soloLocal;
    if (binds.length > 0) {
      enlace = binds.join(", ");
      soloLocal = binds.every(escuchaEnLoopback);
    } else {
      enlace = undefined;
      soloLocal = undefined;
    }
    return {
      pid:       pid      ?? undefined,
      process:   procName ?? undefined,
      // Sin datos de bind queda undefined: no se afirma lo que no se sabe.
      bind:      enlace,
      localOnly: soloLocal,
    };
  } catch (_) {
    return {};
  }
}

// Windows: netstat para el PID y tasklist para el nombre.
async function completarWindows(port) {
  try {
    const netstatOut = await ejecutar(
      `netstat -ano | findstr :${port}`,
      ENRICH_TIMEOUT_MS
    );
    const pid = leerPidNetstat(netstatOut, port);
    if (!pid) return {};

    const binds = leerEscuchasNetstat(netstatOut, port);

    const taskOut = await ejecutar(
      `tasklist /FI "PID eq ${pid}" /FO CSV`,
      ENRICH_TIMEOUT_MS
    );
    const procName = leerTasklist(taskOut);

    let enlace;
    let soloLocal;
    if (binds.length > 0) {
      enlace = binds.join(", ");
      soloLocal = binds.every(escuchaEnLoopback);
    } else {
      enlace = undefined;
      soloLocal = undefined;
    }
    return {
      pid,
      process:   procName ?? undefined,
      bind:      enlace,
      localOnly: soloLocal,
    };
  } catch (_) {
    return {};
  }
}

// Cortafuegos presente y activo, sin sudo. Nunca lanza: si no se puede consultar, active es null y va el error.
async function detectarFirewall(platform) {
  const plat = platform || process.platform;
  const FW_TIMEOUT_MS = 4000;

  // Algunas órdenes salen con error al estar apagado ("not running", "inactive"): esa salida sí es un dato.
  async function consultar(name, cmd, leer) {
    let out;
    try {
      out = await ejecutar(cmd, FW_TIMEOUT_MS);
    } catch (err) {
      // firewalld avisa de "not running" por stderr.
      const active = leer(`${err.stdout || ""}\n${err.stderr || ""}`, true);
      if (active !== null) return { name, active };
      return { name, active: null, error: String((err.stderr || err.message || "sin detalle")).trim().slice(0, 200) };
    }
    const active = leer(String(out), false);
    if (active === null) {
      return { name, active: null, error: "respuesta no reconocida" };
    } else {
      return { name, active };
    }
  }

  try {
    if (plat === "linux") {
      if (await existeComando("ufw")) {
        return await consultar("ufw", "grep -i '^ENABLED' /etc/ufw/ufw.conf",
          (s) => {
            if (/ENABLED\s*=\s*"?yes/i.test(s)) {
              return true;
            } else if (/ENABLED\s*=\s*"?no/i.test(s)) {
              return false;
            } else {
              return null;
            }
          });
      }
      if (await existeComando("firewall-cmd")) {
        return await consultar("firewalld", "firewall-cmd --state",
          (s) => {
            if (/not running/i.test(s)) {
              return false;
            } else if (/running/i.test(s)) {
              return true;
            } else {
              return null;
            }
          });
      }
      if (await existeComando("nft")) {
        return await consultar("nftables", "systemctl is-active nftables",
          (s) => {
            if (s.trim() === "active") {
              return true;
            } else if (/^(inactive|failed|unknown|activating|deactivating)$/.test(s.trim())) {
              return false;
            } else {
              return null;
            }
          });
      }
      return { name: null, active: false };
    }

    if (plat === "darwin") {
      return await consultar("alf", "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate",
        (s) => {
          if (/enabled/i.test(s)) {
            return true;
          } else if (/disabled/i.test(s)) {
            return false;
          } else {
            return null;
          }
        });
    }

    if (plat === "win32") {
      return await consultar("windows", "netsh advfirewall show currentprofile state",
        (s, conError) => {
          if (/\bON\b/i.test(s) || /activad/i.test(s)) {
            return true;
          } else if (!conError && s.trim()) {
            return false;
          } else {
            return null;
          }
        });
    }
  } catch (err) {
    return { name: null, active: null, error: String((err && err.message) || err).slice(0, 200) };
  }

  return { name: null, active: false };
}

// En paralelo con allSettled: el puerto que falle se devuelve sin enriquecer.
async function completarPuertos(openPorts) {
  if (!Array.isArray(openPorts) || openPorts.length === 0) return [];

  let enrich;
  if (process.platform === "win32") {
    enrich = completarWindows;
  } else {
    enrich = completarUnix;
  }

  const results = await Promise.allSettled(
    openPorts.map((p) => enrich(p.port))
  );

  return openPorts.map((p, i) => {
    let enrichment;
    if (results[i].status === "fulfilled") {
      enrichment = results[i].value;
    } else {
      enrichment = {};
    }
    return { ...p, ...enrichment };
  });
}

module.exports = { completarPuertos, detectarFirewall };
