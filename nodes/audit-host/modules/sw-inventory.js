"use strict";

/** Inventario de software instalado. Cada plataforma tiene su fuente y ninguna es obligatoria. */

const { execCommand, commandExists } = require("../../../lib/executor");

// Sin Homebrew el inventario se queda en las apps del sistema. No es un fallo: aquí una lista
// vacía sí significa "no hay paquetes de brew", no "no se pudo mirar".
async function fromBrew() {
  if (!(await commandExists("brew"))) return [];
  try {
    const stdout = await execCommand("brew list --versions", 15000);
    return stdout
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        const parts = line.trim().split(/\s+/);
        return {
          name: parts[0] || line.trim(),
          version: parts[1] || "unknown",
          source: "brew",
        };
      });
  } catch (_) {
    return [];
  }
}

async function fromSystemProfiler() {
  try {
    const stdout = await execCommand(
      "system_profiler SPApplicationsDataType -json",
      30000
    );
    const data = JSON.parse(stdout);
    const apps = data?.SPApplicationsDataType || [];
    return apps
      .filter((a) => a._name)
      .map((a) => ({
        name: a._name,
        version: a.version || "unknown",
        source: "system_profiler",
      }));
  } catch (_) {
    return [];
  }
}

async function fromDpkg() {
  try {
    const stdout = await execCommand(
      "dpkg-query -W -f='${Package} ${Version}\\n'",
      15000
    );
    return stdout
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        const [name, ...rest] = line.trim().split(/\s+/);
        return { name, version: rest.join(" ") || "unknown", source: "dpkg" };
      });
  } catch (_) {
    return [];
  }
}

async function fromRpm() {
  try {
    const stdout = await execCommand(
      "rpm -qa --queryformat '%{NAME} %{VERSION}\\n'",
      15000
    );
    return stdout
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        const [name, ...rest] = line.trim().split(/\s+/);
        return { name, version: rest.join(" ") || "unknown", source: "rpm" };
      });
  } catch (_) {
    return [];
  }
}

async function fromWmic() {
  try {
    const stdout = await execCommand(
      "wmic product get name,version /format:csv",
      30000
    );
    // El CSV de wmic abre con una línea vacía y la cabecera Node,Name,Version.
    return stdout
      .trim()
      .split("\n")
      .slice(1)
      .filter(Boolean)
      .map((line) => {
        const parts = line.split(",");
        const name = (parts[1] || "").trim();
        const version = (parts[2] || "unknown").trim();
        return name ? { name, version, source: "wmic" } : null;
      })
      .filter(Boolean);
  } catch (_) {
    return [];
  }
}

async function getSwInventory() {
  const platform = process.platform;

  if (platform === "darwin") {
    const [brew, apps] = await Promise.all([fromBrew(), fromSystemProfiler()]);
    // brew va detrás en el spread para que su versión pise a la de system_profiler.
    const map = new Map();
    for (const pkg of [...apps, ...brew]) {
      map.set(pkg.name.toLowerCase(), pkg);
    }
    return Array.from(map.values()).sort((a, b) =>
      a.name.localeCompare(b.name)
    );
  }

  if (platform === "win32") {
    return fromWmic();
  }

  const hasDpkg = await commandExists("dpkg-query");
  if (hasDpkg) return fromDpkg();

  const hasRpm = await commandExists("rpm");
  if (hasRpm) return fromRpm();

  return []; // sin gestor de paquetes conocido
}

module.exports = { getSwInventory };
