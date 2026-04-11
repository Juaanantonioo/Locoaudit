"use strict";

/**
 * sw-inventory.js — Inventario de software instalado, multiplataforma.
 *
 * macOS:   brew list --versions  (si Homebrew existe)
 *          + system_profiler SPApplicationsDataType -json
 * Linux:   dpkg-query (Debian/Ubuntu) o rpm (RHEL/Fedora/SUSE)
 * Windows: wmic product get name,version
 *
 * Exporta:
 *   getSwInventory() → Promise<Array<{ name: string, version: string, source: string }>>
 */

const { execCommand, commandExists } = require("../../../lib/executor");

// ── macOS ────────────────────────────────────────────────────────────────────

/**
 * Obtiene paquetes de Homebrew.
 * @returns {Promise<Array<{name, version, source}>>}
 */
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

/**
 * Obtiene aplicaciones de macOS vía system_profiler.
 * @returns {Promise<Array<{name, version, source}>>}
 */
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

// ── Linux ────────────────────────────────────────────────────────────────────

/**
 * Obtiene paquetes vía dpkg (Debian/Ubuntu).
 * @returns {Promise<Array<{name, version, source}>>}
 */
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

/**
 * Obtiene paquetes vía rpm (RHEL / Fedora / SUSE).
 * @returns {Promise<Array<{name, version, source}>>}
 */
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

// ── Windows ──────────────────────────────────────────────────────────────────

/**
 * Obtiene productos instalados vía wmic.
 * @returns {Promise<Array<{name, version, source}>>}
 */
async function fromWmic() {
  try {
    const stdout = await execCommand(
      "wmic product get name,version /format:csv",
      30000
    );
    // El CSV de wmic tiene una línea vacía al inicio y cabecera: Node,Name,Version
    return stdout
      .trim()
      .split("\n")
      .slice(1)              // saltar cabecera
      .filter(Boolean)
      .map((line) => {
        const parts = line.split(",");
        // formato: Node,Name,Version
        const name = (parts[1] || "").trim();
        const version = (parts[2] || "unknown").trim();
        return name ? { name, version, source: "wmic" } : null;
      })
      .filter(Boolean);
  } catch (_) {
    return [];
  }
}

// ── API pública ─────────────────────────────────────────────────────────────

/**
 * Recolecta el inventario de software instalado según la plataforma.
 * @returns {Promise<Array<{ name: string, version: string, source: string }>>}
 */
async function getSwInventory() {
  const platform = process.platform;

  if (platform === "darwin") {
    const [brew, apps] = await Promise.all([fromBrew(), fromSystemProfiler()]);
    // Deduplicar por nombre: brew tiene precedencia para versión
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

  // Linux: intentar dpkg primero, luego rpm
  const hasDpkg = await commandExists("dpkg-query");
  if (hasDpkg) return fromDpkg();

  const hasRpm = await commandExists("rpm");
  if (hasRpm) return fromRpm();

  return []; // sin gestor de paquetes conocido
}

module.exports = { getSwInventory };
