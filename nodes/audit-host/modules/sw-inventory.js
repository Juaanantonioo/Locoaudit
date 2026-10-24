"use strict";

/** Inventario de software instalado. Una fuente que no llega a mirar sale como { skipped, kind, reason }, no como lista vacía. */

const { execCommand, commandExists } = require("../../../lib/executor");

const BREW_TIMEOUT_MS     = 15000;
const PROFILER_TIMEOUT_MS = 30000;
const DPKG_TIMEOUT_MS     = 15000;
const RPM_TIMEOUT_MS      = 15000;
const WMIC_TIMEOUT_MS     = 30000;

/** Un timeout se arregla reintentando y un error no: por eso son kinds distintos. */
function isTimeout(err) {
  return Boolean(err && (err.killed || err.signal === "SIGTERM"));
}

/** Skip a partir de un fallo de exec; el comando va como detalle reproducible. */
function execSkip(err, cmd, what, timeoutMs) {
  if (isTimeout(err)) {
    return {
      skipped: true,
      kind: "timeout",
      reason:
        `No se ha podido obtener ${what}: el comando \`${cmd}\` superó el límite de ` +
        `${timeoutMs / 1000} s sin terminar.`,
    };
  }
  return {
    skipped: true,
    kind: "error",
    reason:
      `No se ha podido obtener ${what}: el comando \`${cmd}\` falló ` +
      `(${(err && err.message) || "error desconocido"}).`,
  };
}

// Brew ausente ('not-installed') no es un fallo; brew instalado que no responde, sí.
async function fromBrew() {
  if (!(await commandExists("brew"))) {
    return {
      skipped: true,
      kind: "not-installed",
      reason:
        "Homebrew no está instalado en este equipo, así que no se han podido listar los paquetes " +
        "que gestiona.",
    };
  }
  const cmd = "brew list --versions";
  try {
    const stdout = await execCommand(cmd, BREW_TIMEOUT_MS);
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
  } catch (err) {
    return execSkip(err, cmd, "los paquetes de Homebrew", BREW_TIMEOUT_MS);
  }
}

async function fromSystemProfiler() {
  const cmd = "system_profiler SPApplicationsDataType -json";
  let stdout;
  try {
    stdout = await execCommand(cmd, PROFILER_TIMEOUT_MS);
  } catch (err) {
    return execSkip(err, cmd, "las aplicaciones instaladas del sistema", PROFILER_TIMEOUT_MS);
  }

  // Parseo aparte del exec: no ejecutarse y responder algo ilegible son fallos distintos.
  let data;
  try {
    data = JSON.parse(stdout);
  } catch (parseErr) {
    return {
      skipped: true,
      kind: "error",
      reason:
        `El comando \`${cmd}\` se ejecutó, pero su salida no es JSON válido, así que no se han ` +
        `podido leer las aplicaciones instaladas (${parseErr.message}).`,
    };
  }

  const apps = data?.SPApplicationsDataType || [];
  return apps
    .filter((a) => a._name)
    .map((a) => ({
      name: a._name,
      version: a.version || "unknown",
      source: "system_profiler",
    }));
}

// La existencia de dpkg-query la comprueba getSwInventory().
async function fromDpkg() {
  const cmd = "dpkg-query -W -f='${Package} ${Version}\\n'";
  try {
    const stdout = await execCommand(cmd, DPKG_TIMEOUT_MS);
    return stdout
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        const [name, ...rest] = line.trim().split(/\s+/);
        return { name, version: rest.join(" ") || "unknown", source: "dpkg" };
      });
  } catch (err) {
    return execSkip(err, "dpkg-query -W", "los paquetes instalados con dpkg", DPKG_TIMEOUT_MS);
  }
}

// La existencia de rpm la comprueba getSwInventory().
async function fromRpm() {
  const cmd = "rpm -qa --queryformat '%{NAME} %{VERSION}\\n'";
  try {
    const stdout = await execCommand(cmd, RPM_TIMEOUT_MS);
    return stdout
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        const [name, ...rest] = line.trim().split(/\s+/);
        return { name, version: rest.join(" ") || "unknown", source: "rpm" };
      });
  } catch (err) {
    return execSkip(err, "rpm -qa", "los paquetes instalados con rpm", RPM_TIMEOUT_MS);
  }
}

async function fromWmic() {
  // wmic ya no viene en Windows 11 24H2: ausente es lo esperable, no un error.
  if (!(await commandExists("wmic"))) {
    return {
      skipped: true,
      kind: "not-installed",
      reason:
        "No se ha encontrado el comando `wmic`. Windows 11 24H2 y posteriores ya no lo incluyen, " +
        "así que no se ha podido listar el software instalado.",
    };
  }
  const cmd = "wmic product get name,version /format:csv";
  try {
    const stdout = await execCommand(cmd, WMIC_TIMEOUT_MS);
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
  } catch (err) {
    return execSkip(err, cmd, "el software instalado", WMIC_TIMEOUT_MS);
  }
}

/** ¿Este resultado es un skip y no un inventario? */
function isSkip(result) {
  return Boolean(result && result.skipped);
}

/** Una entrada por nombre, en orden alfabético. */
function dedupeAndSort(pkgs) {
  const map = new Map();
  for (const pkg of pkgs) map.set(pkg.name.toLowerCase(), pkg);
  return Array.from(map.values()).sort((a, b) => a.name.localeCompare(b.name));
}

/** ¿La fuente no está instalada? Entonces no queda software suyo sin listar. */
function isAbsentSource(result) {
  return isSkip(result) && result.kind === "not-installed";
}

/** macOS junta brew y system_profiler; si una cae, el inventario sale con `partial`. */
function mergeDarwin(brew, apps) {
  const brewFailed = isSkip(brew) && !isAbsentSource(brew);
  // system_profiler es nativo: nunca sale como ausente.
  const appsFailed = isSkip(apps);

  if (brewFailed && appsFailed) {
    return {
      skipped: true,
      // Si los motivos no coinciden, el kind es 'error'.
      kind: brew.kind === apps.kind ? brew.kind : "error",
      reason: `${brew.reason} ${apps.reason}`,
    };
  }

  // Brew ausente y system_profiler caído: no queda ninguna fuente.
  if (appsFailed && isSkip(brew)) {
    return { skipped: true, kind: apps.kind, reason: apps.reason };
  }

  if (brewFailed || appsFailed) {
    const failed = brewFailed ? brew : apps;
    return {
      packages: dedupeAndSort(brewFailed ? apps : brew),
      partial: true,
      partialSource: brewFailed ? "brew" : "system_profiler",
      partialReason: failed.reason,
    };
  }

  // Brew ausente y system_profiler bien: inventario completo.
  if (isSkip(brew)) return dedupeAndSort(apps);

  // brew va detrás en el spread para que su versión pise a la de system_profiler.
  return dedupeAndSort([...apps, ...brew]);
}

async function getSwInventory() {
  const platform = process.platform;

  if (platform === "darwin") {
    const [brew, apps] = await Promise.all([fromBrew(), fromSystemProfiler()]);
    return mergeDarwin(brew, apps);
  }

  if (platform === "win32") {
    return fromWmic();
  }

  // En Linux la existencia del gestor se comprueba solo aquí, para que un sistema sin gestor salga 'unsupported'.
  const hasDpkg = await commandExists("dpkg-query");
  if (hasDpkg) return fromDpkg();

  const hasRpm = await commandExists("rpm");
  if (hasRpm) return fromRpm();

  return {
    skipped: true,
    kind: "unsupported",
    reason:
      "LoCoAudit solo sabe leer dpkg y rpm, y no ha encontrado ninguno de los dos. Este sistema " +
      "usa otro gestor de paquetes, así que no se ha podido inventariar el software instalado.",
  };
}

module.exports = { getSwInventory };
