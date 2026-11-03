"use strict";

/** Inventario de software instalado. Una fuente que no llega a mirar sale como { skipped, kind, reason }, no como lista vacía. */

const { ejecutar, existeComando } = require("../../../lib/executor");

const BREW_TIMEOUT_MS     = 15000;
const PROFILER_TIMEOUT_MS = 30000;
const DPKG_TIMEOUT_MS     = 15000;
const RPM_TIMEOUT_MS      = 15000;
const WMIC_TIMEOUT_MS     = 30000;

/** Un timeout se arregla reintentando y un error no: por eso son kinds distintos. */
function esTimeout(err) {
  return Boolean(err && (err.killed || err.signal === "SIGTERM"));
}

/** Skip a partir de un fallo de exec; el comando va como detalle reproducible. */
function omisionPorError(err, cmd, what, timeoutMs) {
  if (esTimeout(err)) {
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
async function desdeBrew() {
  if (!(await existeComando("brew"))) {
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
    const stdout = await ejecutar(cmd, BREW_TIMEOUT_MS);
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
    return omisionPorError(err, cmd, "los paquetes de Homebrew", BREW_TIMEOUT_MS);
  }
}

async function desdeSystemProfiler() {
  const cmd = "system_profiler SPApplicationsDataType -json";
  let stdout;
  try {
    stdout = await ejecutar(cmd, PROFILER_TIMEOUT_MS);
  } catch (err) {
    return omisionPorError(err, cmd, "las aplicaciones instaladas del sistema", PROFILER_TIMEOUT_MS);
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

// La existencia de dpkg-query la comprueba inventarioSoftware().
async function desdeDpkg() {
  const cmd = "dpkg-query -W -f='${Package} ${Version}\\n'";
  try {
    const stdout = await ejecutar(cmd, DPKG_TIMEOUT_MS);
    return stdout
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        const [name, ...rest] = line.trim().split(/\s+/);
        return { name, version: rest.join(" ") || "unknown", source: "dpkg" };
      });
  } catch (err) {
    return omisionPorError(err, "dpkg-query -W", "los paquetes instalados con dpkg", DPKG_TIMEOUT_MS);
  }
}

// La existencia de rpm la comprueba inventarioSoftware().
async function desdeRpm() {
  const cmd = "rpm -qa --queryformat '%{NAME} %{VERSION}\\n'";
  try {
    const stdout = await ejecutar(cmd, RPM_TIMEOUT_MS);
    return stdout
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        const [name, ...rest] = line.trim().split(/\s+/);
        return { name, version: rest.join(" ") || "unknown", source: "rpm" };
      });
  } catch (err) {
    return omisionPorError(err, "rpm -qa", "los paquetes instalados con rpm", RPM_TIMEOUT_MS);
  }
}

async function desdeWmic() {
  // wmic ya no viene en Windows 11 24H2: ausente es lo esperable, no un error.
  if (!(await existeComando("wmic"))) {
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
    const stdout = await ejecutar(cmd, WMIC_TIMEOUT_MS);
    // El CSV de wmic abre con una línea vacía y la cabecera Node,Name,Version.
    const programas = stdout
      .trim()
      .split("\n")
      .slice(1)
      .filter(Boolean)
      .map((line) => {
        const parts = line.split(",");
        const name = (parts[1] || "").trim();
        const version = (parts[2] || "unknown").trim();
        if (name) {
          return { name, version, source: "wmic" };
        } else {
          return null;
        }
      })
      .filter(Boolean);
    // Vacío no es "ningún programa": wmic solo ve lo instalado con Windows Installer (MSI).
    if (programas.length === 0) {
      return {
        skipped: true,
        kind: "error",
        reason:
          "wmic no ha devuelto ningún programa. Solo lista el software instalado con Windows " +
          "Installer (MSI), así que una lista vacía no significa que no haya software instalado.",
      };
    }
    return programas;
  } catch (err) {
    return omisionPorError(err, cmd, "el software instalado", WMIC_TIMEOUT_MS);
  }
}

/** ¿Este resultado es un skip y no un inventario? */
function esOmision(result) {
  return Boolean(result && result.skipped);
}

/** Una entrada por nombre, en orden alfabético. */
function quitarDuplicadosYOrdenar(pkgs) {
  const map = new Map();
  for (const pkg of pkgs) map.set(pkg.name.toLowerCase(), pkg);
  return Array.from(map.values()).sort((a, b) => a.name.localeCompare(b.name));
}

/** ¿La fuente no está instalada? Entonces no queda software suyo sin listar. */
function fuenteAusente(result) {
  return esOmision(result) && result.kind === "not-installed";
}

/** macOS junta brew y system_profiler; si una cae, el inventario sale con `partial`. */
function unirMac(brew, apps) {
  const brewFailed = esOmision(brew) && !fuenteAusente(brew);
  // system_profiler es nativo: nunca sale como ausente.
  const appsFailed = esOmision(apps);

  if (brewFailed && appsFailed) {
    let tipo;
    if (brew.kind === apps.kind) {
      tipo = brew.kind;
    } else {
      tipo = "error";
    }
    return {
      skipped: true,
      // Si los motivos no coinciden, el kind es 'error'.
      kind: tipo,
      reason: `${brew.reason} ${apps.reason}`,
    };
  }

  // Brew ausente y system_profiler caído: no queda ninguna fuente.
  if (appsFailed && esOmision(brew)) {
    return { skipped: true, kind: apps.kind, reason: apps.reason };
  }

  if (brewFailed || appsFailed) {
    let failed;
    if (brewFailed) {
      failed = brew;
    } else {
      failed = apps;
    }
    let lista;
    let fuente;
    if (brewFailed) {
      lista = apps;
      fuente = "brew";
    } else {
      lista = brew;
      fuente = "system_profiler";
    }
    return {
      packages: quitarDuplicadosYOrdenar(lista),
      partial: true,
      partialSource: fuente,
      partialReason: failed.reason,
    };
  }

  // Brew ausente y system_profiler bien: inventario completo.
  if (esOmision(brew)) return quitarDuplicadosYOrdenar(apps);

  // brew va detrás en el spread para que su versión pise a la de system_profiler.
  return quitarDuplicadosYOrdenar([...apps, ...brew]);
}

async function inventarioSoftware() {
  const platform = process.platform;

  if (platform === "darwin") {
    const [brew, apps] = await Promise.all([desdeBrew(), desdeSystemProfiler()]);
    return unirMac(brew, apps);
  }

  if (platform === "win32") {
    return desdeWmic();
  }

  // En Linux la existencia del gestor se comprueba solo aquí, para que un sistema sin gestor salga 'unsupported'.
  const hasDpkg = await existeComando("dpkg-query");
  if (hasDpkg) return desdeDpkg();

  const hasRpm = await existeComando("rpm");
  if (hasRpm) return desdeRpm();

  return {
    skipped: true,
    kind: "unsupported",
    reason:
      "LoCoAudit solo sabe leer dpkg y rpm, y no ha encontrado ninguno de los dos. Este sistema " +
      "usa otro gestor de paquetes, así que no se ha podido inventariar el software instalado.",
  };
}

module.exports = { inventarioSoftware };
