"use strict";

/** Inventario de software instalado. Cada plataforma tiene su fuente y ninguna es obligatoria.
 *  Que una fuente no llegue a mirar no es un inventario vacío: sale como { skipped, kind, reason },
 *  el mismo contrato que lynis.js y trivy-fs.js, que es el que audit-host.js sabe ramificar. */

const { execCommand, commandExists } = require("../../../lib/executor");

const BREW_TIMEOUT_MS     = 15000;
const PROFILER_TIMEOUT_MS = 30000;
const DPKG_TIMEOUT_MS     = 15000;
const RPM_TIMEOUT_MS      = 15000;
const WMIC_TIMEOUT_MS     = 30000;

/** Mismo criterio que lynis.js: child_process mata por timeout con SIGTERM y marca killed.
 *  Un timeout se arregla reintentando, un error no: por eso son kinds distintos. */
function isTimeout(err) {
  return Boolean(err && (err.killed || err.signal === "SIGTERM"));
}

/** Skip a partir de un fallo de exec. `what` va en primera persona del inventario, no el comando:
 *  el comando entra como detalle reproducible, no como el mensaje. */
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

// Sin Homebrew el inventario se queda en las apps del sistema. No es un fallo: aquí una lista
// vacía sí significa "no hay paquetes de brew", no "no se pudo mirar". Distinto es que brew esté
// instalado y no responda (timeout, error): entonces sí hay software que se ha quedado sin listar.
// El kind 'not-installed' es lo que separa "ausente" de "caído", y mergeDarwin() lo lee.
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

  // El parseo va aparte del exec a propósito: "el comando no se pudo ejecutar" y "el comando
  // respondió algo que no se entiende" son dos fallos distintos y el usuario hace cosas distintas.
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

// Sin comprobar que dpkg-query existe: eso lo decide el despacho de getSwInventory(), que es
// quien puede responder 'unsupported' cuando no hay ningún gestor. Ver la nota de allí.
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

// Igual que fromDpkg: la existencia de rpm la comprueba el despacho, no esta función.
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
  // wmic está deprecado y no viene en Windows 11 24H2 ni posteriores: ausente es el caso esperable,
  // y sin esta comprobación salía como un error de ejecución cualquiera.
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

/** Una entrada por nombre y orden alfabético, como siempre. */
function dedupeAndSort(pkgs) {
  const map = new Map();
  for (const pkg of pkgs) map.set(pkg.name.toLowerCase(), pkg);
  return Array.from(map.values()).sort((a, b) => a.name.localeCompare(b.name));
}

/** Skip que no deja agujero: la fuente no está en este equipo, así que tampoco hay software suyo
 *  que se haya quedado sin listar. Es otra cosa que "está y no se ha podido leer". */
function isAbsentSource(result) {
  return isSkip(result) && result.kind === "not-installed";
}

/**
 * macOS suma dos fuentes. Que una esté ausente no deja hueco; que una caiga, sí, y entonces el
 * inventario sigue saliendo con `partial` diciendo qué falta y por qué.
 */
function mergeDarwin(brew, apps) {
  // Homebrew ausente no resta nada: system_profiler sigue dando el inventario completo del equipo.
  const brewFailed = isSkip(brew) && !isAbsentSource(brew);
  // system_profiler es nativo de macOS: no hay comprobación de existencia y nunca sale ausente.
  const appsFailed = isSkip(apps);

  if (brewFailed && appsFailed) {
    return {
      skipped: true,
      // Dos motivos distintos no se resumen en uno: si no coinciden, el kind honesto es 'error'.
      kind: brew.kind === apps.kind ? brew.kind : "error",
      reason: `${brew.reason} ${apps.reason}`,
    };
  }

  // Brew ausente y system_profiler caído: no queda ninguna fuente. El estado lo pone la que falló,
  // que es la única de las dos que representa algo que no se pudo mirar.
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

  // Homebrew ausente y system_profiler bien: inventario completo, array plano y sin envolver.
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

  // Fuente única: su skip es directamente el del módulo, sin envolver.
  if (platform === "win32") {
    return fromWmic();
  }

  // En Linux la comprobación de existencia vive AQUÍ y solo aquí. No la metas dentro de fromDpkg()
  // ni de fromRpm(): duplicada, un sistema sin gestor podría salir como 'not-installed' por una
  // función y como 'unsupported' por el despacho, y solo el segundo describe ese sistema.
  // (fromBrew y fromWmic sí llevan la suya: allí no está duplicada, es la única.)
  const hasDpkg = await commandExists("dpkg-query");
  if (hasDpkg) return fromDpkg();

  const hasRpm = await commandExists("rpm");
  if (hasRpm) return fromRpm();

  return {
    skipped: true,
    kind: "unsupported",
    reason:
      "No se ha encontrado un gestor de paquetes reconocido en este sistema (se han buscado " +
      "dpkg-query y rpm), así que no se ha podido inventariar el software instalado.",
  };
}

module.exports = { getSwInventory };
