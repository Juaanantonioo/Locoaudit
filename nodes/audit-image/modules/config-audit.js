"use strict";

/**
 * Configuraciones inseguras de los contenedores en marcha, todo con `docker inspect`.
 *
 * En "high" va lo que da escalada de privilegios o expone credenciales: correr como root, porque
 * un proceso comprometido tiene UID 0 y desde ahí se intenta el escape al host, y los secretos en
 * variables de entorno, visibles para cualquier proceso del contenedor, para quien pueda hacer
 * `docker inspect` y además grabados en el historial de capas de la imagen.
 *
 * En "medium", lo que amplía la superficie sin comprometer nada por sí solo: publicar en 0.0.0.0
 * cuando casi siempre bastaría 127.0.0.1, y montar /var/run/docker.sock, que da control del
 * daemon del host y equivale en la práctica a root fuera del contenedor.
 */

const { execCommand }    = require("../../../lib/executor");
const { createFinding }  = require("../../../lib/finding-schema");

const INSPECT_TIMEOUT_MS = 8000;

// Nombres de variable que delatan un secreto.
const SENSITIVE_PATTERNS = ["PASSWORD", "SECRET", "KEY", "TOKEN", "PASS", "CREDENTIAL"];

/** null si el inspect falla: un contenedor que se para a mitad de auditoría no rompe el resto. */
async function inspect(id, format) {
  try {
    const out = await execCommand(
      `docker inspect ${id} --format "${format}"`,
      INSPECT_TIMEOUT_MS
    );
    return out.trim();
  } catch (_) {
    return null;
  }
}

/** Sobre el ["VAR=value", …] que devuelve `docker inspect --format "{{json .Config.Env}}"`. */
function findSensitiveEnvVars(envJson) {
  if (!envJson) return [];
  let envList;
  try {
    envList = JSON.parse(envJson);
  } catch (_) {
    return [];
  }
  if (!Array.isArray(envList)) return [];

  return envList
    .map((entry) => entry.split("=")[0].toUpperCase())
    .filter((name) => SENSITIVE_PATTERNS.some((pat) => name.includes(pat)));
}

/** IDs correlativos por tipo de hallazgo: IMG-CFG-001, IMG-CFG-002… */
function findingId(base, n) {
  return `${base}-${String(n + 1).padStart(3, "0")}`;
}

/** Los cuatro chequeos sobre un contenedor. El idx solo sirve para numerar los IDs. */
async function auditContainer(container, idx) {
  const findings = [];
  const name = container.name || container.id;

  // En paralelo: son cuatro procesos `docker inspect` independientes.
  const [userOut, envOut, bindsOut] = await Promise.all([
    inspect(container.id, "{{.Config.User}}"),
    inspect(container.id, "{{json .Config.Env}}"),
    inspect(container.id, "{{json .HostConfig.Binds}}"),
  ]);

  const user = userOut ?? "";
  if (user === "" || user === "root" || user === "0") {
    findings.push(createFinding({
      id:       findingId("IMG-CFG-001", idx),
      title:    `Contenedor ${name} ejecutándose como root`,
      severity: "high",
      evidence: `Usuario del contenedor: ${user === "" ? "(no definido — default root)" : user}`,
      fix:      "Añadir USER <usuario> no root en el Dockerfile.",
      category: "image",
      source:   "native",
    }));
  }

  const sensitiveVars = findSensitiveEnvVars(envOut);
  if (sensitiveVars.length > 0) {
    findings.push(createFinding({
      id:       findingId("IMG-CFG-002", idx),
      title:    `Variables de entorno sensibles en ${name}: ${sensitiveVars.join(", ")}`,
      severity: "high",
      evidence: `Variables con nombres sensibles detectadas: ${sensitiveVars.join(", ")}`,
      fix:      "Usar Docker secrets o variables de entorno en tiempo de ejecución en lugar de valores en el Dockerfile o docker run -e.",
      category: "image",
      source:   "native",
    }));
  }

  if (container.ports && container.ports.includes("0.0.0.0:")) {
    // El binding se cambia al arrancar el contenedor, en `docker run` o en Compose, no con
    // comandos del host: por eso aquí no se anexa el fix de proceso.
    const portsFix =
      "Limitar el binding a 127.0.0.1 si el servicio es solo local: " +
      "-p 127.0.0.1:<puerto>:<puerto> en docker run, o el mapeo de puertos equivalente en Docker Compose.";
    findings.push(createFinding({
      id:       findingId("IMG-CFG-003", idx),
      title:    `Contenedor ${name} expone puertos en todas las interfaces`,
      severity: "medium",
      evidence: `Puertos publicados: ${container.ports}`,
      fix:      portsFix,
      category: "image",
      source:   "native",
    }));
  }

  let binds = [];
  try { binds = JSON.parse(bindsOut || "[]"); } catch (_) { /* ignorar */ }
  const hasSock = Array.isArray(binds) &&
    binds.some((b) => typeof b === "string" && b.includes("/var/run/docker.sock"));

  if (hasSock) {
    findings.push(createFinding({
      id:       findingId("IMG-CFG-004", idx),
      title:    `Contenedor ${name} monta el socket de Docker`,
      severity: "medium",
      evidence: `Bind mounts: ${binds.join(", ")}`,
      fix:      "Evitar montar docker.sock salvo en herramientas de CI/CD controladas. Equivale a dar privilegios de root en el host.",
      category: "image",
      source:   "native",
    }));
  }

  return findings;
}

/** Sin Docker devuelve el array vacío: quien avisa de su ausencia es el nodo, con un finding. */
async function auditDockerConfig(dockerInfo) {
  if (!dockerInfo || dockerInfo.skipped) return [];

  const containers = dockerInfo.containers || [];
  if (containers.length === 0) return [];

  const results = await Promise.allSettled(
    containers.map((c, i) => auditContainer(c, i))
  );

  return results.flatMap((r) => (r.status === "fulfilled" ? r.value : []));
}

module.exports = { auditDockerConfig };
