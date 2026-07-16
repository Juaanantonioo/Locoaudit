"use strict";

/**
 * config-audit.js — Auditoría de configuración de seguridad de contenedores Docker.
 *
 * Analiza los contenedores activos buscando configuraciones inseguras frecuentes
 * usando exclusivamente comandos `docker inspect` (CLI, sin dependencias externas).
 *
 * ── Criterio de severidad aplicado ───────────────────────────────────────────
 *
 * "high"   — Configuraciones que suponen un riesgo directo de escalada de
 *            privilegios o exposición de credenciales:
 *
 *            · Contenedor ejecutándose como root: un proceso comprometido dentro
 *              del contenedor tiene UID 0, lo que facilita técnicas de escape
 *              de contenedor y acceso al host.
 *
 *            · Variables de entorno con datos sensibles: contraseñas, tokens y
 *              claves en variables de entorno son visibles para cualquier proceso
 *              dentro del contenedor y para quien tenga acceso a `docker inspect`.
 *              Además quedan registradas en el historial de capas de la imagen.
 *
 * "medium" — Configuraciones que amplían innecesariamente la superficie de ataque
 *            pero no implican compromiso inmediato:
 *
 *            · Puertos publicados en 0.0.0.0: el servicio es accesible desde
 *              cualquier interfaz de red, incluyendo las externas, cuando en la
 *              mayoría de casos bastaría con 127.0.0.1.
 *
 *            · Montaje del socket de Docker (/var/run/docker.sock): otorga al
 *              contenedor control total sobre el daemon Docker del host, lo que
 *              equivale en la práctica a privilegios de root en el host.  Solo
 *              justificado en herramientas de CI/CD muy controladas.
 *
 * Exporta:
 *   auditDockerConfig(dockerInfo) → Promise<Finding[]>
 */

const { execCommand }    = require("../../../lib/executor");
const { createFinding }  = require("../../../lib/finding-schema");

const INSPECT_TIMEOUT_MS = 8000;

// Palabras clave que indican variables de entorno con datos sensibles
const SENSITIVE_PATTERNS = ["PASSWORD", "SECRET", "KEY", "TOKEN", "PASS", "CREDENTIAL"];

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Ejecuta docker inspect sobre un contenedor y devuelve el valor del formato.
 * Si falla devuelve null silenciosamente.
 *
 * @param {string} id      ID o nombre del contenedor
 * @param {string} format  Plantilla Go para --format
 * @returns {Promise<string|null>}
 */
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

/**
 * Detecta variables de entorno con nombres sensibles en un JSON array de strings.
 * Formato esperado: ["VAR=value", "OTHER=val", ...]
 *
 * @param {string|null} envJson  Salida de docker inspect --format "{{json .Config.Env}}"
 * @returns {string[]}  Nombres de variables sensibles encontradas
 */
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

/**
 * Contador para IDs de finding con prefijo e índice correlativo por tipo.
 * @param {string} prefix  Ej: "IMG-CFG-001"
 * @param {number} n       Índice 0-based del contenedor
 * @returns {string}
 */
function findingId(base, n) {
  return `${base}-${String(n + 1).padStart(3, "0")}`;
}

// ── Auditoría de un contenedor ────────────────────────────────────────────────

/**
 * Inspecciona un único contenedor y devuelve todos sus findings de configuración.
 *
 * @param {{ id, name, ports }} container
 * @param {number} idx  Posición en el array de contenedores (para IDs)
 * @returns {Promise<Finding[]>}
 */
async function auditContainer(container, idx) {
  const findings = [];
  const name = container.name || container.id;

  // Inspecciones en paralelo para minimizar la latencia total
  const [userOut, envOut, bindsOut] = await Promise.all([
    inspect(container.id, "{{.Config.User}}"),
    inspect(container.id, "{{json .Config.Env}}"),
    inspect(container.id, "{{json .HostConfig.Binds}}"),
  ]);

  // ── HIGH: contenedor corriendo como root ──────────────────────────────────
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

  // ── HIGH: variables de entorno con datos sensibles ────────────────────────
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

  // ── MEDIUM: puertos publicados en todas las interfaces ────────────────────
  if (container.ports && container.ports.includes("0.0.0.0:")) {
    // El binding se corrige en el arranque del contenedor (docker run / Compose),
    // no con comandos del host. Por eso no se anexa el fix de proceso del host.
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

  // ── MEDIUM: montaje del socket de Docker ──────────────────────────────────
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

// ── API pública ───────────────────────────────────────────────────────────────

/**
 * Audita la configuración de seguridad de todos los contenedores Docker.
 * Si dockerInfo indica que Docker no está disponible devuelve array vacío.
 *
 * @param {{ skipped?: boolean, containers?: Array }} dockerInfo
 * @returns {Promise<Finding[]>}
 */
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
