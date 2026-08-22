"use strict";

/**
 * audit-image.js — Nodo audit-image para Node-RED.
 *
 * Orquesta docker-api.js, config-audit.js y cve-checker.js y emite:
 *   msg.payload = {
 *     findings: Finding[],
 *     summary,
 *     source: "audit-image",
 *     auditType: "image",
 *     host: { hostname, platform },
 *     scanMeta: {
 *       modulesRun: string[],
 *       imagesFound: number,
 *       containersFound: number,
 *       containersRunning: number,
 *       durationMs: number
 *     },
 *     raw: { docker, configFindings, trivy },
 *     timestamp: string (ISO 8601)
 *   }
 *
 * Configuración (config):
 *   enableConfig  boolean  (default true)  — activa config-audit.js
 *   enableTrivy   boolean  (default true)  — activa cve-checker.js
 *
 * Si Docker no está disponible el nodo termina limpiamente con un único
 * finding informativo (IMG-DOCKER-OFF) en lugar de propagar un error.
 */

const os = require("os");
const { getDockerInfo }      = require("./modules/docker-api");
const { auditDockerConfig }  = require("./modules/config-audit");
const { runTrivyImage }      = require("./modules/cve-checker");
const { normalizeImage }     = require("../../lib/normalizer");
const { summarize }          = require("../../lib/severity-map");
const { createFinding }      = require("../../lib/finding-schema");
const { commandExists }      = require("../../lib/executor");

/**
 * Si la referencia es una URL de Docker Hub, intenta extraer el nombre de
 * imagen utilizable por `trivy image`. Si no se puede parsear con confianza,
 * devuelve la referencia tal cual (extra de UX, nunca rompe el flujo).
 *
 *   https://hub.docker.com/_/nginx          → "nginx"
 *   https://hub.docker.com/r/usuario/repo    → "usuario/repo"
 *
 * @param {string} ref
 * @returns {string}
 */
function parseImageRef(ref) {
  if (!/^https?:\/\/hub\.docker\.com\//i.test(ref)) return ref;
  let m = ref.match(/hub\.docker\.com\/r\/([^/?#]+\/[^/?#]+)/i);
  if (m) return m[1];
  m = ref.match(/hub\.docker\.com\/_\/([^/?#]+)/i);
  if (m) return m[1];
  return ref;
}

/**
 * Resume un error crudo de Trivy en un mensaje legible para el dashboard.
 * El error completo se conserva en raw.trivy.failed para depuración.
 *
 * @param {string} err  stderr/mensaje crudo de Trivy
 * @returns {string}
 */
function summarizeScanError(err) {
  const e = String(err || "");
  // Causas de infraestructura (marcadas por cve-checker) primero: son las que el
  // mensaje genérico "revisa el nombre" enmascaraba erróneamente.
  if (/^MAXBUFFER:|maxBuffer/i.test(e)) {
    return "El informe del análisis es demasiado grande para procesarlo (imagen muy voluminosa con cientos de paquetes). " +
           "El límite de memoria ya se ha ampliado; si persiste, escanea la imagen directamente con 'trivy image <ref>'.";
  }
  // Lock de la caché de trivy. Va ANTES de la rama de timeout a propósito: el
  // texto crudo de trivy contiene la palabra "timeout" y caería ahí, aconsejando
  // subir un límite de tiempo que no tiene nada que ver con la causa.
  if (/^LOCK:|cache may be in use by another process|unable to initialize (fs )?cache/i.test(e)) {
    return "Trivy no pudo escanear esta imagen porque otro análisis estaba usando su caché al mismo tiempo " +
           "(Trivy solo admite un escaneo a la vez). LoCoAudit ya escanea las imágenes de una en una; " +
           "si ves este aviso, comprueba que no haya otro 'trivy' en marcha (otra auditoría de LoCoAudit " +
           "en paralelo o una terminal) y repite el escaneo.";
  }
  if (/^TIMEOUT:|context deadline exceeded|ETIMEDOUT|timed out/i.test(e)) {
    return "El análisis excedió el tiempo límite (imagen grande: la descarga puede tardar varios minutos). " +
           "Aumenta el 'Timeout por imagen' en la configuración del nodo.";
  }
  if (/no space left on device|disk quota exceeded/i.test(e)) {
    return "Sin espacio en disco para descargar la imagen. Libera espacio con 'docker image prune' y reintenta.";
  }
  // El rate limit se comprueba antes que auth: su mensaje también contiene "denied".
  if (/TOOMANYREQUESTS|toomanyrequests|429|rate limit/i.test(e)) {
    return "Límite de descargas del registro alcanzado (rate limit de Docker Hub). Inicia sesión con 'docker login' o reintenta más tarde.";
  }
  // Autenticación ANTES que "no encontrada": cuando la imagen no está en local
  // y el registro exige credenciales, el error de Trivy contiene AMBOS patrones
  // ("No such image" del daemon local + "401 Unauthorized" del registro remoto)
  // y la causa real es la falta de credenciales, no el nombre.
  if (/unauthorized|authentication required|access.*denied|denied:/i.test(e) || /\b401\b/.test(e)) {
    return "La imagen está en un registro privado que requiere autenticación ('docker login <registro>'). " +
           "LoCoAudit soporta imágenes públicas; los registros privados quedan como trabajo futuro.";
  }
  if (/MANIFEST_UNKNOWN|manifest unknown|No such image|unable to find the specified image|NAME_UNKNOWN|not found/i.test(e)) {
    return "Imagen o tag no encontrado (ni en local ni en el registro). Revisa el nombre y el tag.";
  }
  if (/no such host|dial tcp|network is unreachable|i\/o timeout|connection refused|TLS handshake/i.test(e)) {
    return "No se pudo contactar con el registro (problema de red o sin conexión).";
  }
  // Red de seguridad para causas aún sin catalogar: se quita el prefijo de log
  // de trivy ("2026-…\tFATAL\tFatal error\trun error: "), 40 caracteres de ruido
  // que empujaban la causa real fuera del recorte — con el error del lock, el
  // corte a 200 caía justo en "…cache may be in use" y se comía " by another
  // process: timeout", que era justamente la explicación.
  const clean = e
    .replace(/^\S+\s+FATAL\s+Fatal error\s+/m, "")
    .replace(/^run error:\s*/, "");
  const firstLine = clean.split("\n").map((s) => s.trim()).filter(Boolean)[0] || "Fallo al escanear con Trivy";
  return firstLine.slice(0, 400);
}

/**
 * Convierte la lista de imágenes que no se pudieron escanear en findings.
 *
 * Vive a nivel de módulo porque lo necesitan LOS DOS modos: el modo "specific"
 * ya lo hacía, pero el modo "local" descartaba `trivy.failed` en silencio — una
 * imagen que fallaba desaparecía sin finding, sin aviso y sin contar. Un fallo
 * mudo es peor que cualquier mensaje truncado.
 *
 * @param {Array<{ ref: string, error: string }>} failed
 * @returns {Finding[]}
 */
function buildScanErrorFindings(failed) {
  return (failed || []).map((fa, i) =>
    createFinding({
      id:       `IMG-SCAN-ERR-${String(i + 1).padStart(3, "0")}`,
      title:    `No se pudo escanear la imagen «${fa.ref || "desconocida"}»`,
      severity: "info",
      evidence: summarizeScanError(fa.error),
      // La evidencia ya explica la causa concreta y qué hacer; el fix
      // remite a ella para no contradecirla con un consejo genérico.
      fix:      "Consulta el detalle del error arriba: indica la causa (tiempo de espera, tamaño, red, credenciales, caché ocupada o nombre) y cómo resolverla.",
      category: "image",
      source:   "trivy",
      image:    fa.ref || null,
    })
  );
}

/**
 * Construye el payload de salida del nodo a partir de los findings y metadatos.
 * @param {Array} findings
 * @param {object} scanMeta
 * @param {object} raw
 * @returns {object}
 */
function buildImagePayload(findings, scanMeta, raw, scannedImages) {
  return {
    findings,
    summary:   summarize(findings),
    source:    "audit-image",
    auditType: "image",
    host: { hostname: os.hostname(), platform: process.platform },
    scanMeta,
    // Lista de imágenes escaneadas derivada del informe de Trivy (idéntica en
    // local y remoto). La tarjeta del dashboard cae a este campo cuando no hay
    // metadatos de `docker images` (caso imagen remota).
    scannedImages: Array.isArray(scannedImages) ? scannedImages : [],
    raw,
    timestamp: new Date().toISOString(),
  };
}

module.exports = function (RED) {
  function AuditImageNode(config) {
    RED.nodes.createNode(this, config);
    const node = this;

    // Referencia OPCIONAL al nodo de configuración del asistente IA (tipo "llm-config").
    // Solo habilita crear/seleccionar el config desde el editor; el chat lo sirve el
    // endpoint /locoaudit/chat. No interviene en la lógica de auditoría.
    node.llmConfig = config.llmConfig ? RED.nodes.getNode(config.llmConfig) : null;

    node.on("input", async function (msg, send, done) {
      const scanMode     = config.scanMode || "local";
      const enableConfig = config.enableConfig !== false;
      const enableTrivy  = config.enableTrivy  !== false;
      // Timeout por imagen (segundos → ms). Configurable: las imágenes grandes
      // (modelos de IA de varios GB) necesitan más tiempo para descargarse antes
      // de escanearse. Rango 30–1800 s, por defecto 300 s (5 min).
      const imageTimeout = Math.min(1800, Math.max(30, parseInt(config.imageTimeout, 10) || 300)) * 1000;

      const startTime = Date.now();

      try {
        // ── Modo "specific": escanear una o varias imágenes (locales o de un registro remoto) ──
        // Se admite una lista separada por comas: "nginx:latest, mysql:latest, debian:12".
        // trivy image resuelve solo: si la imagen no está en local la descarga del
        // registro. NO requiere el daemon Docker (cae a remote si no hay daemon).
        if (scanMode === "specific") {
          node.status({ fill: "blue", shape: "dot", text: "Auditando imágenes..." });

          // Resolver la referencia (texto fijo o tomado de msg)
          let rawRef = "";
          try {
            rawRef = (RED.util.evaluateNodeProperty(
              config.imageRef, config.imageRefType || "str", node, msg
            ) || "").toString();
          } catch (_) { rawRef = ""; }

          // Separar por comas → lista de referencias, normalizando URLs de Docker Hub
          const refs = rawRef
            .split(",")
            .map((s) => parseImageRef(s.trim()))
            .filter(Boolean);

          // Sin referencias: finding informativo y salida limpia (no peta el flujo)
          if (refs.length === 0) {
            const findings = [
              createFinding({
                id:       "IMG-IMAGE-NONE",
                title:    "No se indicó ninguna imagen a escanear",
                severity: "info",
                evidence: "scanMode='specific' pero la referencia de imagen está vacía",
                // Sin ": " en el texto: el dashboard lo leería como "etiqueta:
                // comando" y ofrecería copiar "nginx:latest) o proporciónala…".
                // Esto no es un comando, es una instrucción de configuración.
                fix:      "Indica una imagen en el nodo, por ejemplo nginx:latest, o proporciónala vía msg.",
                category: "image",
                source:   "native",
              }),
            ];
            msg.payload = buildImagePayload(
              findings,
              { modulesRun: [], imagesFound: 0, containersFound: 0, containersRunning: 0, durationMs: Date.now() - startTime },
              { docker: null, configFindings: [], trivy: null }
            );
            node.status({ fill: "grey", shape: "dot", text: "Sin imagen indicada" });
            send(msg);
            done();
            return;
          }

          // trivy es la única herramienta requerida en este modo
          const trivyAvailable = await commandExists("trivy");
          if (!trivyAvailable) {
            const findings = [
              createFinding({
                id:       "IMG-TRIVY-OFF",
                title:    "Trivy no disponible",
                severity: "info",
                evidence: "trivy not installed",
                fix:      "Instalar Trivy: https://trivy.dev/latest/getting-started/installation/",
                category: "image",
                source:   "native",
              }),
            ];
            msg.payload = buildImagePayload(
              findings,
              { modulesRun: [], imagesFound: 0, containersFound: 0, containersRunning: 0, durationMs: Date.now() - startTime },
              { docker: null, configFindings: [], trivy: null }
            );
            node.status({ fill: "grey", shape: "dot", text: "Trivy no disponible" });
            send(msg);
            done();
            return;
          }

          // Escaneo: un target por referencia. Objeto sintético → imageRef() en
          // cve-checker devuelve la ref tal cual (repository vacío ⇒ usa el campo id).
          const targets = refs.map((r) => ({ id: r, repository: "", tag: "" }));
          const trivy   = await runTrivyImage(targets, imageTimeout);

          // CVEs de las imágenes que SÍ se escanearon (vacío si todas fallaron)
          const findings = (trivy && !trivy.skipped)
            ? normalizeImage(trivy, "trivy")
            : [];

          // Una imagen que no existe / no se detecta / falla → finding explicativo
          // por cada una (no se cae el flujo, y se reporta cuál y por qué).
          const failed = (trivy && trivy.failed) || [];
          findings.push(...buildScanErrorFindings(failed));

          const scannedImages = (trivy && trivy.scannedImages) || [];

          msg.payload = buildImagePayload(
            findings,
            { modulesRun: ["trivy-image"], imagesFound: scannedImages.length, containersFound: 0, containersRunning: 0, durationMs: Date.now() - startTime },
            { docker: null, configFindings: [], trivy },
            scannedImages
          );

          const maxSev = msg.payload.summary.maxSeverity || "info";
          const statusColor =
            maxSev === "critical" || maxSev === "high" ? "red"
            : maxSev === "medium"                      ? "yellow"
            :                                            "green";
          const statusTxt = failed.length
            ? `${scannedImages.length} ok · ${failed.length} fallo(s) · riesgo: ${maxSev}`
            : `${scannedImages.length} imagen(es) · riesgo: ${maxSev}`;
          node.status({ fill: statusColor, shape: "dot", text: statusTxt });

          send(msg);
          done();
          return;
        }

        // ── Modo "local" (comportamiento original): todas las imágenes locales ──
        node.status({ fill: "blue", shape: "dot", text: "Auditando imágenes..." });

        // 1. Recoger información de Docker
        const docker = await getDockerInfo();

        if (docker.skipped) {
          // Docker no disponible: finding informativo y salida limpia
          const findings = [
            createFinding({
              id:       "IMG-DOCKER-OFF",
              title:    "Docker no disponible",
              severity: "info",
              evidence: docker.reason || "docker not available",
              fix:      "Instalar Docker Desktop desde https://www.docker.com/products/docker-desktop",
              category: "image",
              source:   "native",
            }),
          ];
          const summary    = summarize(findings);
          const durationMs = Date.now() - startTime;

          msg.payload = {
            findings,
            summary,
            source:    "audit-image",
            auditType: "image",
            host: { hostname: os.hostname(), platform: process.platform },
            scanMeta: {
              modulesRun:        [],
              imagesFound:       0,
              containersFound:   0,
              containersRunning: 0,
              durationMs,
            },
            raw: { docker, configFindings: [], trivy: null },
            timestamp: new Date().toISOString(),
          };

          node.status({ fill: "grey", shape: "dot", text: "Docker no disponible" });
          send(msg);
          done();
          return;
        }

        // 2. Auditorías en paralelo
        const [configResult, trivyResult] = await Promise.allSettled([
          enableConfig ? auditDockerConfig(docker)         : Promise.resolve([]),
          enableTrivy  ? runTrivyImage(docker.images, imageTimeout) : Promise.resolve({ skipped: true, reason: "disabled" }),
        ]);

        const configFindings = configResult.status === "fulfilled" ? configResult.value : [];
        const trivy          = trivyResult.status  === "fulfilled" ? trivyResult.value  : null;

        if (configResult.status === "rejected") {
          node.warn(`[audit-image] config-audit falló: ${configResult.reason}`);
        }
        if (trivyResult.status === "rejected") {
          node.warn(`[audit-image] cve-checker falló: ${trivyResult.reason}`);
        }

        // 3. Normalizar findings
        const trivyFindings = (trivy && !trivy.skipped)
          ? normalizeImage(trivy, "trivy")
          : [];

        // Imágenes que no se pudieron escanear. Se leen de `trivy.failed` SIEMPRE,
        // también cuando el resultado viene con skipped:true — runTrivyImage
        // devuelve `{ skipped: true, reason: "all image scans failed", failed }`
        // en el peor caso (ninguna imagen escaneada), y ese es justo el caso que
        // no puede quedarse mudo.
        const scanErrors = buildScanErrorFindings(trivy && trivy.failed);

        const findings   = [...configFindings, ...trivyFindings, ...scanErrors];
        const summary    = summarize(findings);
        const durationMs = Date.now() - startTime;

        // 4. Construir payload
        const modulesRun = [
          "docker-api",
          enableConfig                       && "config-audit",
          enableTrivy && trivy && !trivy.skipped && "trivy-image",
        ].filter(Boolean);

        msg.payload = {
          findings,
          summary,
          source:    "audit-image",
          auditType: "image",
          host: { hostname: os.hostname(), platform: process.platform },
          scanMeta: {
            modulesRun,
            imagesFound:       docker.images.length,
            containersFound:   docker.containers.length,
            containersRunning: docker.containers.filter((c) => c.running).length,
            durationMs,
          },
          // Imágenes escaneadas según Trivy; el dashboard usa raw.docker.images
          // en local (sin cambios) y cae a este campo en remoto.
          scannedImages: (trivy && trivy.scannedImages) || [],
          raw: { docker, configFindings, trivy },
          timestamp: new Date().toISOString(),
        };

        // 5. Status del nodo según severidad máxima
        const maxSev = summary.maxSeverity || "info";
        const statusColor =
          maxSev === "critical" || maxSev === "high" ? "red"
          : maxSev === "medium"                      ? "yellow"
          :                                            "green";

        node.status({
          fill:  statusColor,
          shape: "dot",
          text:  `${docker.images.length} imágenes · ${docker.containers.length} contenedores` +
                 (scanErrors.length ? ` · ${scanErrors.length} fallo(s)` : "") +
                 ` · riesgo: ${maxSev}`,
        });

        send(msg);
        done();
      } catch (err) {
        node.status({ fill: "red", shape: "ring", text: "Error" });
        done(err);
      }
    });
  }

  RED.nodes.registerType("audit-image", AuditImageNode);
};
