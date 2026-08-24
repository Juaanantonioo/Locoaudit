"use strict";

/**
 * Nodo audit-image, con dos modos: el local recorre lo que haya en el daemon, y el específico
 * escanea las referencias que le den, estén o no en el equipo. Sin Docker el nodo no propaga el
 * error: sale con un IMG-DOCKER-OFF informativo.
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
 * La URL de Docker Hub que el usuario pega en el navegador, convertida en algo que entienda
 * `trivy image`: hub.docker.com/_/nginx → nginx, hub.docker.com/r/user/repo → user/repo. Si no
 * se puede parsear con confianza devuelve la referencia tal cual, sin romper nada.
 */
function parseImageRef(ref) {
  if (!/^https?:\/\/hub\.docker\.com\//i.test(ref)) return ref;
  let m = ref.match(/hub\.docker\.com\/r\/([^/?#]+\/[^/?#]+)/i);
  if (m) return m[1];
  m = ref.match(/hub\.docker\.com\/_\/([^/?#]+)/i);
  if (m) return m[1];
  return ref;
}

/** El error crudo de Trivy, legible. El original se guarda entero en raw.trivy.failed. */
function summarizeScanError(err) {
  const e = String(err || "");
  // Las causas de infraestructura van primero: el mensaje genérico "revisa el nombre" las tapaba.
  if (/^MAXBUFFER:|maxBuffer/i.test(e)) {
    return "El informe del análisis es demasiado grande para procesarlo (imagen muy voluminosa con cientos de paquetes). " +
           "El límite de memoria ya se ha ampliado; si persiste, escanea la imagen directamente con 'trivy image <ref>'.";
  }
  // El lock de la caché va antes que el timeout a propósito: su texto crudo lleva la palabra
  // "timeout" y caería ahí, aconsejando subir un límite que no tiene nada que ver.
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
  // El rate limit, antes que auth: su mensaje también contiene "denied".
  if (/TOOMANYREQUESTS|toomanyrequests|429|rate limit/i.test(e)) {
    return "Límite de descargas del registro alcanzado (rate limit de Docker Hub). Inicia sesión con 'docker login' o reintenta más tarde.";
  }
  // Y la autenticación antes que "no encontrada": con la imagen ausente en local y un registro
  // que pide credenciales, el error trae los dos patrones a la vez, el "No such image" del
  // daemon y el 401 del registro, y la causa real son las credenciales.
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
  // Para las causas sin catalogar, quitando el prefijo de log de trivy ("2026-…\tFATAL\tFatal
  // error\trun error: "): son 40 caracteres de ruido que empujaban la causa fuera del recorte.
  // Con el error del lock, el corte caía en "…cache may be in use" y se comía la explicación.
  const clean = e
    .replace(/^\S+\s+FATAL\s+Fatal error\s+/m, "")
    .replace(/^run error:\s*/, "");
  const firstLine = clean.split("\n").map((s) => s.trim()).filter(Boolean)[0] || "Fallo al escanear con Trivy";
  return firstLine.slice(0, 400);
}

/**
 * A nivel de módulo porque lo usan los dos modos: el específico ya lo hacía, pero el local tiraba
 * `trivy.failed` en silencio y una imagen que fallaba desaparecía sin finding y sin contarse.
 */
function buildScanErrorFindings(failed) {
  return (failed || []).map((fa, i) =>
    createFinding({
      id:       `IMG-SCAN-ERR-${String(i + 1).padStart(3, "0")}`,
      title:    `No se pudo escanear la imagen «${fa.ref || "desconocida"}»`,
      severity: "info",
      evidence: summarizeScanError(fa.error),
      // La causa concreta ya está en la evidencia: el fix remite a ella en vez de dar un
      // consejo genérico que la contradiga.
      fix:      "Consulta el detalle del error arriba: indica la causa (tiempo de espera, tamaño, red, credenciales, caché ocupada o nombre) y cómo resolverla.",
      category: "image",
      source:   "trivy",
      image:    fa.ref || null,
    })
  );
}

function buildImagePayload(findings, scanMeta, raw, scannedImages) {
  return {
    findings,
    summary:   summarize(findings),
    source:    "audit-image",
    auditType: "image",
    host: { hostname: os.hostname(), platform: process.platform },
    scanMeta,
    // Sale del informe de Trivy, igual en local que en remoto: es a lo que cae la tarjeta del
    // dashboard cuando no hay metadatos de `docker images`, o sea con una imagen remota.
    scannedImages: Array.isArray(scannedImages) ? scannedImages : [],
    raw,
    timestamp: new Date().toISOString(),
  };
}

module.exports = function (RED) {
  function AuditImageNode(config) {
    RED.nodes.createNode(this, config);
    const node = this;

    // Solo para poder elegir el config desde el editor: el chat lo sirve /locoaudit/chat.
    node.llmConfig = config.llmConfig ? RED.nodes.getNode(config.llmConfig) : null;

    node.on("input", async function (msg, send, done) {
      const scanMode     = config.scanMode || "local";
      const enableConfig = config.enableConfig !== false;
      const enableTrivy  = config.enableTrivy  !== false;
      // Configurable porque una imagen de varios GB necesita descargarse antes de escanearse.
      const imageTimeout = Math.min(1800, Math.max(30, parseInt(config.imageTimeout, 10) || 300)) * 1000;

      const startTime = Date.now();

      try {
        // Modo específico: una lista separada por comas. `trivy image` se apaña solo, descarga
        // del registro lo que no esté en local, y no necesita el daemon de Docker.
        if (scanMode === "specific") {
          node.status({ fill: "blue", shape: "dot", text: "Auditando imágenes..." });

          // Texto fijo del nodo o valor tomado de msg.
          let rawRef = "";
          try {
            rawRef = (RED.util.evaluateNodeProperty(
              config.imageRef, config.imageRefType || "str", node, msg
            ) || "").toString();
          } catch (_) { rawRef = ""; }

          const refs = rawRef
            .split(",")
            .map((s) => parseImageRef(s.trim()))
            .filter(Boolean);

          if (refs.length === 0) {
            const findings = [
              createFinding({
                id:       "IMG-IMAGE-NONE",
                title:    "No se indicó ninguna imagen a escanear",
                severity: "info",
                evidence: "scanMode='specific' pero la referencia de imagen está vacía",
                // Sin ": " en el texto: el dashboard lo leería como "etiqueta: comando" y
                // ofrecería copiar media frase. Esto es una instrucción, no un comando.
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

          // La única herramienta que hace falta en este modo.
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

          // Un target por referencia, sintético: con repository vacío, imageRef() en cve-checker
          // devuelve el campo id tal cual.
          const targets = refs.map((r) => ({ id: r, repository: "", tag: "" }));
          const trivy   = await runTrivyImage(targets, imageTimeout);

          const findings = (trivy && !trivy.skipped)
            ? normalizeImage(trivy, "trivy")
            : [];

          // Un finding por imagen fallida, diciendo cuál y por qué: el flujo no se cae.
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

        // Modo local: todas las imágenes del daemon.
        node.status({ fill: "blue", shape: "dot", text: "Auditando imágenes..." });

        const docker = await getDockerInfo();

        if (docker.skipped) {
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

        const trivyFindings = (trivy && !trivy.skipped)
          ? normalizeImage(trivy, "trivy")
          : [];

        // `trivy.failed` se lee siempre, también con skipped:true: cuando no se escanea ni una
        // imagen, runTrivyImage devuelve justo eso, y ese es el caso que no puede quedarse mudo.
        const scanErrors = buildScanErrorFindings(trivy && trivy.failed);

        const findings   = [...configFindings, ...trivyFindings, ...scanErrors];
        const summary    = summarize(findings);
        const durationMs = Date.now() - startTime;

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
          // En local el dashboard usa raw.docker.images; en remoto cae a este campo.
          scannedImages: (trivy && trivy.scannedImages) || [],
          raw: { docker, configFindings, trivy },
          timestamp: new Date().toISOString(),
        };

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
