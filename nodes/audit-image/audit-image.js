"use strict";

// Nodo audit-image. Modo local: imágenes del daemon. Modo específico: las referencias indicadas.
// Sin Docker o sin Trivy el nodo falla, como audit-host con Lynis: el error sale en Node-RED y no se envía nada al dashboard.

const os = require("os");
const { infoDocker }      = require("./modules/docker-api");
const { auditarConfigDocker }  = require("./modules/config-audit");
const { ejecutarTrivyImagen, referenciaImagen } = require("./modules/cve-checker");
const { normalizarImagen, resumenOmitidas } = require("../../lib/normalizer");
const { resumir }          = require("../../lib/severity-map");
const { crearHallazgo }      = require("../../lib/finding-schema");
const { existeComando }      = require("../../lib/executor");
const { sinResultados }     = require("../../lib/utils");

// URL de Docker Hub a referencia de trivy (hub.docker.com/_/nginx → nginx). Si no encaja, se devuelve tal cual.
function leerReferenciaImagen(ref) {
  if (!/^https?:\/\/hub\.docker\.com\//i.test(ref)) return ref;
  let m = ref.match(/hub\.docker\.com\/r\/([^/?#]+\/[^/?#]+)/i);
  if (m) return m[1];
  m = ref.match(/hub\.docker\.com\/_\/([^/?#]+)/i);
  if (m) return m[1];
  return ref;
}

// Error de Trivy en lenguaje claro; el original queda en raw.trivy.failed. El orden de las comprobaciones importa.
function resumirErrorEscaneo(err) {
  const e = String(err || "");
  if (/^INVALID_REF:/.test(e)) {
    return "La referencia no tiene la forma de una imagen (registro/repositorio:tag o @sha256:digest) y no se ha escaneado. " +
           "Revisa que no lleve espacios ni otros caracteres, por ejemplo nginx:latest.";
  }
  if (/^NO_OS:/.test(e)) {
    return "Trivy no ha reconocido el sistema operativo de la imagen ni ha encontrado paquetes que revisar, " +
           "así que no se ha podido comprobar si tiene vulnerabilidades. No significa que esté limpia. " +
           "Suele pasar con imágenes muy mínimas o con un sistema que Trivy no soporta.";
  }
  if (/^MAXBUFFER:|maxBuffer/i.test(e)) {
    return "El informe del análisis es demasiado grande para procesarlo (imagen muy voluminosa con cientos de paquetes). " +
           "El límite de memoria ya se ha ampliado; si persiste, escanea la imagen directamente con 'trivy image <ref>'.";
  }
  // Antes que el timeout: el error del lock también contiene "timeout".
  if (/^LOCK:|cache may be in use by another process|unable to initialize (fs )?cache/i.test(e)) {
    return "Trivy no pudo escanear esta imagen porque otro análisis estaba usando su caché al mismo tiempo " +
           "(Trivy solo admite un escaneo a la vez). LoCoAudit ya escanea las imágenes de una en una; " +
           "si ves este aviso, comprueba que no haya otro 'trivy' en marcha (otra auditoría de LoCoAudit " +
           "en paralelo o una terminal) y repite el escaneo.";
  }
  // Caché creada con sudo; su error dice "failed to download" y si no acabaría en el de red.
  const perm = e.match(/(\/\S*?\/trivy)\/[^\s:]*: permission denied/i);
  if (perm) {
    return `Trivy no puede escribir en su caché (${perm[1]}): pertenece a otro usuario, normalmente porque alguna vez ` +
           "se ejecutó Trivy con sudo. Devuélvela a tu usuario con 'sudo chown -R $(whoami) " + perm[1] + "' y repite el escaneo.";
  }
  if (/^TIMEOUT:|context deadline exceeded|ETIMEDOUT|timed out/i.test(e)) {
    return "El análisis excedió el tiempo límite (imagen grande: la descarga puede tardar varios minutos). " +
           "Aumenta el 'Timeout por imagen' en la configuración del nodo.";
  }
  if (/no space left on device|disk quota exceeded/i.test(e)) {
    return "Sin espacio en disco para descargar la imagen. Libera espacio con 'docker image prune' y reintenta.";
  }
  // Antes que la autenticación: su mensaje también contiene "denied".
  if (/TOOMANYREQUESTS|toomanyrequests|429|rate limit/i.test(e)) {
    return "Límite de descargas del registro alcanzado (rate limit de Docker Hub). Inicia sesión con 'docker login' o reintenta más tarde.";
  }
  // Antes que "no encontrada": con registro privado el error trae también "No such image".
  if (/unauthorized|authentication required|access.*denied|denied:/i.test(e) || /\b401\b/.test(e)) {
    return "La imagen está en un registro privado que requiere autenticación ('docker login <registro>'). " +
           "LoCoAudit soporta imágenes públicas; los registros privados quedan como trabajo futuro.";
  }
  // Antes que "no encontrada": la imagen está pero le falta una capa.
  if (/unable to export the image|content digest \S+: not found/i.test(e)) {
    return "La imagen está en Docker pero su copia local está incompleta: le falta una capa y no se puede leer. " +
           "Vuelve a descargarla con 'docker pull' o bórrala si ya no la usas.";
  }
  if (/MANIFEST_UNKNOWN|manifest unknown|No such image|unable to find the specified image|NAME_UNKNOWN|not found/i.test(e)) {
    return "Imagen o tag no encontrado (ni en local ni en el registro). Revisa el nombre y el tag.";
  }
  if (/no such host|dial tcp|network is unreachable|i\/o timeout|connection refused|TLS handshake/i.test(e)) {
    return "No se pudo contactar con el registro (problema de red o sin conexión).";
  }
  // Sin catalogar: se quita el prefijo de log de trivy para que la causa quepa en el recorte.
  const clean = e
    .replace(/^\S+\s+FATAL\s+Fatal error\s+/m, "")
    .replace(/^run error:\s*/, "");
  const firstLine = clean.split("\n").map((s) => s.trim()).filter(Boolean)[0] || "Fallo al escanear con Trivy";
  return firstLine.slice(0, 400);
}

function plural(n, uno, varios) {
  let palabra;
  if (n === 1) {
    palabra = uno;
  } else {
    palabra = varios;
  }
  return `${n} ${palabra}`;
}

// Sin análisis de CVE una imagen no puede darse por limpia: se dice que no se hizo y por qué.
function hallazgoCveOmitido(trivy, rejectReason) {
  let kind = trivy && trivy.kind;
  let reason = trivy && trivy.reason;
  if (rejectReason) {
    kind = "error";
    reason = rejectReason;
  }
  // "nothing-to-scan" no deja nada sin revisar y el fallo de todas ya tiene sus propios hallazgos.
  if (!["disabled", "error"].includes(kind)) return null;
  if (kind === "error" && !rejectReason) return null;

  const fix = {
    "disabled":      "Activa el análisis de vulnerabilidades en las opciones del nodo si quieres revisar las imágenes.",
    "error":         "Vuelve a lanzar la auditoría. Si se repite, comprueba que Trivy funciona con 'trivy --version'.",
  }[kind];
  return crearHallazgo({
    id:        "IMG-TRIVY-SKIP",
    title:     "Vulnerabilidades de las imágenes: no se han analizado",
    severity:  "info",
    evidence:  `${String(reason || "sin detalle").trim()}. ` +
               "Que no aparezcan CVE no significa que las imágenes no los tengan.",
    fix,
    category:  "image",
    source:    "native",
    isCommand: false,
    skipped:   true,
    kind,
  });
}

// Consulta a Docker fallida: comprobación no realizada, no "sin resultados".
function hallazgoListaFallida(id, label, reason, checkCmd) {
  return crearHallazgo({
    id,
    title:     `${label}: no se ha podido comprobar`,
    severity:  "info",
    evidence:  `Docker no respondió al consultarlo: ${String(reason || "sin detalle").trim()}. ` +
               "Que no aparezcan resultados de esta parte no significa que no los haya.",
    fix:       "Vuelve a lanzar la auditoría. Si se repite, comprueba que el servicio de Docker responde.\n" +
               `$ ${checkCmd}`,
    category:  "image",
    source:    "native",
    isCommand: false,
    skipped:   true,
    kind:      "error",
  });
}

// Un hallazgo por imagen fallida, en los dos modos, para que ninguna desaparezca sin avisar.
function hallazgosErrorEscaneo(failed) {
  return (failed || []).map((fa, i) =>
    crearHallazgo({
      id:       `IMG-SCAN-ERR-${String(i + 1).padStart(3, "0")}`,
      title:    `No se pudo escanear la imagen «${fa.ref || "desconocida"}»`,
      severity: "info",
      evidence: resumirErrorEscaneo(fa.error),
      // La causa concreta ya va en la evidencia.
      fix:      "Consulta el detalle del error arriba: indica la causa (tiempo de espera, tamaño, red, credenciales, caché ocupada o nombre) y cómo resolverla.",
      category: "image",
      source:   "trivy",
      image:    fa.ref || null,
      // Cuenta como comprobación no realizada, no como imagen revisada.
      skipped:  true,
      kind:     "error",
    })
  );
}

function construirPayload(findings, scanMeta, raw, scannedImages) {
  raw = { ...raw, trivy: sinResultados(raw.trivy) };
  let imagenes;
  if (Array.isArray(scannedImages)) {
    imagenes = scannedImages;
  } else {
    imagenes = [];
  }
  return {
    findings,
    summary:   resumir(findings),
    source:    "audit-image",
    auditType: "image",
    host: { hostname: os.hostname(), platform: process.platform },
    scanMeta,
    // El dashboard lo usa cuando no hay datos de `docker images` (imágenes remotas).
    scannedImages: imagenes,
    raw,
    timestamp: new Date().toISOString(),
  };
}

module.exports = function (RED) {
  function NodoAuditoriaImagen(config) {
    RED.nodes.createNode(this, config);
    const node = this;

    // Solo para poder elegir el config desde el editor: el chat lo sirve /locoaudit/chat.
    if (config.llmConfig) {
      node.llmConfig = RED.nodes.getNode(config.llmConfig);
    } else {
      node.llmConfig = null;
    }

    node.on("input", async function (msg, send, done) {
      const scanMode     = config.scanMode || "local";
      const enableConfig = config.enableConfig !== false;
      const enableTrivy  = config.enableTrivy  !== false;
      // Configurable porque una imagen grande tarda en descargarse.
      const imageTimeout = Math.min(1800, Math.max(30, parseInt(config.imageTimeout, 10) || 300)) * 1000;

      const startTime = Date.now();

      try {
        // Modo específico: lista separada por comas; trivy descarga lo que falte y no necesita el daemon.
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
            .map((s) => leerReferenciaImagen(s.trim()))
            .filter(Boolean);

          if (refs.length === 0) {
            const findings = [
              crearHallazgo({
                id:       "IMG-IMAGE-NONE",
                title:    "No se indicó ninguna imagen a escanear",
                severity: "info",
                evidence: "scanMode='specific' pero la referencia de imagen está vacía",
                // Sin ": " para que el dashboard no lo tome por "etiqueta: comando".
                fix:      "Indica una imagen en el nodo, por ejemplo nginx:latest, o proporciónala vía msg.",
                category: "image",
                source:   "native",
              }),
            ];
            msg.payload = construirPayload(
              findings,
              { modulesRun: [], imagesFound: 0, containersFound: 0, containersRunning: 0, durationMs: Date.now() - startTime },
              { docker: null, configFindings: [], trivy: null }
            );
            node.status({ fill: "grey", shape: "dot", text: "Sin imagen indicada" });
            send(msg);
            done();
            return;
          }

          // Única herramienta necesaria en este modo.
          const trivyAvailable = await existeComando("trivy");
          if (!trivyAvailable) {
            node.status({ fill: "red", shape: "ring", text: "Trivy no instalado" });
            done(new Error(
              "Trivy no se encontró instalado en el sistema y audit-image lo necesita para analizar las imágenes. " +
              "Instala Trivy (https://trivy.dev/) y vuelve a lanzar la auditoría."
            ));
            return;
          }

          // Con repository vacío, referenciaImagen() de cve-checker usa el id tal cual.
          const targets = refs.map((r) => ({ id: r, repository: "", tag: "" }));
          const trivy   = await ejecutarTrivyImagen(targets, imageTimeout);

          let findings;
          if (trivy && !trivy.skipped) {
            findings = normalizarImagen(trivy, "trivy");
          } else {
            findings = [];
          }

          const failed = (trivy && trivy.failed) || [];
          findings.push(...hallazgosErrorEscaneo(failed));

          const scannedImages = (trivy && trivy.scannedImages) || [];

          msg.payload = construirPayload(
            findings,
            { modulesRun: ["trivy-image"], imagesFound: scannedImages.length, containersFound: 0, containersRunning: 0, durationMs: Date.now() - startTime },
            { docker: null, configFindings: [], trivy },
            scannedImages
          );

          msg.payload.scanMeta.checksSkipped = resumenOmitidas(findings);

          const maxSev = msg.payload.summary.maxSeverity || "info";
          let statusColor;
          if (maxSev === "critical" || maxSev === "high") {
            statusColor = "red";
          } else if (maxSev === "medium" || failed.length) {
            statusColor = "yellow";
          } else {
            statusColor = "green";
          }
          let statusTxt;
          if (failed.length) {
            statusTxt = `${scannedImages.length} ok · ${plural(failed.length, "fallo", "fallos")} · riesgo: ${maxSev}`;
          } else {
            statusTxt = `${plural(scannedImages.length, "imagen", "imágenes")} · riesgo: ${maxSev}`;
          }
          let formaRemota;
          if (failed.length) {
            formaRemota = "ring";
          } else {
            formaRemota = "dot";
          }
          node.status({ fill: statusColor, shape: formaRemota, text: statusTxt });

          send(msg);
          done();
          return;
        }

        // Modo local: todas las imágenes del daemon.
        node.status({ fill: "blue", shape: "dot", text: "Auditando imágenes..." });

        const docker = await infoDocker();

        if (docker.skipped) {
          // Por kind, no por reason: el texto lo redacta docker-api según el caso.
          if (docker.kind === "daemon-down") {
            node.status({ fill: "red", shape: "ring", text: "Docker no responde" });
            done(new Error(
              "Docker está instalado pero su servicio no responde, y el modo de imágenes locales lo necesita. " +
              "Arranca Docker (Docker Desktop o el servicio del sistema) y vuelve a lanzar la auditoría."
            ));
          } else {
            node.status({ fill: "red", shape: "ring", text: "Docker no instalado" });
            done(new Error(
              "Docker no se encontró instalado en el sistema y el modo de imágenes locales lo necesita. " +
              "Instálalo (https://www.docker.com/products/docker-desktop) o usa el modo de imagen específica."
            ));
          }
          return;
        }

        let promesaConfig;
        if (enableConfig) {
          promesaConfig = auditarConfigDocker(docker);
        } else {
          promesaConfig = Promise.resolve([]);
        }
        let promesaTrivy;
        if (enableTrivy) {
          promesaTrivy = ejecutarTrivyImagen(docker.images, imageTimeout);
        } else {
          // kind distingue "desactivado" de "falló"; reason es solo para leer.
          promesaTrivy = Promise.resolve({ skipped: true, kind: "disabled", reason: "El análisis de vulnerabilidades de las imágenes está desactivado en las opciones del nodo." });
        }
        const [configResult, trivyResult] = await Promise.allSettled([
          promesaConfig,
          promesaTrivy,
        ]);

        let configFindings;
        if (configResult.status === "fulfilled") {
          configFindings = configResult.value;
        } else {
          configFindings = [];
        }
        // Un fallo de la revisión o de los listados no puede quedar como lista vacía.
        const dockerGaps = [];
        if (configResult.status === "rejected") {
          dockerGaps.push(hallazgoListaFallida("IMG-CFG-SKIP", "Configuración de los contenedores",
            String((configResult.reason && configResult.reason.message) || configResult.reason), "docker ps -a"));
        }
        if (docker.imagesError) {
          dockerGaps.push(hallazgoListaFallida("IMG-DOCKER-IMAGES-SKIP", "Inventario de imágenes locales", docker.imagesError, "docker images"));
        }
        if (docker.containersError) {
          dockerGaps.push(hallazgoListaFallida("IMG-DOCKER-CONTAINERS-SKIP", "Inventario de contenedores", docker.containersError, "docker ps -a"));
        }
        let trivy;
        if (trivyResult.status  === "fulfilled") {
          trivy = trivyResult.value;
        } else {
          trivy = null;
        }

        if (configResult.status === "rejected") {
          node.warn(`[audit-image] config-audit falló: ${configResult.reason}`);
        }
        if (trivyResult.status === "rejected") {
          node.warn(`[audit-image] cve-checker falló: ${trivyResult.reason}`);
        }

        // Por kind, no por reason. Un fallo durante el análisis no tira la auditoría: queda como hallazgo.
        if (enableTrivy && trivy && trivy.kind === "not-installed") {
          node.status({ fill: "red", shape: "ring", text: "Trivy no instalado" });
          done(new Error(
            "Trivy está activado en la configuración del nodo pero no se encontró instalado en el sistema. " +
            "Instala Trivy (https://trivy.dev/) o desactiva el módulo en las opciones del nodo."
          ));
          return;
        }

        let trivyFindings;
        if (trivy && !trivy.skipped) {
          trivyFindings = normalizarImagen(trivy, "trivy");
        } else {
          trivyFindings = [];
        }

        // trivy.failed se lee también con skipped:true: es el caso en que fallaron todas.
        const scanErrors = hallazgosErrorEscaneo(trivy && trivy.failed);
        let motivoRechazo;
        if (trivyResult.status === "rejected") {
          motivoRechazo = String((trivyResult.reason && trivyResult.reason.message) || trivyResult.reason);
        } else {
          motivoRechazo = null;
        }
        const cveGap = hallazgoCveOmitido(trivy,
          motivoRechazo);

        // El dashboard solo pinta "Limpia" en las imágenes que Trivy analizó de verdad.
        const analizadas = new Set(((trivy && trivy.scannedImages) || []).map((m) => m.name));
        const fallidas = new Set(((trivy && trivy.failed) || []).map((f) => f.ref));
        for (const img of docker.images) {
          const ref = referenciaImagen(img);
          if (fallidas.has(ref)) img.cveScan = "fallida";
          else if (analizadas.has(ref)) img.cveScan = "analizada";
          else img.cveScan = "sin-analizar";
        }

        let huecoCve;
        if (cveGap) {
          huecoCve = [cveGap];
        } else {
          huecoCve = [];
        }
        const findings   = [...configFindings, ...dockerGaps, ...trivyFindings, ...scanErrors, ...huecoCve];
        const summary    = resumir(findings);
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
            // Mismo resumen que audit-host, sacado de los hallazgos.
            checksSkipped: resumenOmitidas(findings),
            modulesRun,
            imagesFound:       docker.images.length,
            containersFound:   docker.containers.length,
            containersRunning: docker.containers.filter((c) => c.running).length,
            // Para que el informe sea reproducible: la base de datos de Trivy cambia.
            trivyVersion:      (trivy && trivy.trivyVersion) || null,
            engineVersion:     docker.serverVersion || null,
            durationMs,
          },
          // En local el dashboard usa raw.docker.images; en remoto cae a este campo.
          scannedImages: (trivy && trivy.scannedImages) || [],
          raw: { docker, configFindings, trivy: sinResultados(trivy) },
          timestamp: new Date().toISOString(),
        };

        const maxSev = summary.maxSeverity || "info";
        // Cualquier parte que no se pudo revisar impide el verde; desactivarla a propósito, no.
        const incompleto = scanErrors.length > 0 || dockerGaps.length > 0 ||
          Boolean(cveGap && cveGap.kind !== "disabled");
        let statusColor = "green";
        if (maxSev === "critical" || maxSev === "high") statusColor = "red";
        else if (maxSev === "medium" || incompleto) statusColor = "yellow";

        let forma;
        if (incompleto) {
          forma = "ring";
        } else {
          forma = "dot";
        }
        let sufijoFallos;
        if (scanErrors.length) {
          sufijoFallos = ` · ${plural(scanErrors.length, "fallo", "fallos")}`;
        } else {
          sufijoFallos = "";
        }
        let sufijoCve;
        if (cveGap) {
          sufijoCve = " · CVE sin analizar";
        } else {
          sufijoCve = "";
        }
        node.status({
          fill:  statusColor,
          shape: forma,
          text:  `${plural(docker.images.length, "imagen", "imágenes")} · ` +
                 `${plural(docker.containers.length, "contenedor", "contenedores")}` +
                 sufijoFallos +
                 sufijoCve +
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

  RED.nodes.registerType("audit-image", NodoAuditoriaImagen);
};
