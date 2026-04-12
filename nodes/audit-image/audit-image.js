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

module.exports = function (RED) {
  function AuditImageNode(config) {
    RED.nodes.createNode(this, config);
    const node = this;

    node.on("input", async function (msg, send, done) {
      node.status({ fill: "blue", shape: "dot", text: "Auditando imágenes..." });

      const enableConfig = config.enableConfig !== false;
      const enableTrivy  = config.enableTrivy  !== false;

      const startTime = Date.now();

      try {
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
          enableTrivy  ? runTrivyImage(docker.images)      : Promise.resolve({ skipped: true, reason: "disabled" }),
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

        const findings   = [...configFindings, ...trivyFindings];
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
          text:  `${docker.images.length} imágenes · ${docker.containers.length} contenedores · riesgo: ${maxSev}`,
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
