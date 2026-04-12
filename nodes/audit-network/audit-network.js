"use strict";

/**
 * audit-network.js — Nodo audit-network para Node-RED.
 *
 * Orquesta port-scanner.js y service-detect.js y emite:
 *   msg.payload = {
 *     findings: Finding[],
 *     summary,
 *     source: "audit-network",
 *     auditType: "network",
 *     host: { hostname, platform },
 *     scanMeta: {
 *       modulesRun: string[],
 *       portsScanned: number,
 *       portsOpen: number,
 *       durationMs: number
 *     },
 *     raw: { ports },
 *     timestamp: string (ISO 8601)
 *   }
 *
 * Configuración (config):
 *   enablePortScan  boolean  (default true)  — activa port-scanner.js
 *   enableEnrich    boolean  (default true)  — activa service-detect.js
 *   scanTimeout     number   (default 500)   — ms por intento TCP
 *   concurrency     number   (default 20)    — workers paralelos
 */

const os = require("os");
const { scanPorts, PORT_CATALOG } = require("./modules/port-scanner");
const { enrichPorts }             = require("./modules/service-detect");
const { normalizeNetwork }        = require("../../lib/normalizer");
const { summarize }               = require("../../lib/severity-map");

module.exports = function (RED) {
  function AuditNetworkNode(config) {
    RED.nodes.createNode(this, config);
    const node = this;

    node.on("input", async function (msg, send, done) {
      node.status({ fill: "blue", shape: "dot", text: "Escaneando..." });

      const enablePortScan = config.enablePortScan !== false;
      const enableEnrich   = config.enableEnrich   !== false;
      const scanTimeout    = Number(config.scanTimeout)  || 500;
      const concurrency    = Number(config.concurrency)  || 20;

      const startTime = Date.now();

      try {
        // 1. Escaneo de puertos
        let openPorts = [];
        if (enablePortScan) {
          try {
            openPorts = await scanPorts({ timeout: scanTimeout, concurrency });
          } catch (err) {
            node.warn(`[audit-network] port-scanner falló: ${err.message}`);
          }
        }

        // 2. Enriquecimiento con información de proceso
        let ports = openPorts;
        if (enableEnrich && openPorts.length > 0) {
          try {
            ports = await enrichPorts(openPorts);
          } catch (err) {
            node.warn(`[audit-network] service-detect falló: ${err.message}`);
          }
        }

        // 3. Normalizar a findings[]
        const findings  = normalizeNetwork(ports, "native");
        const summary   = summarize(findings);
        const durationMs = Date.now() - startTime;

        // 4. Construir payload
        msg.payload = {
          findings,
          summary,
          source:    "audit-network",
          auditType: "network",
          host: {
            hostname: os.hostname(),
            platform: process.platform,
          },
          scanMeta: {
            modulesRun: [
              enablePortScan             && "port-scanner",
              enableEnrich && ports !== openPorts && "service-detect",
            ].filter(Boolean),
            portsScanned: Object.keys(PORT_CATALOG).length,
            portsOpen:    openPorts.length,
            durationMs,
          },
          raw: { ports },
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
          text:  `${openPorts.length} puertos abiertos · riesgo: ${maxSev}`,
        });

        send(msg);
        done();
      } catch (err) {
        node.status({ fill: "red", shape: "ring", text: "Error" });
        done(err);
      }
    });
  }

  RED.nodes.registerType("audit-network", AuditNetworkNode);
};
