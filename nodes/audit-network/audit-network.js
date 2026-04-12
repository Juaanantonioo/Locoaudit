"use strict";

/**
 * audit-network.js — Nodo audit-network para Node-RED.
 *
 * Orquesta port-scanner.js, nmap-wrapper.js y service-detect.js y emite:
 *   msg.payload = {
 *     findings: Finding[],
 *     summary,
 *     source: "audit-network",
 *     auditType: "network",
 *     host: { hostname, platform },
 *     scanMeta: {
 *       modulesRun: string[],
 *       portSource: "nmap" | "native",
 *       portsScanned: number,
 *       portsOpen: number,
 *       durationMs: number
 *     },
 *     raw: { ports },
 *     timestamp: string (ISO 8601)
 *   }
 *
 * Configuración (config):
 *   enablePortScan  boolean  (default true)  — activa port-scanner.js (fallback nativo)
 *   enableNmap      boolean  (default true)  — intenta nmap antes del fallback nativo
 *   enableEnrich    boolean  (default true)  — activa service-detect.js
 *   scanTimeout     number   (default 500)   — ms por intento TCP (port-scanner)
 *   concurrency     number   (default 20)    — workers paralelos (port-scanner)
 *
 * Lógica de selección de escáner:
 *   1. Si enableNmap → intentar runNmap({ target: "127.0.0.1", timeout: 30000 })
 *      - Si nmap disponible y tiene éxito → portSource: "nmap"
 *      - Si nmap no disponible o falla    → fallback a port-scanner nativo
 *   2. Si enablePortScan (y no se usó nmap) → scanPorts()
 *   portSource: "native" si se usó el fallback.
 */

const os = require("os");
const { scanPorts, PORT_CATALOG } = require("./modules/port-scanner");
const { runNmap }                 = require("./modules/nmap-wrapper");
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
      const enableNmap     = config.enableNmap     !== false;
      const enableEnrich   = config.enableEnrich   !== false;
      const scanTimeout    = Number(config.scanTimeout) || 500;
      const concurrency    = Number(config.concurrency) || 20;

      const startTime = Date.now();

      try {
        // 1. Selección de escáner: nmap primero, port-scanner como fallback
        let openPorts  = [];
        let portSource = "native";
        const modulesRun = [];

        if (enableNmap) {
          try {
            const nmapResult = await runNmap({ target: "127.0.0.1", timeout: 30000 });
            if (!nmapResult.skipped) {
              openPorts  = nmapResult.ports;
              portSource = "nmap";
              modulesRun.push("nmap");
              node.log("[audit-network] escáner: nmap");
            } else {
              node.log(`[audit-network] nmap omitido (${nmapResult.reason}), usando fallback nativo`);
            }
          } catch (err) {
            node.warn(`[audit-network] nmap-wrapper falló: ${err.message}`);
          }
        }

        if (portSource === "native" && enablePortScan) {
          try {
            openPorts = await scanPorts({ timeout: scanTimeout, concurrency });
            modulesRun.push("port-scanner");
            node.log("[audit-network] escáner: native-fallback");
          } catch (err) {
            node.warn(`[audit-network] port-scanner falló: ${err.message}`);
          }
        }

        // 2. Enriquecimiento con información de proceso (independiente de la fuente)
        let ports = openPorts;
        if (enableEnrich && openPorts.length > 0) {
          try {
            ports = await enrichPorts(openPorts);
            modulesRun.push("service-detect");
          } catch (err) {
            node.warn(`[audit-network] service-detect falló: ${err.message}`);
          }
        }

        // 3. Normalizar a findings[]
        const nmapSource = portSource === "nmap" ? "nmap" : "native";
        const findings   = normalizeNetwork(ports, nmapSource);
        const summary    = summarize(findings);
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
            modulesRun,
            portSource,
            portsScanned: portSource === "nmap" ? null : Object.keys(PORT_CATALOG).length,
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
