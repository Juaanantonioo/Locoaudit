"use strict";

/**
 * audit-host.js — Nodo audit-host para Node-RED.
 *
 * Orquesta los 6 módulos de auditoría de host en paralelo y emite:
 *   msg.payload = {
 *     findings: Finding[],
 *     source: 'audit-host',
 *     raw: { cpuMemory, disk, swInventory, osInfo, lynis, trivy },
 *     timestamp: string (ISO 8601)
 *   }
 *
 * La UI (audit-host.html) expone checkboxes para activar/desactivar módulos.
 * Configuración en config: enableCpu, enableDisk, enableSw, enableLynis, enableTrivy
 */

const { runSystemModule } = require("./modules/cpu-memory");
const { getDiskInfo } = require("./modules/disk-storage");
const { getSwInventory } = require("./modules/sw-inventory");
const { getOsInfo } = require("./modules/os-info");
const { runLynis } = require("./modules/lynis");
const { runTrivyFs } = require("./modules/trivy-fs");
const { normalizeHost } = require("../../lib/normalizer");
const { summarize } = require("../../lib/severity-map");

module.exports = function (RED) {
  function AuditHostNode(config) {
    RED.nodes.createNode(this, config);
    const node = this;

    node.on("input", async function (msg, send, done) {
      node.status({ fill: "blue", shape: "dot", text: "Auditando..." });

      // Opciones de módulos (activados por defecto si no se especifica)
      const enableCpu = config.enableCpu !== false;
      const enableDisk = config.enableDisk !== false;
      const enableSw = config.enableSw !== false;
      const enableLynis = config.enableLynis !== false;
      const enableTrivy = config.enableTrivy !== false;

      const startTime = Date.now();

      try {
        // Lanzar todos los módulos habilitados en paralelo
        const [cpuResult, diskResult, swResult, lynisResult, trivyResult] =
          await Promise.allSettled([
            enableCpu ? Promise.resolve(runSystemModule()) : Promise.resolve(null),
            enableDisk ? getDiskInfo() : Promise.resolve(null),
            enableSw ? getSwInventory() : Promise.resolve(null),
            enableLynis ? runLynis() : Promise.resolve({ skipped: true, reason: "disabled" }),
            enableTrivy ? runTrivyFs() : Promise.resolve({ skipped: true, reason: "disabled" }),
          ]);

        // Extraer valores (null si el módulo falló o estaba desactivado)
        const cpuMemory = cpuResult.status === "fulfilled" ? cpuResult.value : null;
        const disk = diskResult.status === "fulfilled" ? diskResult.value : null;
        const swInventory = swResult.status === "fulfilled" ? swResult.value : null;
        const lynis = lynisResult.status === "fulfilled" ? lynisResult.value : null;
        const trivy = trivyResult.status === "fulfilled" ? trivyResult.value : null;

        // os-info siempre se recoge (no tiene dependencias externas)
        const osInfo = getOsInfo();

        // Registrar errores de módulos en el log de Node-RED
        if (cpuResult.status === "rejected") {
          node.warn(`[audit-host] cpu-memory falló: ${cpuResult.reason}`);
        }
        if (diskResult.status === "rejected") {
          node.warn(`[audit-host] disk-storage falló: ${diskResult.reason}`);
        }
        if (swResult.status === "rejected") {
          node.warn(`[audit-host] sw-inventory falló: ${swResult.reason}`);
        }
        if (lynisResult.status === "rejected") {
          node.warn(`[audit-host] lynis falló: ${lynisResult.reason}`);
        }
        if (trivyResult.status === "rejected") {
          node.warn(`[audit-host] trivy-fs falló: ${trivyResult.reason}`);
        }

        // Normalizar todo a findings[]
        const raw = { cpuMemory, disk, swInventory, lynis, trivy };
        const findings = normalizeHost(raw, { platform: process.platform });
        const summary = summarize(findings);
        const durationMs = Date.now() - startTime;

        // Construir payload
        msg.payload = {
          findings,
          summary,
          source: "audit-host",
          auditType: "host",
          host: {
            hostname: osInfo.hostname,
            platform: osInfo.platform,
            arch: osInfo.arch,
            uptimeSec: osInfo.uptimeSec,
            uptimeHuman: osInfo.uptimeHuman,
            release: osInfo.release,
            type: osInfo.type,
          },
          scanMeta: {
            modulesRun: [
              enableCpu && "cpu-memory",
              enableDisk && "disk-storage",
              enableSw && "sw-inventory",
              enableLynis && !lynis?.skipped && "lynis",
              enableTrivy && !trivy?.skipped && "trivy-fs",
            ].filter(Boolean),
            durationMs,
          },
          raw: { ...raw, osInfo },
          timestamp: new Date().toISOString(),
        };

        const count = findings.length;
        const maxSev = summary.maxSeverity || "info";
        const statusColor =
          maxSev === "critical" || maxSev === "high"
            ? "red"
            : maxSev === "medium"
            ? "yellow"
            : "green";

        node.status({
          fill: statusColor,
          shape: "dot",
          text: `${count} hallazgos · riesgo: ${maxSev}`,
        });

        send(msg);
        done();
      } catch (err) {
        node.status({ fill: "red", shape: "ring", text: "Error" });
        done(err);
      }
    });
  }

  RED.nodes.registerType("audit-host", AuditHostNode);
};
