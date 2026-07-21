"use strict";

/**
 * audit-host.js — Nodo audit-host para Node-RED.
 *
 * Orquesta los 6 módulos de auditoría de host en paralelo y emite:
 *   msg.payload = {
 *     findings: Finding[],
 *     source: 'audit-host',
 *     raw: { cpuMemory, disk, swInventory, osInfo, lynis, trivy, securityEvents },
 *     securityEvents?: { windowHours, events: [{ts,type,user,origin,detail}], truncated },
 *     timestamp: string (ISO 8601)
 *   }
 *
 * La UI (audit-host.html) expone checkboxes para activar/desactivar módulos.
 * Configuración en config: enableCpu, enableDisk, enableSw, enableLynis, enableTrivy,
 * securityEvents (default false) + securityEventsWindow (horas, 1-168, default 24)
 */

const { runSystemModule } = require("./modules/cpu-memory");
const { getDiskInfo } = require("./modules/disk-storage");
const { getSwInventory } = require("./modules/sw-inventory");
const { getOsInfo } = require("./modules/os-info");
const { runLynis } = require("./modules/lynis");
const { runTrivyFs } = require("./modules/trivy-fs");
const { runSecurityEvents, buildEventList } = require("./modules/security-events");
const { normalizeHost } = require("../../lib/normalizer");
const { detectPackageManager } = require("../../lib/pkg-manager");
const { summarize } = require("../../lib/severity-map");

module.exports = function (RED) {
  function AuditHostNode(config) {
    RED.nodes.createNode(this, config);
    const node = this;

    // Referencia OPCIONAL al nodo de configuración del asistente IA (tipo "llm-config").
    // Solo habilita crear/seleccionar el config desde el editor; el chat lo sirve el
    // endpoint /locoaudit/chat. No interviene en la lógica de auditoría.
    node.llmConfig = config.llmConfig ? RED.nodes.getNode(config.llmConfig) : null;

    node.on("input", async function (msg, send, done) {
      node.status({ fill: "blue", shape: "dot", text: "Auditando..." });

      // Opciones de módulos (activados por defecto si no se especifica)
      const enableCpu = config.enableCpu !== false;
      const enableDisk = config.enableDisk !== false;
      const enableSw = config.enableSw !== false;
      const enableLynis = config.enableLynis !== false;
      const enableTrivy = config.enableTrivy !== false;
      // Eventos de seguridad: desactivado por defecto (opt-in)
      const enableSecEvents = config.securityEvents === true;
      const secWindow = Math.min(168, Math.max(1, parseInt(config.securityEventsWindow, 10) || 24));

      const startTime = Date.now();

      try {
        // Lanzar todos los módulos habilitados en paralelo
        const [cpuResult, diskResult, swResult, lynisResult, trivyResult, secResult] =
          await Promise.allSettled([
            enableCpu ? Promise.resolve(runSystemModule()) : Promise.resolve(null),
            enableDisk ? getDiskInfo() : Promise.resolve(null),
            enableSw ? getSwInventory() : Promise.resolve(null),
            enableLynis ? runLynis() : Promise.resolve({ skipped: true, reason: "disabled" }),
            enableTrivy ? runTrivyFs() : Promise.resolve({ skipped: true, reason: "disabled" }),
            enableSecEvents ? runSecurityEvents(secWindow) : Promise.resolve(null),
          ]);

        // Extraer valores (null si el módulo falló o estaba desactivado)
        const cpuMemory = cpuResult.status === "fulfilled" ? cpuResult.value : null;
        const disk = diskResult.status === "fulfilled" ? diskResult.value : null;
        const swInventory = swResult.status === "fulfilled" ? swResult.value : null;
        const lynis = lynisResult.status === "fulfilled" ? lynisResult.value : null;
        const trivy = trivyResult.status === "fulfilled" ? trivyResult.value : null;
        const securityEvents = secResult.status === "fulfilled" ? secResult.value : null;

        // Si el usuario activó Lynis o Trivy y la herramienta no está instalada → error explícito
        if (enableLynis && lynis && lynis.skipped) {
          node.status({ fill: "red", shape: "ring", text: "Lynis no instalado" });
          done(new Error(
            "Lynis está activado en la configuración del nodo pero no se encontró instalado en el sistema. " +
            "Instala Lynis (https://cisofy.com/lynis/) o desactiva el módulo en las opciones del nodo."
          ));
          return;
        }
        if (enableTrivy && trivy && trivy.skipped) {
          node.status({ fill: "red", shape: "ring", text: "Trivy no instalado" });
          done(new Error(
            "Trivy está activado en la configuración del nodo pero no se encontró instalado en el sistema. " +
            "Instala Trivy (https://trivy.dev/) o desactiva el módulo en las opciones del nodo."
          ));
          return;
        }

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
        if (secResult.status === "rejected") {
          node.warn(`[audit-host] security-events falló: ${secResult.reason}`);
        }

        // Normalizar todo a findings[]
        // Nota: security-events skipped NO es error del nodo (a diferencia de
        // Lynis/Trivy): el normalizador lo convierte en un finding informativo.
        const raw = { cpuMemory, disk, swInventory, lynis, trivy, securityEvents };

        // Gestor de paquetes REAL del equipo: sin esto los fixes asumían apt en
        // Linux y brew en macOS, y en Arch (pacman) el comando era inejecutable.
        let pkgManager = null;
        try {
          pkgManager = await detectPackageManager(process.platform);
        } catch (_) { /* nunca bloquear la auditoría por la detección */ }

        const findings = normalizeHost(raw, { platform: process.platform, pkgManager });
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
              enableSecEvents && !securityEvents?.skipped && "security-events",
            ].filter(Boolean),
            durationMs,
          },
          raw: { ...raw, osInfo },
          timestamp: new Date().toISOString(),
        };

        // Eventos parseados para la tabla de log del dashboard (grupo
        // "Logs del sistema"): lista plana ordenada por ts desc, tope 200.
        if (enableSecEvents && securityEvents) {
          msg.payload.securityEvents = buildEventList(securityEvents);
        }

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
