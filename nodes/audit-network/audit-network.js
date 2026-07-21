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
 *   enablePortScan  boolean  (default true)        — activa port-scanner.js (fallback nativo)
 *   enableNmap      boolean  (default true)         — intenta nmap antes del fallback nativo
 *   enableEnrich    boolean  (default true)         — activa service-detect.js
 *   scanTimeout     number   (default 500)          — ms por intento TCP (port-scanner)
 *   concurrency     number   (default 20)           — workers paralelos (port-scanner)
 *   scanMode        string   (default "standard")   — "standard" | "full" | "custom"
 *   customPorts     string   (default "")           — lista de puertos para scanMode "custom"
 *   scanTarget      string   (default "localhost")  — "localhost" | "custom"
 *   customTarget    string   (default "127.0.0.1")  — IP para nmap cuando scanTarget es "custom"
 *
 * Lógica de selección de escáner:
 *   1. Si scanMode === "custom" y customPorts vacío → emite finding NET-CFG-ERR y termina.
 *   2. Si enableNmap → intentar runNmap({ target, timeout: 30000 })
 *      - Si nmap disponible y tiene éxito → portSource: "nmap"
 *      - Si nmap no disponible o falla    → fallback a port-scanner nativo
 *   3. Si enablePortScan (y no se usó nmap) → scanPorts({ mode: scanMode, customPorts })
 *   portSource: "native" si se usó el fallback.
 */

const os = require("os");
const { scanPorts, PORT_CATALOG } = require("./modules/port-scanner");
const { runNmap }                 = require("./modules/nmap-wrapper");
const { enrichPorts, detectFirewall } = require("./modules/service-detect");
const { isLocalTarget }           = require("./modules/network-utils");
const { normalizeNetwork }        = require("../../lib/normalizer");
const { summarize }               = require("../../lib/severity-map");
const { createFinding }           = require("../../lib/finding-schema");

module.exports = function (RED) {
  function AuditNetworkNode(config) {
    RED.nodes.createNode(this, config);
    const node = this;

    // Referencia OPCIONAL al nodo de configuración del asistente IA (tipo "llm-config").
    // Solo habilita crear/seleccionar el config desde el editor; el chat lo sirve el
    // endpoint /locoaudit/chat. No interviene en la lógica de auditoría.
    node.llmConfig = config.llmConfig ? RED.nodes.getNode(config.llmConfig) : null;

    node.on("input", async function (msg, send, done) {
      node.status({ fill: "blue", shape: "dot", text: "Escaneando..." });

      const enablePortScan = config.enablePortScan !== false;
      const enableNmap     = config.enableNmap     !== false;
      const enableEnrich   = config.enableEnrich   !== false;
      const scanTimeout    = Number(config.scanTimeout) || 500;
      const concurrency    = Number(config.concurrency) || 20;
      const scanMode       = config.scanMode    || "standard";
      const customPorts    = config.customPorts || "";
      const target         = config.scanTarget === "custom" && config.customTarget
        ? config.customTarget
        : "127.0.0.1";

      const startTime = Date.now();

      try {
        // 1. Validar configuración: modo custom sin puertos definidos
        if (scanMode === "custom" && !customPorts.trim()) {
          const errFinding = createFinding({
            id:       "NET-CFG-ERR",
            title:    "Configuración incorrecta: lista de puertos vacía",
            severity: "medium",
            evidence: "El modo personalizado requiere una lista de puertos.",
            fix:      "Configura los puertos en el nodo audit-network. Ejemplo: 22,80,443",
            category: "network",
            source:   "native",
          });
          msg.payload = {
            findings:  [errFinding],
            summary:   summarize([errFinding]),
            source:    "audit-network",
            auditType: "network",
            host: { hostname: os.hostname(), platform: process.platform },
            scanMeta: { modulesRun: [], portSource: "none", portsScanned: 0, portsOpen: 0, durationMs: 0, scanMode },
            raw:       { ports: [] },
            timestamp: new Date().toISOString(),
          };
          node.status({ fill: "yellow", shape: "ring", text: "Configuración incorrecta" });
          send(msg);
          done();
          return;
        }

        // 2. Selección de escáner: nmap primero, port-scanner como fallback
        let openPorts  = [];
        let portSource = "native";
        const modulesRun = [];
        // Estado del escaneo nmap: distingue "host up + 0 puertos" (verde legítimo)
        // de "escaneo no concluyente / host no respondió" (advertencia, no verde).
        let nmapScan = null;
        let scanInconclusive = false;

        if (enableNmap) {
          try {
            // Timeout del executor por modo, alineado con el tiempo real medido
            // sobre un host filtrado (cada puerto filtrado añade espera). NO se usa
            // --host-timeout de nmap (cortaría antes de sondear puertos altos y
            // daría falso 0): si el escaneo excede este timeout, el executor lo mata
            // y el resultado se marca "no concluyente" (banner de aviso).
            const NMAP_TIMEOUT_BY_MODE = { rapido: 90000, standard: 240000, full: 620000, custom: 90000 };
            const nmapTimeout = NMAP_TIMEOUT_BY_MODE[scanMode] || 240000;
            const nmapResult = await runNmap({ target, scanMode, customPorts, timeout: nmapTimeout });
            if (!nmapResult.skipped) {
              openPorts  = nmapResult.ports;
              portSource = "nmap";
              nmapScan   = nmapResult.scan || null;
              modulesRun.push("nmap");
              node.log("[audit-network] escáner: nmap");
            } else {
              if (nmapResult.inconclusive) {
                scanInconclusive = true;
                nmapScan = nmapResult.scan || null;
              }
              node.log(`[audit-network] nmap omitido (${nmapResult.reason}), usando fallback nativo`);
            }
          } catch (err) {
            node.warn(`[audit-network] nmap-wrapper falló: ${err.message}`);
          }
        }

        if (portSource === "native" && enablePortScan) {
          try {
            openPorts = await scanPorts({ timeout: scanTimeout, concurrency, host: target, mode: scanMode, customPorts });
            modulesRun.push("port-scanner");
            node.log("[audit-network] escáner: native-fallback");
          } catch (err) {
            node.warn(`[audit-network] port-scanner falló: ${err.message}`);
          }
        }

        // 3. Enriquecimiento con información de proceso — SOLO para localhost:
        // lsof/netstat inspeccionan ESTE equipo; en un target remoto atribuirían
        // el puerto a un proceso local que no tiene nada que ver.
        const targetIsLocal = isLocalTarget(target);
        let ports = openPorts;
        if (enableEnrich && openPorts.length > 0 && targetIsLocal) {
          try {
            ports = await enrichPorts(openPorts);
            modulesRun.push("service-detect");
          } catch (err) {
            node.warn(`[audit-network] service-detect falló: ${err.message}`);
          }
        }

        // 3b. Firewall real del sistema (solo relevante para target local):
        // los fixes solo sugieren reglas del firewall detectado Y activo.
        let firewall = null;
        if (targetIsLocal && openPorts.length > 0) {
          try {
            firewall = await detectFirewall();
          } catch (_) { /* nunca bloquear la auditoría por esto */ }
        }

        // 4. Normalizar a findings[]
        const nmapSource = portSource === "nmap" ? "nmap" : "native";
        const findings   = normalizeNetwork(ports, nmapSource, { firewall, targetIsLocal });

        // 4b. Falso "sin riesgo": distinguir escaneo concluyente de host que no
        // respondió. Un resultado de 0 puertos SOLO es tranquilizador si el
        // escaneo terminó y el host estaba activo. Casos de advertencia:
        //   - nmap no concluyó (timeout / proceso interrumpido)
        //   - nmap terminó pero el host no respondió al descubrimiento (down)
        // En ambos, se antepone un finding "medium" para que el dashboard NO
        // pinte verde "SIN RIESGO".
        let scanStatus = "ok";
        const isRemote = !targetIsLocal;
        if (scanInconclusive) {
          scanStatus = "inconclusive";
          findings.unshift(createFinding({
            id:       "NET-SCAN-WARN",
            title:    "Escaneo no concluyente: el resultado NO garantiza que no haya puertos abiertos",
            severity: "medium",
            evidence: `El escaneo de ${target} no terminó (timeout o interrupción). ` +
                      "No se puede afirmar que el host esté seguro con estos datos.",
            fix:      "El host puede estar protegido por un firewall que ralentiza el escaneo. " +
                      "Reintenta con el modo Completo (más tiempo) o aumenta el timeout del nodo.",
            category: "network",
            source:   "nmap",
          }));
        } else if (portSource === "nmap" && nmapScan && nmapScan.hostUp === false && isRemote) {
          scanStatus = "host-down";
          findings.unshift(createFinding({
            id:       "NET-SCAN-WARN",
            title:    "El host no respondió al descubrimiento (puede estar protegido por firewall)",
            severity: "medium",
            evidence: `${target} no respondió. No se detectaron puertos, pero el resultado no es concluyente.`,
            fix:      "Si sabes que el host está encendido, está filtrando el descubrimiento. " +
                      "El nodo ya usa -Pn; prueba el modo Completo para un rango de puertos mayor.",
            category: "network",
            source:   "nmap",
          }));
        }

        const summary    = summarize(findings);
        const durationMs = Date.now() - startTime;

        // 5. Construir payload
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
            scanMode,
            // Estado del escaneo: 'ok' | 'inconclusive' | 'host-down'.
            // El dashboard usa esto para NO pintar verde cuando no es concluyente.
            scanStatus,
            hostUp: nmapScan ? nmapScan.hostUp : null,
            filteredPorts: nmapScan ? nmapScan.filteredCount : null,
            // Transparencia del escaneo: target y rango exactos para que el
            // resultado sea reproducible (un `nmap localhost` manual escanea
            // otro conjunto de puertos — top-1000 de nmap — y puede diferir).
            target,
            portRange:
              nmapScan && nmapScan.portSpec
                ? nmapScan.portSpec
                : portSource === "nmap"
                ? `1-1024 + catálogo (${Object.keys(PORT_CATALOG).length} puertos conocidos)`
                : scanMode === "custom"
                ? customPorts.trim()
                : `catálogo (${Object.keys(PORT_CATALOG).length} puertos conocidos)`,
            customTarget: target !== "127.0.0.1" ? target : null,
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
          text:  scanStatus !== "ok"
            ? `escaneo no concluyente (${scanStatus})`
            : `${openPorts.length} puertos abiertos · riesgo: ${maxSev}`,
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
