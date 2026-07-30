"use strict";

/**
 * audit-network.js — Nodo audit-network para Node-RED.
 *
 * Orquesta nmap-wrapper.js y service-detect.js y emite:
 *   msg.payload = {
 *     findings: Finding[],
 *     summary,
 *     source: "audit-network",
 *     auditType: "network",
 *     host: { hostname, platform },
 *     scanMeta: {
 *       modulesRun: string[],
 *       portSource: "nmap" | "none",
 *       portsScanned: number,
 *       portsOpen: number,
 *       durationMs: number
 *     },
 *     raw: { ports },
 *     timestamp: string (ISO 8601)
 *   }
 *
 * Configuración (config):
 *   scanMode        string   (default "standard")   — "standard" | "full" | "custom"
 *   customPorts     string   (default "")           — lista de puertos para scanMode "custom"
 *   scanTarget      string   (default "localhost")  — "localhost" | "custom"
 *   customTarget    string   (default "127.0.0.1")  — IP para nmap cuando scanTarget es "custom"
 *
 * Nmap es REQUISITO del nodo: no hay escáner alternativo. El antiguo escáner
 * nativo (port-scanner.js) se eliminó, y con él sus opciones de la UI (timeout
 * por puerto y workers paralelos, que solo tenían sentido para él).
 *
 * La identificación de proceso/PID/bind (service-detect.js) NO es opcional:
 * siempre se ejecuta para targets locales, porque de esos campos dependen las
 * reglas de resolución (localhost vs expuesto, servicio del sistema vs terceros).
 *
 * Lógica de escaneo:
 *   1. Si scanMode === "custom" y customPorts vacío → finding NET-CFG-ERR y termina.
 *   2. commandExists("nmap") vía runNmap(): si no está instalado → finding
 *      NET-DEP-NMAP con las instrucciones de instalación de la plataforma.
 *      El nodo NO revienta: emite el payload con ese hallazgo.
 *   3. Con nmap disponible → portSource: "nmap".
 */

const os = require("os");
const { PORT_CATALOG }            = require("./modules/port-catalog");
const { runNmap }                 = require("./modules/nmap-wrapper");
const { enrichPorts, detectFirewall } = require("./modules/service-detect");
const { isLocalTarget }           = require("./modules/network-utils");
const { normalizeNetwork }        = require("../../lib/normalizer");
const { summarize }               = require("../../lib/severity-map");
const { createFinding }           = require("../../lib/finding-schema");

/**
 * Instrucciones de instalación de Nmap por plataforma.
 *
 * La gestión de dependencias del SO es un objetivo del proyecto: si falta la
 * herramienta, el usuario recibe el comando exacto de SU sistema, no un
 * "instala nmap" genérico. En Linux se dan las tres familias de gestor porque
 * el nodo no puede saber la distribución sin sondearla.
 *
 * @param {string} platform  process.platform
 * @returns {string} Texto del fix, en pasos numerados.
 */
function nmapInstallInstructions(platform) {
  if (platform === "darwin") {
    return "1. Instala Homebrew si no lo tienes: /bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"\n" +
           "2. Instala Nmap: brew install nmap\n" +
           "3. Comprueba que responde: nmap --version\n" +
           "4. Vuelve a lanzar la auditoría desde Node-RED.";
  }
  if (platform === "win32") {
    return "1. Instala Nmap: winget install -e --id Insecure.Nmap\n" +
           "2. Cierra y vuelve a abrir la terminal (y Node-RED) para que tome el PATH.\n" +
           "3. Comprueba que responde: nmap --version\n" +
           "4. Vuelve a lanzar la auditoría desde Node-RED.";
  }
  // Linux y otros Unix: el gestor depende de la distribución.
  return "1. Instala Nmap con el gestor de tu distribución:\n" +
         "   · Debian/Ubuntu: sudo apt install nmap\n" +
         "   · Arch/Manjaro:  sudo pacman -S nmap\n" +
         "   · Fedora/RHEL:   sudo dnf install nmap\n" +
         "2. Comprueba que responde: nmap --version\n" +
         "3. Vuelve a lanzar la auditoría desde Node-RED.";
}

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

        // 2. Escaneo con nmap (único escáner: es requisito del nodo)
        let openPorts  = [];
        let portSource = "none";
        const modulesRun = [];
        // Estado del escaneo nmap: distingue "host up + 0 puertos" (verde legítimo)
        // de "escaneo no concluyente / host no respondió" (advertencia, no verde).
        let nmapScan = null;
        let scanInconclusive = false;
        // Nmap ausente: no es un error del nodo, es una dependencia del SO que
        // falta. Se reporta como finding accionable, no como excepción.
        let nmapMissing = false;
        let nmapError   = null;

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
          } else if (nmapResult.inconclusive) {
            // nmap existe pero el escaneo no terminó: lo trata el bloque 4b.
            scanInconclusive = true;
            nmapScan = nmapResult.scan || null;
            portSource = "nmap";
            modulesRun.push("nmap");
          } else {
            nmapMissing = true;
            node.warn(`[audit-network] nmap no disponible (${nmapResult.reason})`);
          }
        } catch (err) {
          nmapError = err.message;
          node.warn(`[audit-network] nmap-wrapper falló: ${err.message}`);
        }

        // 3. Identificación de proceso, PID y dirección de bind — SIEMPRE activa
        // para targets locales (ya no es opcional): las reglas de resolución
        // dependen de estos campos para distinguir un servicio en loopback de uno
        // expuesto, y un daemon del sistema de una aplicación de terceros.
        //
        // Solo para localhost: lsof/netstat inspeccionan ESTE equipo; en un target
        // remoto atribuirían el puerto a un proceso local que no tiene nada que ver.
        const targetIsLocal = isLocalTarget(target);
        let ports = openPorts;
        if (openPorts.length > 0 && targetIsLocal) {
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
        const findings = normalizeNetwork(ports, "nmap", { firewall, targetIsLocal });

        // 4a. Nmap ausente o roto: es la única forma de escanear, así que un
        // resultado vacío NO significa "sin puertos abiertos". Se antepone un
        // finding con las instrucciones de instalación de ESTA plataforma para
        // que el dashboard no pinte verde y el usuario sepa qué hacer.
        if (nmapMissing || nmapError) {
          findings.unshift(createFinding({
            id:       "NET-DEP-NMAP",
            title:    nmapMissing
              ? "Nmap no está instalado: no se ha podido escanear ningún puerto"
              : "Nmap falló: no se ha podido completar el escaneo",
            severity: "high",
            evidence: nmapMissing
              ? "audit-network requiere Nmap para descubrir puertos abiertos y no se ha encontrado " +
                "el comando `nmap` en el PATH del sistema. El resultado vacío NO significa que no " +
                "haya puertos abiertos: significa que no se ha escaneado nada."
              : `Nmap está instalado pero la ejecución falló: ${nmapError}. ` +
                "El resultado vacío NO significa que no haya puertos abiertos.",
            fix:      nmapInstallInstructions(process.platform),
            category: "network",
            source:   "native",
          }));
        }

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
            // nmap decide el conjunto real de puertos según el modo: el número
            // exacto lo refleja portRange, no un contador del catálogo.
            portsScanned: null,
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
                : scanMode === "custom"
                ? customPorts.trim()
                : `1-1024 + catálogo (${Object.keys(PORT_CATALOG).length} puertos conocidos)`,
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
          fill:  nmapMissing ? "red" : statusColor,
          shape: nmapMissing ? "ring" : "dot",
          text:  nmapMissing
            ? "Nmap no instalado (requisito)"
            : scanStatus !== "ok"
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
