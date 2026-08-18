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
 *       durationMs: number,
 *       targetState: "reachable" | "unreachable" | "unknown",  // host-discovery.js
 *       discovery: { method, reason, durationMs, cmd, detail }, // host-discovery.js
 *       scanStatus: "ok" | "inconclusive" | "not-run",          // nmap-wrapper.js
 *       hostname: string|null                                   // PTR del objetivo, null si no tiene
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
 *   forceScan       boolean  (default false)        — escanear aunque el descubrimiento
 *                                                     diga que el equipo no responde
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
 *   0. Si el objetivo es remoto, descubrimiento previo con host-discovery.js
 *      (nmap -sn, ~3 s). Si el equipo NO responde no se escanea: se emite
 *      NET-HOST-UNREACHABLE y targetState "unreachable". Evita el falso verde
 *      ("Sin puertos expuestos · SIN RIESGO" sobre una IP que no existe) y evita
 *      esperar 212 s a un escaneo que no puede encontrar nada.
 *   1. Si scanMode === "custom" y customPorts vacío → finding NET-CFG-ERR y termina.
 *   2. commandExists("nmap") vía runNmap(): si no está instalado → finding
 *      NET-DEP-NMAP con las instrucciones de instalación de la plataforma.
 *      El nodo NO revienta: emite el payload con ese hallazgo.
 *   3. Con nmap disponible → portSource: "nmap".
 */

const os = require("os");
const { PORT_CATALOG }            = require("./modules/port-catalog");
const { runNmap }                 = require("./modules/nmap-wrapper");
const { checkHostReachable, deriveTargetState } = require("./modules/host-discovery");
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
      // Escanea aunque el descubrimiento diga que el host no responde. Para el
      // caso legítimo: equipo encendido que filtra ICMP y las sondas TCP del -sn.
      const forceScan      = config.forceScan === true || config.forceScan === "true";

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
        // Estado del escaneo nmap: distingue "escaneo completo" de "escaneo no
        // concluyente" (timeout / proceso cortado). Ya NO decide si el host
        // existe: de eso se encarga el descubrimiento previo.
        let nmapScan = null;
        let scanInconclusive = false;
        // Nmap ausente: no es un error del nodo, es una dependencia del SO que
        // falta. Se reporta como finding accionable, no como excepción.
        let nmapMissing = false;
        let nmapError   = null;

        // 2a. Descubrimiento previo — ÚNICA fuente de verdad sobre si el objetivo
        // existe. El escaneo usa -Pn y por tanto no puede responder a esa pregunta:
        // devuelve siempre "host up (user-set)". Sin esta comprobación, una IP
        // inexistente producía 0 puertos abiertos y el dashboard lo pintaba de
        // verde ("SIN RIESGO"), comunicando seguridad donde solo hay ausencia
        // de host. Además evita esperar: 3 s de -sn frente a los 212 s que tarda
        // el escaneo de 1024 puertos contra una IP muerta.
        //
        // Para localhost no se ejecuta: este equipo siempre se alcanza a sí mismo.
        const targetIsLocal = isLocalTarget(target);
        node.status({ fill: "blue", shape: "dot", text: targetIsLocal ? "Escaneando..." : "Comprobando el equipo..." });
        const discovery = await checkHostReachable({ target, isLocal: targetIsLocal });
        if (discovery.method === "nmap-sn") {
          modulesRun.push("host-discovery");
          node.log(`[audit-network] descubrimiento: ${discovery.detail}`);
        }

        // targetState: 'reachable' | 'unreachable' | 'unknown'.
        // Deriva SOLO del descubrimiento. 'unknown' = no se pudo determinar →
        // se escanea igual y se avisa (un falso "no alcanzable" que cancela la
        // auditoría es peor que un escaneo de más).
        const targetState = deriveTargetState(discovery);

        // Host no alcanzable y sin forzar → NO se escanea. No hay nada que
        // auditar: cero hallazgos aquí significa "no analizado", no "limpio".
        const skipScan = targetState === "unreachable" && !forceScan;

        if (skipScan) {
          node.log(`[audit-network] ${target} no alcanzable: se omite el escaneo de puertos`);
          portSource = "none";
        } else {
          try {
            node.status({ fill: "blue", shape: "dot", text: "Escaneando..." });
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
        }

        // 3. Identificación de proceso, PID y dirección de bind — SIEMPRE activa
        // para targets locales (ya no es opcional): las reglas de resolución
        // dependen de estos campos para distinguir un servicio en loopback de uno
        // expuesto, y un daemon del sistema de una aplicación de terceros.
        //
        // Solo para localhost: lsof/netstat inspeccionan ESTE equipo; en un target
        // remoto atribuirían el puerto a un proceso local que no tiene nada que ver.
        // (targetIsLocal se calcula arriba, antes del descubrimiento.)
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
        const findings = normalizeNetwork(ports, "nmap", { firewall, targetIsLocal, target });

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

        // 4b. Falso "sin riesgo": un resultado de 0 puertos SOLO es tranquilizador
        // si el objetivo existe Y el escaneo terminó. Son dos preguntas distintas
        // y cada una tiene su campo y su fuente:
        //   targetState (host-discovery)  → ¿existe el objetivo?
        //   scanStatus  (nmap-wrapper)    → ¿terminó el escaneo?
        // 'not-run' = no se escaneó porque el host no estaba accesible.
        let scanStatus = skipScan ? "not-run" : "ok";

        if (targetState === "unreachable") {
          // NO es un riesgo: es ausencia de auditoría. Por eso severity 'info' —
          // 'medium' pintaría "Riesgo Moderado", tan falso como el verde. El
          // estado neutro del dashboard lo decide targetState, no la severidad.
          findings.unshift(createFinding({
            id:       "NET-HOST-UNREACHABLE",
            title:    `No se ha podido contactar con ${target}: la auditoría no se ha realizado`,
            severity: "info",
            evidence: `${discovery.detail} ` +
                      (skipScan
                        ? "No se ha escaneado ningún puerto: la ausencia de hallazgos NO significa " +
                          "que el equipo esté seguro, significa que no se ha podido analizar."
                        : "Se ha escaneado de todas formas porque está activada la opción " +
                          "\"Escanear aunque el equipo no responda\", pero el resultado puede " +
                          "estar incompleto."),
            fix:      "1. Comprueba que el equipo está encendido y conectado a la red.\n" +
                      `2. Verifica que la dirección IP es correcta: ${target}\n` +
                      "3. Si usas VPN, confirma que el túnel está activo y enruta esa subred.\n" +
                      `4. Prueba a contactarlo desde una terminal: ping ${target}\n` +
                      (skipScan
                        ? "5. Si sabes que está encendido y solo filtra el descubrimiento, activa " +
                          "\"Escanear aunque el equipo no responda\" en el nodo audit-network."
                        : "5. Si el equipo está encendido, revisa su cortafuegos: está filtrando " +
                          "tanto el descubrimiento como el escaneo."),
            category: "network",
            source:   "nmap",
            target,
            isLocalTarget: targetIsLocal,
          }));
        } else if (scanInconclusive) {
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
        } else if (targetState === "unknown" && !targetIsLocal && !nmapMissing) {
          // No se pudo determinar si el objetivo existe (nmap ausente, timeout del
          // descubrimiento, XML ilegible). Se ha escaneado igual — mejor escanear
          // de más que cancelar por una duda — pero el resultado no puede pintarse
          // de verde sin avisar.
          findings.unshift(createFinding({
            id:       "NET-SCAN-WARN",
            title:    "No se ha podido comprobar si el equipo está accesible",
            severity: "medium",
            evidence: `${discovery.detail} El escaneo se ha realizado de todas formas, ` +
                      "pero si el equipo no existe el resultado de 0 puertos no significa nada.",
            fix:      `Comprueba manualmente que el equipo responde: ping ${target}`,
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
            // ── QUÉ ES EL OBJETIVO — fuente única: host-discovery.js (nmap -sn).
            // 'reachable' | 'unreachable' | 'unknown'. El dashboard decide con
            // ESTE campo si puede pintar verde: 0 puertos solo tranquiliza si el
            // equipo existe. NO se deriva del escaneo, que usa -Pn y siempre
            // responde "host up".
            targetState,
            discovery: {
              method:     discovery.method,
              reason:     discovery.reason,
              durationMs: discovery.durationMs,
              cmd:        discovery.cmd,
              detail:     discovery.detail,
            },
            forceScan,
            // ── QUÉ HIZO EL ESCANEO — fuente única: nmap-wrapper.js.
            // 'ok' | 'inconclusive' | 'not-run' ('not-run' = host no accesible).
            scanStatus,
            // Real desde que se quitó --open (antes siempre 0: el bloque
            // <extraports> no llegaba a emitirse).
            filteredPorts:  nmapScan ? nmapScan.filteredCount  : null,
            filteredReason: nmapScan ? nmapScan.filteredReason : null,
            // Nombre DNS inverso (PTR) del objetivo, resuelto por el propio
            // escaneo. null si el objetivo no tiene PTR: el dashboard entonces
            // NO pinta la píldora, en vez de un guion que sugeriría "se
            // comprobó y no tiene nombre".
            hostname:       nmapScan ? nmapScan.hostname : null,
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

        // El estado del nodo no puede decir "0 puertos · riesgo: info" cuando no
        // se ha auditado nada: sería el mismo falso verde del dashboard.
        node.status({
          fill:  nmapMissing ? "red"
               : targetState === "unreachable" ? "grey"
               : targetState === "unknown"     ? "yellow"
               : statusColor,
          shape: nmapMissing || targetState !== "reachable" ? "ring" : "dot",
          text:  nmapMissing
            ? "Nmap no instalado (requisito)"
            : targetState === "unreachable"
            ? `${target} no accesible — sin auditar`
            : scanStatus === "inconclusive"
            ? "escaneo no concluyente"
            : targetState === "unknown"
            ? `${openPorts.length} puertos · accesibilidad sin confirmar`
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
