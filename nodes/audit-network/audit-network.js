"use strict";

/**
 * Nodo audit-network. Nmap es requisito: no hay escáner alternativo desde que se eliminó el
 * port-scanner nativo, y con él sus opciones de la UI (timeout por puerto, workers). Si falta,
 * el nodo no revienta: emite NET-DEP-NMAP y sigue.
 *
 * La identificación de proceso, PID y bind no es opcional para targets locales: de esos campos
 * dependen las reglas de resolución, que distinguen loopback de expuesto y daemon del sistema de
 * aplicación de terceros.
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

/** El comando exacto del sistema del usuario, no un "instala nmap" genérico. En Linux van las
 *  tres familias de gestor porque el nodo no sabe la distribución sin sondearla. */
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

    // Solo para poder elegir el config desde el editor: el chat lo sirve /locoaudit/chat.
    node.llmConfig = config.llmConfig ? RED.nodes.getNode(config.llmConfig) : null;

    node.on("input", async function (msg, send, done) {
      node.status({ fill: "blue", shape: "dot", text: "Escaneando..." });

      const scanMode       = config.scanMode    || "standard";
      const customPorts    = config.customPorts || "";
      const target         = config.scanTarget === "custom" && config.customTarget
        ? config.customTarget
        : "127.0.0.1";
      // Para el caso legítimo: equipo encendido que filtra ICMP y las sondas TCP del -sn.
      const forceScan      = config.forceScan === true || config.forceScan === "true";

      const startTime = Date.now();

      try {
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

        let openPorts  = [];
        let portSource = "none";
        const modulesRun = [];
        // Separa "escaneo completo" de "no concluyente" (timeout, proceso cortado). Ya no dice
        // si el host existe: eso lo decide el descubrimiento previo.
        let nmapScan = null;
        let scanInconclusive = false;
        // Que falte nmap no es un error del nodo sino una dependencia del SO: sale como finding.
        let nmapMissing = false;
        let nmapError   = null;

        // Única fuente sobre si el objetivo existe: el escaneo va con -Pn y siempre responde
        // "host up (user-set)". Sin esto, una IP inexistente daba 0 puertos abiertos y el
        // dashboard lo pintaba verde. Y ahorra tiempo: medido contra una IP muerta, 3 s de
        // descubrimiento frente a 212 s de escaneo de 1024 puertos. Para localhost no se lanza.
        const targetIsLocal = isLocalTarget(target);
        node.status({ fill: "blue", shape: "dot", text: targetIsLocal ? "Escaneando..." : "Comprobando el equipo..." });
        const discovery = await checkHostReachable({ target, isLocal: targetIsLocal });
        if (discovery.method === "nmap-sn") {
          modulesRun.push("host-discovery");
          node.log(`[audit-network] descubrimiento: ${discovery.detail}`);
        }

        // Sale solo del descubrimiento. Con 'unknown' se escanea igual y se avisa: un falso "no
        // alcanzable" que cancela la auditoría es peor que un escaneo de más.
        const targetState = deriveTargetState(discovery);

        // Sin forzar no se escanea: cero hallazgos aquí es "no analizado", no "limpio".
        const skipScan = targetState === "unreachable" && !forceScan;

        if (skipScan) {
          node.log(`[audit-network] ${target} no alcanzable: se omite el escaneo de puertos`);
          portSource = "none";
        } else {
          try {
            node.status({ fill: "blue", shape: "dot", text: "Escaneando..." });
            // Por modo, según el tiempo medido sobre un host filtrado, donde cada puerto
            // filtrado añade espera. No se usa --host-timeout de nmap: cortaría antes de sondear
            // los puertos altos y daría un falso 0. Pasado este límite, "no concluyente".
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
              // nmap está, pero el escaneo no terminó; el aviso se emite más abajo.
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

        // Solo para el equipo local: lsof y netstat miran ESTE equipo, y contra un target remoto
        // atribuirían el puerto a un proceso de aquí que no tiene nada que ver.
        let ports = openPorts;
        if (openPorts.length > 0 && targetIsLocal) {
          try {
            ports = await enrichPorts(openPorts);
            modulesRun.push("service-detect");
          } catch (err) {
            node.warn(`[audit-network] service-detect falló: ${err.message}`);
          }
        }

        // Los fixes solo proponen reglas del firewall que esté detectado y activo.
        let firewall = null;
        if (targetIsLocal && openPorts.length > 0) {
          try {
            firewall = await detectFirewall();
          } catch (_) { /* detectar el firewall no puede tumbar la auditoría */ }
        }

        const findings = normalizeNetwork(ports, "nmap", { firewall, targetIsLocal, target });

        // Sin nmap no hay forma de escanear, así que el resultado vacío no es "sin puertos
        // abiertos". El finding va delante para que el dashboard no pinte verde.
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

        // Cero puertos solo tranquiliza si el objetivo existe y además el escaneo terminó. Son
        // dos preguntas con campo y fuente propios: targetState de host-discovery, scanStatus de
        // nmap-wrapper. 'not-run' es que no se escaneó por no estar accesible el host.
        let scanStatus = skipScan ? "not-run" : "ok";

        if (targetState === "unreachable") {
          // Ausencia de auditoría, no riesgo: de ahí el 'info'. Un 'medium' pintaría "Riesgo
          // Moderado", tan falso como el verde. El estado neutro lo decide targetState.
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
          // No se pudo determinar si el objetivo existe: nmap ausente, timeout, XML ilegible. Se
          // escaneó igual, mejor de más que cancelar por una duda, pero no se pinta verde a secas.
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
            // El conjunto real lo decide nmap según el modo: el número exacto está en portRange.
            portsScanned: null,
            portsOpen:    openPorts.length,
            durationMs,
            scanMode,
            // Qué es el objetivo, según host-discovery. Con este campo decide el dashboard si
            // puede pintar verde. No sale del escaneo, que con -Pn siempre responde "host up".
            targetState,
            discovery: {
              method:     discovery.method,
              reason:     discovery.reason,
              durationMs: discovery.durationMs,
              cmd:        discovery.cmd,
              detail:     discovery.detail,
            },
            forceScan,
            // Qué hizo el escaneo, según nmap-wrapper.
            scanStatus,
            // Real desde que se quitó --open: con él, nmap no llegaba a emitir <extraports>.
            filteredPorts:  nmapScan ? nmapScan.filteredCount  : null,
            filteredReason: nmapScan ? nmapScan.filteredReason : null,
            // PTR del objetivo. Null si no tiene: el dashboard no pinta la píldora, en vez de un
            // guion que se leería como "se comprobó y no tiene nombre".
            hostname:       nmapScan ? nmapScan.hostname : null,
            // Target y rango exactos para poder reproducirlo: un `nmap localhost` a mano escanea
            // el top-1000 de nmap, que es otro conjunto, y puede dar otra cosa.
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

        const maxSev = summary.maxSeverity || "info";
        const statusColor =
          maxSev === "critical" || maxSev === "high" ? "red"
          : maxSev === "medium"                      ? "yellow"
          :                                            "green";

        // No puede decir "0 puertos · riesgo: info" cuando no se auditó nada: mismo falso verde.
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
