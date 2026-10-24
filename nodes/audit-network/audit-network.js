"use strict";

// Nodo audit-network. Nmap es obligatorio: si falta se emite NET-DEP-NMAP en vez de fallar.
// En el equipo local hacen falta proceso, PID y bind para separar loopback de expuesto.

const os = require("os");
const { PORT_CATALOG }            = require("./modules/port-catalog");
const { runNmap }                 = require("./modules/nmap-wrapper");
const { checkHostReachable, deriveTargetState } = require("./modules/host-discovery");
const { enrichPorts, detectFirewall } = require("./modules/service-detect");
const { isLocalTarget, validateTarget, validatePortSpec, scanTimeoutMs, getFixForPort } = require("./modules/network-utils");
const { detectPackageManager }   = require("../../lib/pkg-manager");
const { commandExists }           = require("../../lib/executor");
const { scriptExists, scriptStates } = require("./modules/nse-scripts");
const { runCanary, canaryIsOk }   = require("./modules/vulners-canary");
const { summarizePort }           = require("./modules/nse-extract");
const { hasVersion }              = require("./modules/nse-catalog");
const { normalizeNetwork }        = require("../../lib/normalizer");
const { summarize }               = require("../../lib/severity-map");
const { createFinding }           = require("../../lib/finding-schema");

// Instrucciones concretas por sistema; en Linux van los tres gestores porque no se sondea la distribución.
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
      // En modo personalizado lo que llega a nmap es la lista normalizada, nunca el texto del campo.
      const portCheck      = validatePortSpec(config.customPorts);
      const customPorts    = portCheck.ok ? portCheck.spec : "";
      // Quien decide si el objetivo es válido es validateTarget(), no el formulario del editor.
      const wantsCustom    = config.scanTarget === "custom";
      const targetCheck    = wantsCustom ? validateTarget(config.customTarget) : { ok: true, ip: "127.0.0.1" };
      const target         = targetCheck.ok ? targetCheck.ip : null;
      // Para equipos encendidos que filtran el descubrimiento (-sn).
      const forceScan      = config.forceScan === true || config.forceScan === "true";

      // NSE apagado por defecto: los scripts hablan con el servicio, vulners sale a internet y alarga el escaneo.
      const nseEnabled = config.nseEnabled === true || config.nseEnabled === "true";
      // Tiempo extra para los scripts; se suma al del modo para no recortar el escaneo de puertos.
      const nseTimeout = Math.max(0, parseInt(config.nseTimeout, 10) || 180000);

      const startTime = Date.now();

      // Configuración inválida: un único NET-CFG-ERR y no se lanza nmap. extraMeta solo añade campos.
      function sendConfigError({ title, evidence, fix, extraMeta = {} }) {
        const errFinding = createFinding({
          id:       "NET-CFG-ERR",
          title,
          severity: "medium",
          evidence,
          fix,
          category: "network",
          source:   "native",
        });
        msg.payload = {
          findings:  [errFinding],
          summary:   summarize([errFinding]),
          source:    "audit-network",
          auditType: "network",
          host: { hostname: os.hostname(), platform: process.platform },
          scanMeta: { modulesRun: [], portSource: "none", portsScanned: 0, portsOpen: 0, durationMs: 0, scanMode, ...extraMeta },
          raw:       { ports: [] },
          timestamp: new Date().toISOString(),
        };
        node.status({ fill: "yellow", shape: "ring", text: "Configuración incorrecta" });
        send(msg);
        done();
      }

      try {
        if (!targetCheck.ok) {
          // Texto libre del usuario: se recorta porque acaba en el panel y en el informe.
          const escrito = String(config.customTarget == null ? "" : config.customTarget).trim().slice(0, 80);
          sendConfigError({
            title:    "Configuración incorrecta: la dirección del equipo no es válida",
            evidence: `${targetCheck.reason}` + (escrito ? ` Valor indicado: «${escrito}».` : "") +
                      " No se ha escaneado nada: la ausencia de puertos NO significa que el equipo esté protegido.",
            fix:      "Indica en el nodo audit-network la dirección IPv4 de un único equipo. Ejemplo: 192.168.1.10\n" +
                      "Para auditar este mismo equipo, elige \"Este equipo\" en Objetivo.",
            extraMeta: { scanStatus: "not-run", target: null, customTarget: null },
          });
          return;
        }

        // La lista acaba en la línea de nmap: si no es válida, no se escanea.
        if (scanMode === "custom" && !portCheck.ok) {
          if (portCheck.empty) {
            sendConfigError({
              title:    "Configuración incorrecta: lista de puertos vacía",
              evidence: "El modo personalizado requiere una lista de puertos.",
              fix:      "Configura los puertos en el nodo audit-network. Ejemplo: 22,80,443",
            });
          } else {
            sendConfigError({
              title:    "Configuración incorrecta: la lista de puertos no es válida",
              evidence: `${portCheck.reason} No se ha escaneado nada: la ausencia de puertos NO ` +
                        "significa que el equipo esté protegido.",
              fix:      "Indica en el nodo audit-network puertos del 1 al 65535 separados por comas, " +
                        "y rangos con guion. Ejemplo: 22,80,443,8000-8080",
              extraMeta: { scanStatus: "not-run" },
            });
          }
          return;
        }

        let openPorts  = [];
        let portSource = "none";
        const modulesRun = [];
        // Escaneo completo frente a no concluyente; si el host existe lo dice el descubrimiento.
        let nmapScan = null;
        let scanInconclusive = false;
        // Que falte nmap es una dependencia del SO, no un error del nodo: sale como hallazgo.
        let nmapMissing = false;
        let nmapError   = null;

        // Estado del análisis NSE para el informe (null = NSE no pedido).
        let nseAvailability = null;   // { checked, available:Set, missing:[], reason }
        let nseCanary       = null;   // { state, detail, probed, evidence }

        // El escaneo va con -Pn y siempre dice "host up": si el objetivo existe lo decide este paso.
        const targetIsLocal = isLocalTarget(target);
        node.status({ fill: "blue", shape: "dot", text: targetIsLocal ? "Escaneando..." : "Comprobando el equipo..." });
        const discovery = await checkHostReachable({ target, isLocal: targetIsLocal });
        if (discovery.method === "nmap-sn") {
          modulesRun.push("host-discovery");
          node.log(`[audit-network] descubrimiento: ${discovery.detail}`);
        }

        // Con 'unknown' se escanea igual y se avisa: mejor un escaneo de más que cancelar por error.
        const targetState = deriveTargetState(discovery);

        // Sin forzar no se escanea: cero hallazgos aquí es "no analizado", no "limpio".
        const skipScan = targetState === "unreachable" && !forceScan;

        if (skipScan) {
          node.log(`[audit-network] ${target} no alcanzable: se omite el escaneo de puertos`);
          portSource = "none";
        } else {
          try {
            node.status({ fill: "blue", shape: "dot", text: "Escaneando..." });
            // No se usa --host-timeout: cortaría antes de los puertos altos y daría un falso 0.
            const nmapTimeout = scanTimeoutMs(scanMode, portCheck.ok ? portCheck.count : 0) +
                                (nseEnabled ? nseTimeout : 0);

            // Un script inexistente aborta todo el escaneo, así que solo se piden los instalados.
            // Si no se puede preguntar, se escanea sin scripts y checked=false llega al informe.
            let nseScripts = [];
            if (nseEnabled) {
              node.status({ fill: "blue", shape: "dot", text: "Comprobando scripts..." });
              const nmapPath = await commandExists("nmap");
              if (nmapPath) {
                nseAvailability = await scriptExists(nmapPath);
                nseScripts = [...nseAvailability.available];
                if (nseAvailability.missing.length) {
                  node.warn(`[audit-network] scripts NSE no instalados: ${nseAvailability.missing.join(", ")}`);
                }
                node.log(`[audit-network] NSE: ${nseScripts.length} script(s) disponibles`);
              } else {
                nseAvailability = { checked: false, available: new Set(), missing: [],
                                    reason: "no se encontró el comando nmap para preguntarle" };
              }
            }

            node.status({ fill: "blue", shape: "dot", text: "Escaneando..." });
            const nmapResult = await runNmap({ target, scanMode, customPorts, timeout: nmapTimeout, nseScripts });
            if (!nmapResult.skipped) {
              openPorts  = nmapResult.ports;
              portSource = "nmap";
              nmapScan   = nmapResult.scan || null;
              modulesRun.push("nmap");
              node.log("[audit-network] escáner: nmap");
            } else if (nmapResult.inconclusive) {
              // nmap está, pero el escaneo no terminó; el aviso se añade más abajo.
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

        // Solo en local: lsof y netstat miran este equipo, no el objetivo remoto.
        let ports = openPorts;
        if (openPorts.length > 0 && targetIsLocal) {
          try {
            ports = await enrichPorts(openPorts);
            modulesRun.push("service-detect");
          } catch (err) {
            node.warn(`[audit-network] service-detect falló: ${err.message}`);
          }
        }

        // El gestor decide el nombre de la unidad systemd del fix (ssh en Debian, sshd en Arch/Fedora).
        let pkgManager = null;
        if (targetIsLocal && process.platform === "linux" && ports.length > 0) {
          try { pkgManager = await detectPackageManager("linux"); } catch (_) { pkgManager = null; }
          for (const p of ports) {
            const guia = getFixForPort(p.port, process.platform, pkgManager);
            if (guia) p.fix = guia;
          }
        }

        // Los fixes solo proponen reglas del firewall que esté detectado y activo.
        let firewall = null;
        if (targetIsLocal && openPorts.length > 0) {
          try {
            firewall = await detectFirewall();
          } catch (err) {
            // No tumba la auditoría, pero tampoco puede leerse como "sin cortafuegos".
            firewall = { name: null, active: null, error: String((err && err.message) || err) };
          }
        }

        // Primero el canario sobre todos los puertos (es del escaneo entero) y luego el resumen por puerto.
        if (nseEnabled) {
          // Sin escaneo el canario debe quedar 'not-run', no "no hacía falta".
          nseCanary = runCanary(ports, { hasVersion, nseEnabled: !skipScan });
          const canaryOk = canaryIsOk(nseCanary.state);
          for (const p of ports) {
            p.nseSummary = summarizePort(p, { canaryOk, states: scriptStates(p, nseAvailability) });
          }
          node.log(`[audit-network] canario de vulners: ${nseCanary.state}`);
        }

        const findings = normalizeNetwork(ports, "nmap", {
          firewall, targetIsLocal, target, pkgManager,
          nse: nseEnabled
            ? {
                enabled: true,
                availability: nseAvailability && {
                  checked: nseAvailability.checked,
                  missing: nseAvailability.missing,
                  reason:  nseAvailability.reason || null,
                },
                canary: nseCanary,
              }
            : { enabled: false },
        });

        // Sin nmap el resultado vacío no es "sin puertos": el hallazgo va delante para no pintar verde.
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

        // Cero puertos solo vale si el objetivo existe (targetState) y el escaneo terminó (scanStatus).
        let scanStatus = skipScan ? "not-run" : "ok";

        if (targetState === "unreachable") {
          // 'info' porque es ausencia de auditoría, no riesgo; el estado neutro lo pinta targetState.
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
            // Sin numerar: la lista del dashboard ya numera. Las líneas "$ " se pintan como orden.
            fix:      "Comprueba que el equipo está encendido y conectado a la red.\n" +
                      `Verifica que la dirección IP es correcta: ${target}\n` +
                      "Si usas VPN, comprueba que no desvía por el túnel el tráfico de tu red local.\n" +
                      "Prueba a contactarlo desde una terminal:\n" +
                      `$ ping ${target}\n` +
                      (skipScan
                        ? "Si sabes que está encendido y solo filtra el descubrimiento, activa " +
                          "\"Escanear aunque el equipo no responda\" en el nodo audit-network."
                        : "Si el equipo está encendido, revisa su cortafuegos: está filtrando " +
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
            fix:      "El equipo puede tener un cortafuegos que hace esperar a cada puerto filtrado. " +
                      "Repite la auditoría con el modo Rápido o con un rango de puertos personalizado " +
                      "más pequeño. Si tienes activado el análisis NSE, también puedes subir su tiempo extra.",
            category: "network",
            source:   "nmap",
          }));
        } else if (targetState === "unknown" && !targetIsLocal && !nmapMissing) {
          // No se supo si el objetivo existe; se escaneó igual, pero no se pinta verde.
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
            // El conjunto real está en portRange.
            portsScanned: null,
            portsOpen:    openPorts.length,
            durationMs,
            scanMode,
            // Según host-discovery; con él decide el dashboard si puede pintar verde.
            targetState,
            discovery: {
              method:     discovery.method,
              reason:     discovery.reason,
              durationMs: discovery.durationMs,
              cmd:        discovery.cmd,
              detail:     discovery.detail,
              // Si el "accesible" lo confirmó el ping del sistema, y con qué orden.
              confirmedBy: discovery.confirmedBy || null,
              pingCmd:     discovery.pingCmd || null,
            },
            forceScan,
            scanStatus,
            // Sin --open para que nmap emita <extraports>.
            filteredPorts:  nmapScan ? nmapScan.filteredCount  : null,
            filteredReason: nmapScan ? nmapScan.filteredReason : null,
            // PTR del objetivo; null si no tiene, y el dashboard no pinta la píldora.
            hostname:       nmapScan ? nmapScan.hostname : null,
            // Objetivo y rango exactos para reproducirlo (un `nmap` a mano usa otro conjunto).
            target,
            portRange:
              nmapScan && nmapScan.portSpec
                ? nmapScan.portSpec
                : scanMode === "custom"
                ? customPorts.trim()
                : `1-1024 + catálogo (${Object.keys(PORT_CATALOG).length} puertos conocidos)`,
            customTarget: target !== "127.0.0.1" ? target : null,
            // Duplica a propósito los hallazgos de omisión para el dashboard y el JSON exportado.
            nse: {
              enabled: nseEnabled,
              // Array ordenado porque un Set se serializa a {}. Vacío con enabled=true es un hueco.
              scriptsRequested: nseAvailability ? [...nseAvailability.available].sort() : [],
              scriptsMissing:   nseAvailability ? nseAvailability.missing : [],
              // false = ni siquiera se pudo preguntar qué hay instalado.
              availabilityChecked: nseAvailability ? nseAvailability.checked : null,
              availabilityReason:  (nseAvailability && nseAvailability.reason) || null,
              // probed es siempre false: LoCoAudit no consulta vulners.com por su cuenta.
              canary: nseCanary
                ? { state: nseCanary.state, probed: nseCanary.probed, detail: nseCanary.detail }
                : null,
              // Tiempo extra de los scripts, para poder explicar un timeout.
              timeoutMs: nseEnabled ? nseTimeout : 0,
            },
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
            : `${openPorts.length} ${openPorts.length === 1 ? "puerto abierto" : "puertos abiertos"} · riesgo: ${maxSev}`,
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
