"use strict";

// Nodo audit-network. Nmap es obligatorio: si falta o no puede ejecutarse el nodo falla, como audit-host con Lynis.
// En el equipo local hacen falta proceso, PID y bind para separar loopback de expuesto.

const os = require("os");
const { PORT_CATALOG }            = require("./modules/port-catalog");
const { ejecutarNmap }                 = require("./modules/nmap-wrapper");
const { comprobarAlcance, deducirEstadoObjetivo } = require("./modules/host-discovery");
const { completarPuertos, detectarFirewall } = require("./modules/service-detect");
const { esObjetivoLocal, validarObjetivo, validarPuertos, tiempoMaximoEscaneo, solucionPorPuerto } = require("./modules/network-utils");
const { detectarGestor }   = require("../../lib/pkg-manager");
const { existeComando }           = require("../../lib/executor");
const { existeScript, estadoScripts } = require("./modules/nse-scripts");
const { ejecutarCanario, canarioCorrecto }   = require("./modules/vulners-canary");
const { resumirPuerto }           = require("./modules/nse-extract");
const { tieneVersion }              = require("./modules/nse-catalog");
const { normalizarRed }        = require("../../lib/normalizer");
const { resumir }               = require("../../lib/severity-map");
const { crearHallazgo }           = require("../../lib/finding-schema");

// Instrucciones concretas por sistema; en Linux van los tres gestores porque no se sondea la distribución.
function instruccionesNmap(platform) {
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
  function NodoAuditoriaRed(config) {
    RED.nodes.createNode(this, config);
    const node = this;

    // Solo para poder elegir el config desde el editor: el chat lo sirve /locoaudit/chat.
    if (config.llmConfig) {
      node.llmConfig = RED.nodes.getNode(config.llmConfig);
    } else {
      node.llmConfig = null;
    }

    node.on("input", async function (msg, send, done) {
      node.status({ fill: "blue", shape: "dot", text: "Escaneando..." });

      const scanMode       = config.scanMode    || "standard";
      // En modo personalizado lo que llega a nmap es la lista normalizada, nunca el texto del campo.
      const portCheck      = validarPuertos(config.customPorts);
      let customPorts;
      if (portCheck.ok) {
        customPorts = portCheck.spec;
      } else {
        customPorts = "";
      }
      // Quien decide si el objetivo es válido es validarObjetivo(), no el formulario del editor.
      const wantsCustom    = config.scanTarget === "custom";
      let targetCheck;
      if (wantsCustom) {
        targetCheck = validarObjetivo(config.customTarget);
      } else {
        targetCheck = { ok: true, ip: "127.0.0.1" };
      }
      let target;
      if (targetCheck.ok) {
        target = targetCheck.ip;
      } else {
        target = null;
      }
      // Para equipos encendidos que filtran el descubrimiento (-sn).
      const forceScan      = config.forceScan === true || config.forceScan === "true";

      // NSE apagado por defecto: los scripts hablan con el servicio, vulners sale a internet y alarga el escaneo.
      const nseEnabled = config.nseEnabled === true || config.nseEnabled === "true";
      // Tiempo extra para los scripts; se suma al del modo para no recortar el escaneo de puertos.
      const nseTimeout = Math.max(0, parseInt(config.nseTimeout, 10) || 180000);

      const startTime = Date.now();

      // Configuración inválida: un único NET-CFG-ERR y no se lanza nmap. extraMeta solo añade campos.
      function enviarErrorConfig({ title, evidence, fix, extraMeta = {} }) {
        const errFinding = crearHallazgo({
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
          summary:   resumir([errFinding]),
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
          let valor;
          if (config.customTarget == null) {
            valor = "";
          } else {
            valor = config.customTarget;
          }
          const escrito = String(valor).trim().slice(0, 80);
          let sufijo;
          if (escrito) {
            sufijo = ` Valor indicado: «${escrito}».`;
          } else {
            sufijo = "";
          }
          enviarErrorConfig({
            title:    "Configuración incorrecta: la dirección del equipo no es válida",
            evidence: `${targetCheck.reason}` + sufijo +
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
            enviarErrorConfig({
              title:    "Configuración incorrecta: lista de puertos vacía",
              evidence: "El modo personalizado requiere una lista de puertos.",
              fix:      "Configura los puertos en el nodo audit-network. Ejemplo: 22,80,443",
            });
          } else {
            enviarErrorConfig({
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
        // Sin nmap no hay escaneo: se avisa al terminar el bloque y el nodo falla sin enviar nada al dashboard.
        let nmapMissing = false;
        let nmapError   = null;

        // Estado del análisis NSE para el informe (null = NSE no pedido).
        let nseAvailability = null;   // { checked, available:Set, missing:[], reason }
        let nseCanary       = null;   // { state, detail, probed, evidence }

        // El escaneo va con -Pn y siempre dice "host up": si el objetivo existe lo decide este paso.
        const targetIsLocal = esObjetivoLocal(target);
        let textoInicial;
        if (targetIsLocal) {
          textoInicial = "Escaneando...";
        } else {
          textoInicial = "Comprobando el equipo...";
        }
        node.status({ fill: "blue", shape: "dot", text: textoInicial });
        const discovery = await comprobarAlcance({ target, isLocal: targetIsLocal });
        if (discovery.method === "nmap-sn") {
          modulesRun.push("host-discovery");
          node.log(`[audit-network] descubrimiento: ${discovery.detail}`);
        }

        // Con 'unknown' se escanea igual y se avisa: mejor un escaneo de más que cancelar por error.
        const targetState = deducirEstadoObjetivo(discovery);

        // Sin forzar no se escanea: cero hallazgos aquí es "no analizado", no "limpio".
        const skipScan = targetState === "unreachable" && !forceScan;

        if (skipScan) {
          node.log(`[audit-network] ${target} no alcanzable: se omite el escaneo de puertos`);
          portSource = "none";
        } else {
          try {
            node.status({ fill: "blue", shape: "dot", text: "Escaneando..." });
            // No se usa --host-timeout: cortaría antes de los puertos altos y daría un falso 0.
            let puertosPedidos;
            if (portCheck.ok) {
              puertosPedidos = portCheck.count;
            } else {
              puertosPedidos = 0;
            }
            let extraNse;
            if (nseEnabled) {
              extraNse = nseTimeout;
            } else {
              extraNse = 0;
            }
            const nmapTimeout = tiempoMaximoEscaneo(scanMode, puertosPedidos) +
                                extraNse;

            // Un script inexistente aborta todo el escaneo, así que solo se piden los instalados.
            // Si no se puede preguntar, se escanea sin scripts y checked=false llega al informe.
            let nseScripts = [];
            if (nseEnabled) {
              node.status({ fill: "blue", shape: "dot", text: "Comprobando scripts..." });
              const nmapPath = await existeComando("nmap");
              if (nmapPath) {
                nseAvailability = await existeScript(nmapPath);
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
            const nmapResult = await ejecutarNmap({ target, scanMode, customPorts, timeout: nmapTimeout, nseScripts });
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

        // Se decide por la causa, no por el texto del error. Un resultado vacío aquí no significaría "sin puertos".
        if (nmapMissing) {
          node.status({ fill: "red", shape: "ring", text: "Nmap no instalado" });
          done(new Error(
            "Nmap no se encontró instalado en el sistema y audit-network lo necesita para escanear los puertos.\n" +
            instruccionesNmap(process.platform)
          ));
          return;
        }
        if (nmapError) {
          node.status({ fill: "red", shape: "ring", text: "Nmap falló" });
          done(new Error(
            `Nmap está instalado pero no pudo completar el escaneo. ${nmapError}\n` +
            "Ejecútalo a mano contra el objetivo para ver dónde falla y vuelve a lanzar la auditoría."
          ));
          return;
        }

        // Solo en local: lsof y netstat miran este equipo, no el objetivo remoto.
        let ports = openPorts;
        if (openPorts.length > 0 && targetIsLocal) {
          try {
            ports = await completarPuertos(openPorts);
            modulesRun.push("service-detect");
          } catch (err) {
            node.warn(`[audit-network] service-detect falló: ${err.message}`);
          }
        }

        // El gestor decide el nombre de la unidad systemd del fix (ssh en Debian, sshd en Arch/Fedora).
        let pkgManager = null;
        if (targetIsLocal && process.platform === "linux" && ports.length > 0) {
          try { pkgManager = await detectarGestor("linux"); } catch (_) { pkgManager = null; }
          for (const p of ports) {
            const guia = solucionPorPuerto(p.port, process.platform, pkgManager);
            if (guia) p.fix = guia;
          }
        }

        // Los fixes solo proponen reglas del firewall que esté detectado y activo.
        let firewall = null;
        if (targetIsLocal && openPorts.length > 0) {
          try {
            firewall = await detectarFirewall();
          } catch (err) {
            // No tumba la auditoría, pero tampoco puede leerse como "sin cortafuegos".
            firewall = { name: null, active: null, error: String((err && err.message) || err) };
          }
        }

        // Primero el canario sobre todos los puertos (es del escaneo entero) y luego el resumen por puerto.
        if (nseEnabled) {
          // Sin escaneo el canario debe quedar 'not-run', no "no hacía falta".
          nseCanary = ejecutarCanario(ports, { hasVersion: tieneVersion, nseEnabled: !skipScan });
          const canaryOk = canarioCorrecto(nseCanary.state);
          for (const p of ports) {
            p.nseSummary = resumirPuerto(p, { canaryOk, states: estadoScripts(p, nseAvailability) });
          }
          node.log(`[audit-network] canario de vulners: ${nseCanary.state}`);
        }

        let nse;
        if (nseEnabled) {
          nse = {
            enabled: true,
            availability: nseAvailability && {
              checked: nseAvailability.checked,
              missing: nseAvailability.missing,
              reason:  nseAvailability.reason || null,
            },
            canary: nseCanary,
          };
        } else {
          nse = { enabled: false };
        }
        const findings = normalizarRed(ports, "nmap", {
          firewall, targetIsLocal, target, pkgManager,
          nse,
        });

        // Cero puertos solo vale si el objetivo existe (targetState) y el escaneo terminó (scanStatus).
        let scanStatus;
        if (skipScan) {
          scanStatus = "not-run";
        } else {
          scanStatus = "ok";
        }

        if (targetState === "unreachable") {
          // 'info' porque es ausencia de auditoría, no riesgo; el estado neutro lo pinta targetState.
          let aviso;
          let consejo;
          if (skipScan) {
            aviso = "No se ha escaneado ningún puerto: la ausencia de hallazgos NO significa " +
                          "que el equipo esté seguro, significa que no se ha podido analizar.";
            consejo = "Si sabes que está encendido y solo filtra el descubrimiento, activa " +
                          "\"Escanear aunque el equipo no responda\" en el nodo audit-network.";
          } else {
            aviso = "Se ha escaneado de todas formas porque está activada la opción " +
                          "\"Escanear aunque el equipo no responda\", pero el resultado puede " +
                          "estar incompleto.";
            consejo = "Si el equipo está encendido, revisa su cortafuegos: está filtrando " +
                          "tanto el descubrimiento como el escaneo.";
          }
          findings.unshift(crearHallazgo({
            id:       "NET-HOST-UNREACHABLE",
            title:    `No se ha podido contactar con ${target}: la auditoría no se ha realizado`,
            severity: "info",
            evidence: `${discovery.detail} ` +
                      aviso,
            // Sin numerar: la lista del dashboard ya numera. Las líneas "$ " se pintan como orden.
            fix:      "Comprueba que el equipo está encendido y conectado a la red.\n" +
                      `Verifica que la dirección IP es correcta: ${target}\n` +
                      "Si usas VPN, comprueba que no desvía por el túnel el tráfico de tu red local.\n" +
                      "Prueba a contactarlo desde una terminal:\n" +
                      `$ ping ${target}\n` +
                      consejo,
            category: "network",
            source:   "nmap",
            target,
            isLocalTarget: targetIsLocal,
          }));
        } else if (scanInconclusive) {
          scanStatus = "inconclusive";
          findings.unshift(crearHallazgo({
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
        } else if (targetState === "unknown" && !targetIsLocal) {
          // No se supo si el objetivo existe; se escaneó igual, pero no se pinta verde.
          findings.unshift(crearHallazgo({
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

        const summary    = resumir(findings);
        const durationMs = Date.now() - startTime;

        let filtrados;
        let motivoFiltrado;
        let nombreHost;
        if (nmapScan) {
          filtrados = nmapScan.filteredCount;
          motivoFiltrado = nmapScan.filteredReason;
          nombreHost = nmapScan.hostname;
        } else {
          filtrados = null;
          motivoFiltrado = null;
          nombreHost = null;
        }
        let rango;
        if (skipScan) {
          // Sin escaneo no hay rango que mostrar: pintar uno sería afirmar algo que no se hizo.
          rango = null;
        } else if (nmapScan && nmapScan.portSpec) {
          rango = nmapScan.portSpec;
        } else if (scanMode === "custom") {
          rango = customPorts.trim();
        } else {
          rango = `1-1024 + catálogo (${Object.keys(PORT_CATALOG).length} puertos conocidos)`;
        }
        let objetivoPropio;
        if (target !== "127.0.0.1") {
          objetivoPropio = target;
        } else {
          objetivoPropio = null;
        }
        let pedidos;
        let ausentes;
        let comprobado;
        if (nseAvailability) {
          pedidos = [...nseAvailability.available].sort();
          ausentes = nseAvailability.missing;
          comprobado = nseAvailability.checked;
        } else {
          pedidos = [];
          ausentes = [];
          comprobado = null;
        }
        let canario;
        if (nseCanary) {
          canario = { state: nseCanary.state, probed: nseCanary.probed, detail: nseCanary.detail };
        } else {
          canario = null;
        }
        let tiempoNse;
        if (nseEnabled) {
          tiempoNse = nseTimeout;
        } else {
          tiempoNse = 0;
        }

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
            filteredPorts:  filtrados,
            filteredReason: motivoFiltrado,
            // PTR del objetivo; null si no tiene, y el dashboard no pinta la píldora.
            hostname:       nombreHost,
            // Objetivo y rango exactos para reproducirlo (un `nmap` a mano usa otro conjunto).
            target,
            portRange:
              rango,
            customTarget: objetivoPropio,
            // Duplica a propósito los hallazgos de omisión para el dashboard y el JSON exportado.
            nse: {
              enabled: nseEnabled,
              // Array ordenado porque un Set se serializa a {}. Vacío con enabled=true es un hueco.
              scriptsRequested: pedidos,
              scriptsMissing:   ausentes,
              // false = ni siquiera se pudo preguntar qué hay instalado.
              availabilityChecked: comprobado,
              availabilityReason:  (nseAvailability && nseAvailability.reason) || null,
              // probed es siempre false: LoCoAudit no consulta vulners.com por su cuenta.
              canary: canario,
              // Tiempo extra de los scripts, para poder explicar un timeout.
              timeoutMs: tiempoNse,
            },
          },
          raw: { ports },
          timestamp: new Date().toISOString(),
        };

        const maxSev = summary.maxSeverity || "info";
        let statusColor;
        if (maxSev === "critical" || maxSev === "high") {
          statusColor = "red";
        } else if (maxSev === "medium") {
          statusColor = "yellow";
        } else {
          statusColor = "green";
        }

        // No puede decir "0 puertos · riesgo: info" cuando no se auditó nada: mismo falso verde.
        let color;
        if (targetState === "unreachable") {
          color = "grey";
        } else if (targetState === "unknown") {
          color = "yellow";
        } else {
          color = statusColor;
        }
        let forma;
        if (targetState !== "reachable") {
          forma = "ring";
        } else {
          forma = "dot";
        }
        let textoEstado;
        if (targetState === "unreachable") {
          textoEstado = `${target} no accesible — sin auditar`;
        } else if (scanStatus === "inconclusive") {
          textoEstado = "escaneo no concluyente";
        } else if (targetState === "unknown") {
          textoEstado = `${openPorts.length} puertos · accesibilidad sin confirmar`;
        } else {
          let etiqueta;
          if (openPorts.length === 1) {
            etiqueta = "puerto abierto";
          } else {
            etiqueta = "puertos abiertos";
          }
          textoEstado = `${openPorts.length} ${etiqueta} · riesgo: ${maxSev}`;
        }
        node.status({
          fill:  color,
          shape: forma,
          text:  textoEstado,
        });

        send(msg);
        done();
      } catch (err) {
        node.status({ fill: "red", shape: "ring", text: "Error" });
        done(err);
      }
    });
  }

  RED.nodes.registerType("audit-network", NodoAuditoriaRed);
};
