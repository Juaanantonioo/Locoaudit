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
const { isLocalTarget, validateTarget, validatePortSpec, scanTimeoutMs } = require("./modules/network-utils");
const { commandExists }           = require("../../lib/executor");
const { scriptExists, scriptStates } = require("./modules/nse-scripts");
const { runCanary, canaryIsOk }   = require("./modules/vulners-canary");
const { summarizePort }           = require("./modules/nse-extract");
const { hasVersion }              = require("./modules/nse-catalog");
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
      // En modo personalizado lo que llega a nmap es la lista normalizada, nunca el texto del campo.
      const portCheck      = validatePortSpec(config.customPorts);
      const customPorts    = portCheck.ok ? portCheck.spec : "";
      // "Otro equipo de mi red" exige una IPv4 válida de un equipo. Antes, un campo vacío caía
      // en silencio a 127.0.0.1 (el usuario pedía otro equipo y se auditaba este) y cualquier
      // texto llegaba tal cual a la línea de nmap, rangos incluidos. La regla vive en
      // validateTarget(); aquí solo se aplica.
      const wantsCustom    = config.scanTarget === "custom";
      const targetCheck    = wantsCustom ? validateTarget(config.customTarget) : { ok: true, ip: "127.0.0.1" };
      const target         = targetCheck.ok ? targetCheck.ip : null;
      // Para el caso legítimo: equipo encendido que filtra ICMP y las sondas TCP del -sn.
      const forceScan      = config.forceScan === true || config.forceScan === "true";

      /**
       * Análisis NSE: APAGADO por defecto, y el defecto se decide aquí una vez.
       *
       * Apagado porque cambia lo que la auditoría le hace a un tercero. El escaneo de puertos
       * pregunta "¿estás abierto?"; los scripts dialogan con el servicio y, en el caso de
       * vulners, mandan la versión detectada a un servidor de internet. Eso es una cesión de
       * datos y una interacción más larga con el equipo auditado, y ninguna de las dos se activa
       * sin que alguien lo haya leído y marcado.
       *
       * Apagado también porque el escaneo tarda bastante más, y quien solo quiere saber qué
       * puertos tiene abiertos no debería pagarlo.
       */
      const nseEnabled = config.nseEnabled === true || config.nseEnabled === "true";
      // Tiempo EXTRA para los scripts, no el total. Se suma al presupuesto del modo en vez de
      // sustituirlo: los límites de scanTimeoutMs() están calibrados para lo que tarda `-sV` sobre puertos
      // filtrados, y meter los scripts dentro de ese mismo margen recortaría el escaneo de
      // puertos —que es la función principal— para pagar una opcional.
      const nseTimeout = Math.max(0, parseInt(config.nseTimeout, 10) || 180000);

      const startTime = Date.now();

      // Una configuración que no permite auditar: un único hallazgo NET-CFG-ERR y nada de nmap.
      // El payload es el que ya se emitía para la lista de puertos vacía; `extraMeta` solo añade
      // campos, para que ese caso siga saliendo byte a byte igual que antes.
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
          // Lo que escribió el usuario se recorta antes de devolverlo: es texto libre y va a
          // parar al panel y al informe exportado.
          const escrito = String(config.customTarget == null ? "" : config.customTarget).trim().slice(0, 80);
          sendConfigError({
            title:    "Configuración incorrecta: la dirección del equipo no es válida",
            evidence: `${targetCheck.reason}` + (escrito ? ` Valor indicado: «${escrito}».` : "") +
                      " No se ha escaneado nada: la ausencia de puertos NO significa que el equipo esté protegido.",
            fix:      "Indica en el nodo audit-network la dirección IPv4 de un único equipo. Ejemplo: 192.168.1.10\n" +
                      "Para auditar este mismo equipo, elige \"Este equipo\" en Objetivo.",
            // scanStatus 'not-run' con el mismo significado que ya tiene: no se escaneó.
            extraMeta: { scanStatus: "not-run", target: null, customTarget: null },
          });
          return;
        }

        // Misma regla que con la IP: la lista va a la línea de nmap, así que lo que no es una
        // lista de puertos no se escanea. La vacía conserva su hallazgo de siempre.
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
        // Separa "escaneo completo" de "no concluyente" (timeout, proceso cortado). Ya no dice
        // si el host existe: eso lo decide el descubrimiento previo.
        let nmapScan = null;
        let scanInconclusive = false;
        // Que falte nmap no es un error del nodo sino una dependencia del SO: sale como finding.
        let nmapMissing = false;
        let nmapError   = null;

        // Lo que se sabrá del análisis NSE al final. Se declara aquí, con el resto del estado del
        // escaneo, porque el informe tiene que poder decir "no se hizo" con la misma seguridad
        // con la que dice "se hizo": null sería un cuarto estado sin significado.
        let nseAvailability = null;   // { checked, available:Set, missing:[], reason }
        let nseCanary       = null;   // { state, detail, probed, evidence }

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
            // Por modo y por número de puertos, según el tiempo medido sobre un host filtrado,
            // donde cada puerto filtrado añade espera (ver scanTimeoutMs). No se usa
            // --host-timeout de nmap: cortaría antes de sondear los puertos altos y daría un
            // falso 0. Pasado este límite, "no concluyente".
            // Presupuesto del modo MÁS el de los scripts. Quien no activa NSE suma 0.
            const nmapTimeout = scanTimeoutMs(scanMode, portCheck.ok ? portCheck.count : 0) +
                                (nseEnabled ? nseTimeout : 0);

            /**
             * Qué scripts pedirle a ESTE nmap.
             *
             * No se pasa la lista a ciegas: `nmap --script a,b,c` con un solo nombre que no
             * existe aborta la ejecución entera y devuelve cero puertos. O sea que un nmap
             * recortado —el `nmap-common` de Debian, sin la colección de scripts— convertiría
             * activar esta opción en perder el escaneo completo. Se pregunta antes y se manda
             * solo lo que hay.
             *
             * Y si no se puede ni preguntar, se escanea SIN scripts: el escaneo de puertos es la
             * función principal y no se arriesga por una opcional. Lo que no se hace es callarlo:
             * `nseAvailability.checked === false` llega al informe como omisión.
             */
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

        /**
         * El veredicto sobre la fuente de CVE, y con él el resumen NSE de cada puerto.
         *
         * ORDEN OBLIGADO: primero el canario sobre TODOS los puertos, después el resumen de cada
         * uno. El canario es una propiedad del escaneo entero —si un solo puerto recibió datos de
         * vulners, la fuente respondió para todos—, así que resolverlo puerto a puerto daría
         * "limpio" a unos y "sin comprobar" a otros dentro de la misma ejecución, según el orden
         * del bucle.
         */
        if (nseEnabled) {
          // `!skipScan` en el estado del canario: con el objetivo no alcanzable no se escaneó
          // nada, y decir "no hacía falta comprobar la fuente" sobre cero puertos daría por
          // resuelto lo que ni se intentó. El estado correcto ahí es 'not-run'.
          nseCanary = runCanary(ports, { hasVersion, nseEnabled: !skipScan });
          const canaryOk = canaryIsOk(nseCanary.state);
          for (const p of ports) {
            p.nseSummary = summarizePort(p, { canaryOk, states: scriptStates(p, nseAvailability) });
          }
          node.log(`[audit-network] canario de vulners: ${nseCanary.state}`);
        }

        const findings = normalizeNetwork(ports, "nmap", {
          firewall, targetIsLocal, target,
          // Solo viaja cuando el análisis se pidió. Sin esta clave el normalizador devuelve
          // exactamente los hallazgos de siempre, sin una línea de más.
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
            // Sin "1." … "5.": la numeración la pone la lista del dashboard, y escribirla
            // aquí producía dos numeraciones superpuestas. El ping va en su línea "$ ".
            fix:      "Comprueba que el equipo está encendido y conectado a la red.\n" +
                      `Verifica que la dirección IP es correcta: ${target}\n` +
                      "Si usas VPN, confirma que el túnel está activo y enruta esa subred.\n" +
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
              // Si el "accesible" lo dio el ping del sistema y no Nmap, y con qué orden.
              confirmedBy: discovery.confirmedBy || null,
              pingCmd:     discovery.pingCmd || null,
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
            /**
             * El estado del análisis NSE, en estructurado.
             *
             * Duplica lo que ya dicen los hallazgos de omisión, y a propósito: son dos lectores
             * distintos. Los hallazgos los lee una persona en el panel y en el informe; esto lo
             * lee el dashboard para decidir si puede pintar verde, y el JSON exportado para que
             * otra herramienta sepa qué cubrió esta ejecución. La regla del proyecto es que el
             * estado de la comprobación viaje aparte del resultado de la comprobación.
             *
             * `available` sale como array ordenado y no como Set: un Set se serializa a {} y el
             * campo llegaría vacío al informe sin que falle nada.
             */
            nse: {
              enabled: nseEnabled,
              // Qué se le llegó a pedir a nmap. Con la lista vacía y enabled=true, el escaneo se
              // lanzó sin scripts: eso es un hueco, no un "sin hallazgos".
              scriptsRequested: nseAvailability ? [...nseAvailability.available].sort() : [],
              scriptsMissing:   nseAvailability ? nseAvailability.missing : [],
              // false = ni siquiera se pudo preguntar qué hay instalado.
              availabilityChecked: nseAvailability ? nseAvailability.checked : null,
              availabilityReason:  (nseAvailability && nseAvailability.reason) || null,
              // El estado de la fuente de CVE y su explicación para el informe. `probed` vale
              // siempre false: LoCoAudit no consulta vulners.com por su cuenta, y poder afirmarlo
              // vale más que dejarlo implícito.
              canary: nseCanary
                ? { state: nseCanary.state, probed: nseCanary.probed, detail: nseCanary.detail }
                : null,
              // Tiempo EXTRA concedido a los scripts, para poder explicar un timeout.
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
