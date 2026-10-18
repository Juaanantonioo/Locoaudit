"use strict";

/** Nodo audit-host: lanza los módulos de host en paralelo y emite findings normalizados. */

const { runSystemModule } = require("./modules/cpu-memory");
const { getDiskInfo } = require("./modules/disk-storage");
const { getSwInventory } = require("./modules/sw-inventory");
const { getOsInfo } = require("./modules/os-info");
const { runLynis } = require("./modules/lynis");
const { runTrivyFs, runTrivySecrets } = require("./modules/trivy-fs");
const { runTrivyRootfs, systemPackagesSupport } = require("../../lib/trivy-rootfs");
const { runSecurityEvents, buildEventList } = require("./modules/security-events");
const { getPendingUpdates } = require("./modules/pending-updates");
const { normalizeHost, esNoAplica, buildSkippedChecksSummary, lynisCoverage } = require("../../lib/normalizer");
const { detectPackageManager, managerLabel } = require("../../lib/pkg-manager");
const { commandExists } = require("../../lib/executor");
const { summarize } = require("../../lib/severity-map");

/**
 * Avisa de un módulo omitido con el nivel que corresponde a su motivo. `node.warn` pinta en amarillo, y para casos
 * 'not-applicable' (Trivy en macOS) contradiría al informe. El criterio es `esNoAplica()`, el mismo del finding y del estado del módulo.
 */
function avisarOmitido(node, modulo, res) {
  const kind = res && res.kind;
  const texto = `[audit-host] ${modulo} omitido: ${res && res.reason}`;
  // 'disabled' lo decidió el usuario y 'no aplica' es un límite del sistema: ninguno es un
  // problema del que haya que avisar en amarillo.
  if (kind === "disabled" || esNoAplica(kind)) node.log(texto);
  else node.warn(texto);
}

/** Cuántos paquetes inventarió sw-inventory. El módulo devuelve un array plano, o un objeto con
 *  `packages` cuando el inventario salió parcial (macOS con brew caído). */
function swPackageCount(sw) {
  if (Array.isArray(sw)) return sw.length;
  if (sw && Array.isArray(sw.packages)) return sw.packages.length;
  return null;
}

/** Con qué herramienta los contó ('dpkg', 'rpm', 'brew'…). Cada entrada trae la suya; se toma la
 *  de la primera porque todas las de un inventario vienen del mismo sitio. */
function swPackageSource(sw) {
  const list = Array.isArray(sw) ? sw : (sw && sw.packages) || [];
  return (list[0] && list[0].source) || null;
}

module.exports = function (RED) {
  function AuditHostNode(config) {
    RED.nodes.createNode(this, config);
    const node = this;

    // Solo para poder elegir el config desde el editor: el chat lo sirve /locoaudit/chat.
    node.llmConfig = config.llmConfig ? RED.nodes.getNode(config.llmConfig) : null;

    node.on("input", async function (msg, send, done) {
      node.status({ fill: "blue", shape: "dot", text: "Auditando..." });

      const enableCpu = config.enableCpu !== false;
      const enableDisk = config.enableDisk !== false;
      const enableSw = config.enableSw !== false;
      const enableLynis = config.enableLynis !== false;
      const enableTrivy = config.enableTrivy !== false;
      const enableSecEvents = config.securityEvents !== false;
      const enableUpdates = config.enableUpdates !== false;
      const enableSecrets = config.enableSecrets !== false;
      const secWindow = Math.min(168, Math.max(1, parseInt(config.securityEventsWindow, 10) || 24));
      // Activo POR DEFECTO, al revés que antes: los paquetes del sistema son la parte del
      // equipo que el usuario no puede auditar por su cuenta, y dejarlos fuera por omisión
      // producía informes que parecían completos y no lo eran. La casilla ahora DESACTIVA.
      const enableSysPkgs = config.trivySystemPkgs !== false;

      const startTime = Date.now();

      try {
        // Sin esto los fixes daban apt en Linux y brew en macOS, y en Arch el comando no se podía ejecutar.
        // Siempre, aunque los paquetes del sistema estén apagados: cuesta un commandExists por candidato
        // y el bloque de alcance del dashboard lo necesita.
        let pkgManager = null;
        try {
          pkgManager = await detectPackageManager(process.platform);
        } catch (_) { /* la detección no puede tumbar la auditoría */ }

        // trivy-rootfs comprueba aquí que Trivy está, y no dentro del módulo: la regla es que el
        // commandExists vive en el despacho. trivy-fs conserva el suyo porque audit-image también
        // le llama y ese camino no pasa por aquí.
        const trivyPath = enableSysPkgs ? await commandExists("trivy") : null;

        const [cpuResult, diskResult, swResult, lynisResult, trivyResult, rootfsResult, secResult, updResult, secretsResult] =
          await Promise.allSettled([
            enableCpu ? Promise.resolve(runSystemModule()) : Promise.resolve(null),
            enableDisk ? getDiskInfo() : Promise.resolve(null),
            enableSw ? getSwInventory() : Promise.resolve(null),
            enableLynis
              ? runLynis()
              // `kind: "disabled"` explícito: un módulo que apagó el usuario NO es una
              // comprobación caída, y el dashboard tiene que poder separarlos sin
              // olfatear el texto de `reason`.
              : Promise.resolve({ skipped: true, kind: "disabled", reason: "El análisis de hardening del sistema está desactivado en las opciones del nodo." }),
            enableTrivy
              // Vacío ⇒ el HOME de quien audita. Solo el HOME: los paquetes del sistema son ahora
              // el módulo de al lado y ya no viajan dentro de este resultado.
              ? runTrivyFs({ target: config.trivyTarget, pkgManager })
              : Promise.resolve({ skipped: true, kind: "disabled", reason: "El análisis de vulnerabilidades de tu carpeta personal está desactivado en las opciones del nodo." }),
            !enableSysPkgs
              ? Promise.resolve({ skipped: true, kind: "disabled", reason: "El análisis de los paquetes del sistema está desactivado en las opciones del nodo." })
              : !trivyPath
              ? Promise.resolve({ skipped: true, kind: "not-installed", reason: "Trivy no está instalado, y es lo que lee la base de datos de paquetes del sistema." })
              : runTrivyRootfs(),
            enableSecEvents ? runSecurityEvents(secWindow) : Promise.resolve(null),
            // pkgManager por parámetro: audit-host ya lo resolvió arriba y es la fuente única.
            enableUpdates ? getPendingUpdates({ pkgManager }) : Promise.resolve(null),
            // Mismo ámbito que el análisis de vulnerabilidades, en una pasada aparte con su propio estado.
            enableSecrets
              ? runTrivySecrets({ target: config.trivyTarget })
              : Promise.resolve({ skipped: true, kind: "disabled", reason: "La búsqueda de secretos y configuraciones inseguras está desactivada en las opciones del nodo." }),
          ]);

        const cpuMemory = cpuResult.status === "fulfilled" ? cpuResult.value : null;
        const disk = diskResult.status === "fulfilled" ? diskResult.value : null;
        const swInventory = swResult.status === "fulfilled" ? swResult.value : null;
        const lynis = lynisResult.status === "fulfilled" ? lynisResult.value : null;
        const trivy = trivyResult.status === "fulfilled" ? trivyResult.value : null;
        const trivyRootfs = rootfsResult.status === "fulfilled" ? rootfsResult.value : null;
        const securityEvents = secResult.status === "fulfilled" ? secResult.value : null;
        const pendingUpdates = updResult.status === "fulfilled" ? updResult.value : null;

        // Un throw vale lo mismo que un skipped kind 'error'. Antes iba al revés: el throw dejaba
        // lynis a null y la auditoría seguía, y el skipped limpio la abortaba.
        const lynisResolved = lynis || (
          lynisResult.status === "rejected" && enableLynis
            ? { skipped: true, kind: "error", reason: String(lynisResult.reason) }
            : null
        );

        if (enableLynis && lynisResolved && lynisResolved.skipped) {
          // Por kind, nunca por el texto de reason: interpola mensajes del SO y cambia de plataforma,
          // que es lo que rompía la comparación de strings en el gate de Trivy.
          if (lynisResolved.kind === "not-installed") {
            node.status({ fill: "red", shape: "ring", text: "Lynis no instalado" });
            done(new Error(
              "Lynis está activado en la configuración del nodo pero no se encontró instalado en el sistema. " +
              "Instala Lynis (https://cisofy.com/lynis/) o desactiva el módulo en las opciones del nodo."
            ));
            return;
          }
          if (lynisResolved.kind === "timeout") {
            node.status({ fill: "red", shape: "ring", text: "Lynis agotó el tiempo" });
            done(new Error(
              `Lynis no terminó a tiempo. ${lynisResolved.reason}. ` +
              "Ejecútalo a mano para ver dónde se detiene, o desactiva el módulo en las opciones del nodo."
            ));
            return;
          }
          if (lynisResolved.kind === "error") {
            node.status({ fill: "red", shape: "ring", text: "Lynis falló" });
            done(new Error(`Lynis no pudo completar la auditoría. ${lynisResolved.reason}`));
            return;
          }
          // kind 'unsupported': límite conocido (Windows sin WSL), no fallo. Sigue el resto de
          // módulos y el motivo viaja en scanMeta.lynis hasta el dashboard.
          avisarOmitido(node, "lynis", lynisResolved);
        }
        if (enableTrivy && trivy && trivy.skipped) {
          // Por kind, no por reason: el mismo límite se redacta distinto en macOS ("rootfs solo
          // aplica en Linux") y en Arch ("no soporta pacman"). Comparando textos, el return saltaba
          // antes del send(msg) y el dashboard se quedaba con los datos de la ejecución anterior.
          if (trivy.kind === "not-installed") {
            node.status({ fill: "red", shape: "ring", text: "Trivy no instalado" });
            done(new Error(
              "Trivy está activado en la configuración del nodo pero no se encontró instalado en el sistema. " +
              "Instala Trivy (https://trivy.dev/) o desactiva el módulo en las opciones del nodo."
            ));
            return;
          }
          // 'error' y los tres kinds que puede devolver el ejecutor cuando la salida no sirve.
          // Los cuatro significan lo mismo para el usuario: el escaneo NO se hizo. Que caigan
          // aquí y no en el warn de abajo es lo que evita el falso verde: 'unsupported' es un
          // límite conocido y sigue, pero una salida cortada o ilegible es un escaneo fallido.
          const TRIVY_FATAL = ["error", "timeout", "output-too-large", "invalid-json", "empty-output"];
          if (TRIVY_FATAL.includes(trivy.kind)) {
            const label = trivy.walkError
              ? "Carpeta inaccesible"
              : trivy.kind === "output-too-large"
              ? "Salida de Trivy cortada"
              : trivy.kind === "timeout"
              ? "Trivy agotó el tiempo"
              : "Trivy falló";
            node.status({ fill: "red", shape: "ring", text: label });
            done(new Error(`Trivy no pudo completar el escaneo. ${trivy.reason}`));
            return;
          }
          // kind 'unsupported': límite de esta plataforma o de este gestor. Sigue el resto y el
          // límite viaja en scanMeta.systemPackages hasta el bloque de alcance.
          avisarOmitido(node, "trivy-fs", trivy);
        }

        // Sin herramientas externas detrás: no hay nada que pueda faltar.
        const osInfo = getOsInfo();

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
        if (rootfsResult.status === "rejected") {
          node.warn(`[audit-host] trivy-rootfs falló: ${rootfsResult.reason}`);
        }
        if (secResult.status === "rejected") {
          node.warn(`[audit-host] security-events falló: ${secResult.reason}`);
        }
        if (updResult.status === "rejected") {
          node.warn(`[audit-host] pending-updates falló: ${updResult.reason}`);
        }

        // Como pending-updates: un fallo aquí no invalida el resto, sale como comprobación no realizada.
        const secretsResolved = secretsResult.status === "fulfilled"
          ? secretsResult.value
          : { skipped: true, kind: "error", reason: `La búsqueda de secretos falló: ${String(secretsResult.reason)}.` };
        const secretsSkipped = !!(secretsResolved && secretsResolved.skipped);
        if (enableSecrets && secretsSkipped) {
          avisarOmitido(node, "trivy-secrets", secretsResolved);
        }

        // Un throw vale lo mismo que un skipped kind 'error', igual que en Lynis: si no, un rechazo
        // dejaría swInventory a null y el módulo saldría como ejecutado sin haber inventariado nada.
        const swResolved = swInventory || (
          swResult.status === "rejected" && enableSw
            ? {
                skipped: true,
                kind: "error",
                reason: `El inventario de software falló: ${String(swResult.reason)}`,
              }
            : null
        );

        // Igual que en Lynis y en sw-inventory: un throw vale lo mismo que un skipped kind
        // 'error'. A diferencia de Lynis, aquí NO se aborta el nodo: no saber si hay
        // actualizaciones pendientes no invalida el resto de la auditoría.
        const updResolved = pendingUpdates || (
          updResult.status === "rejected" && enableUpdates
            ? {
                skipped: true,
                kind: "error",
                reason: `LoCoAudit no ha podido consultar las actualizaciones pendientes: ${String(updResult.reason)}.`,
              }
            : null
        );
        // Mismo criterio que en Lynis, sw-inventory y pending-updates: un throw vale lo mismo que
        // un skipped kind 'error'. Sin esto un rechazo dejaría trivyRootfs a null y el bloque de
        // alcance diría 'failed' sin poder decir por qué.
        const rootfsResolved = trivyRootfs || (
          rootfsResult.status === "rejected"
            ? {
                skipped: true,
                kind: "error",
                reason: `El análisis de los paquetes del sistema falló: ${String(rootfsResult.reason)}.`,
              }
            : null
        );
        const rootfsSkipped = !!(rootfsResolved && rootfsResolved.skipped);
        if (enableSysPkgs && rootfsSkipped) {
          avisarOmitido(node, "trivy-rootfs", rootfsResolved);
        }

        const updSkipped = !!(updResolved && updResolved.skipped);
        const updStatus = !enableUpdates ? "disabled" : updSkipped ? "skip" : "ok";
        if (enableUpdates && updSkipped) {
          avisarOmitido(node, "pending-updates", updResolved);
        }

        // Un solo punto decide si el módulo cuenta como ejecutado y qué estado viaja en scanMeta.
        // Derivarlo dos veces del mismo valor es lo que ya se corrigió en isCommand y en
        // targetIsLocal: aquí sale una vez y lo leen los dos sitios.
        const swSkipped = !!(swResolved && swResolved.skipped);
        const swPartial = !!(swResolved && swResolved.partial);
        const swStatus = !enableSw
          ? "disabled"
          : swSkipped
          ? "skip"
          : swPartial
          ? "partial"
          : "ok";

        // Un security-events omitido no es error del nodo, al contrario que Lynis o Trivy:
        // el normalizador lo saca como finding informativo.
        const raw = { cpuMemory, disk, swInventory: swResolved, lynis, trivy, trivyRootfs: rootfsResolved, securityEvents, pendingUpdates: updResolved, trivySecrets: secretsResolved };

        const findings = normalizeHost(raw, { platform: process.platform, pkgManager });
        const summary = summarize(findings);
        const durationMs = Date.now() - startTime;

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
            // Resumen de lo que NO se comprobó, derivado de los propios findings `skipped`. El
            // dashboard lo enseña junto al Alcance y saca esos hallazgos de la lista: son una
            // sola cosa —"esto es lo que no se ha mirado"— y no cuatro problemas del equipo.
            checksSkipped: buildSkippedChecksSummary(findings),
            /**
             * Los módulos y qué pasó con cada uno. `modulesRun` no distingue un módulo APAGADO de uno que se CAYÓ, y
             * solo Lynis y Trivy emiten hallazgo al omitirse, así que se deriva aquí y no de los findings.
             */
            modules: [
              { id: "cpu-memory",      label: "Procesador y memoria",        requested: enableCpu,       ran: enableCpu },
              { id: "disk-storage",    label: "Almacenamiento",              requested: enableDisk,      ran: enableDisk },
              { id: "sw-inventory",    label: "Inventario de software",      requested: enableSw,        ran: enableSw && !swSkipped,                              kind: swResolved?.kind },
              { id: "lynis",           label: "Hardening del sistema",       requested: enableLynis,     ran: enableLynis && !lynis?.skipped,                      kind: lynisResolved?.kind },
              { id: "trivy-fs",        label: "Vulnerabilidades del home",   requested: enableTrivy,     ran: enableTrivy && !trivy?.skipped,                      kind: trivy?.kind },
              { id: "trivy-rootfs",    label: "Paquetes del sistema",        requested: enableSysPkgs,   ran: enableSysPkgs && !rootfsSkipped,                     kind: rootfsResolved?.kind },
              { id: "security-events", label: "Eventos de seguridad",        requested: enableSecEvents, ran: enableSecEvents && !securityEvents?.skipped,         kind: securityEvents?.kind },
              { id: "pending-updates", label: "Actualizaciones pendientes",  requested: enableUpdates,   ran: enableUpdates && !updSkipped,                        kind: updResolved?.kind },
              { id: "trivy-secrets",   label: "Secretos y configuraciones",  requested: enableSecrets,   ran: enableSecrets && !secretsSkipped,                    kind: secretsResolved?.kind },
            ].map((m) => ({
              id: m.id,
              label: m.label,
              requested: !!m.requested,
              ran: !!m.ran,
              // El kind del módulo, para poder separar el límite estructural del fallo real sin
              // volver a mirar el resultado entero.
              kind: m.kind || null,
              // Cuatro estados: 'not-requested' (lo apagó el usuario), 'not-applicable' (no tiene sentido en este
              // sistema), 'failed' (se pidió y no salió: el único agujero) y 'ok'. Fundir los dos primeros con 'failed'
              // ponía avisos ámbar sobre cosas que nadie puede arreglar.
              status: !m.requested
                ? "not-requested"
                : m.ran
                ? "ok"
                : esNoAplica(m.kind)
                ? "not-applicable"
                : "failed",
            })),
            modulesRun: [
              enableCpu && "cpu-memory",
              enableDisk && "disk-storage",
              // Un inventario parcial sí se ejecutó; solo el skip total lo saca de la lista.
              enableSw && !swSkipped && "sw-inventory",
              enableLynis && !lynis?.skipped && "lynis",
              enableTrivy && !trivy?.skipped && "trivy-fs",
              enableSysPkgs && !rootfsSkipped && "trivy-rootfs",
              enableSecEvents && !securityEvents?.skipped && "security-events",
              enableUpdates && !updSkipped && "pending-updates",
              enableSecrets && !secretsSkipped && "trivy-secrets",
            ].filter(Boolean),
            durationMs,
            // Se emite siempre, también con el interruptor apagado: "no analizados" no es "limpios"
            // y de una lista de hallazgos vacía nadie puede distinguirlo.
            // El veredicto sale del informe de trivy-rootfs, que es la fuente única. Ya no se
            // reconstruye de un sub-bloque de trivy-fs ni de una lista de gestores nuestra.
            systemPackages: {
              status: systemPackagesSupport(process.platform, rootfsResolved, {
                enabled: enableSysPkgs,
              }),
              // Separa "nadie lo pidió" de "lo pediste y no se pudo"; el dashboard lo redacta.
              requested: enableSysPkgs,
              kind: rootfsSkipped ? (rootfsResolved.kind || null) : null,
              // El gestor lo sigue detectando pkg-manager.js y solo se usa para redactar: la
              // decisión de si se pudo analizar ya NO depende de él.
              manager: pkgManager,
              managerLabel: pkgManager ? managerLabel(pkgManager) : null,
              reason: rootfsSkipped ? rootfsResolved.reason : null,
              // Duración real del rootfs, también cuando se omitió: saber que se tiró diez
              // minutos antes de rendirse es parte del diagnóstico.
              durationMs: (rootfsResolved && rootfsResolved.durationMs) || null,
              // Todo lo de abajo sale del informe de Trivy y de ningún otro sitio. Con el módulo
              // omitido son null, que es distinto de cero: cero paquetes sería un dato, y aquí
              // no hay dato.
              osFamily: !rootfsSkipped && rootfsResolved ? rootfsResolved.os.family : null,
              osName: !rootfsSkipped && rootfsResolved ? rootfsResolved.os.name : null,
              packages: !rootfsSkipped && rootfsResolved ? rootfsResolved.pkgNum : null,
              trivyVersion: !rootfsSkipped && rootfsResolved ? rootfsResolved.trivyVersion : null,
              vulnTotal: !rootfsSkipped && rootfsResolved ? rootfsResolved.total : null,
              fixablePackages: !rootfsSkipped && rootfsResolved ? rootfsResolved.fixable.length : null,
              fixableVulns: !rootfsSkipped && rootfsResolved ? rootfsResolved.fixableVulnCount : null,
              unfixedVulns: !rootfsSkipped && rootfsResolved ? rootfsResolved.unfixed.total : null,
              unfixedBySeverity: !rootfsSkipped && rootfsResolved ? rootfsResolved.unfixed.bySeverity : null,
            },
            // Espejo de scanMeta.lynis: el estado del módulo, aparte de sus datos. Sale del mismo
            // swResolved que decide modulesRun, no de una segunda derivación.
            swInventory: {
              status: swStatus,
              reason: swSkipped
                ? swResolved.reason
                : swPartial
                ? swResolved.partialReason
                : null,
              kind: swSkipped ? (swResolved.kind || null) : null,
              // Cuántos paquetes vio ESTE módulo, y con qué herramienta los vio. La cifra viaja
              // con su fuente porque hay otra al lado, la de trivy-rootfs, que cuenta lo mismo
              // por otro camino y da otro número. No se intentan cuadrar: son dos medidas de dos
              // herramientas distintas, y presentarlas como una sola sería inventar una tercera.
              packages: swSkipped ? null : swPackageCount(swResolved),
              source: swSkipped ? null : swPackageSource(swResolved),
            },
            // Espejo de scanMeta.lynis. Sale del mismo updResolved que decide modulesRun.
            pendingUpdates: {
              status: updStatus,
              reason: updSkipped ? updResolved.reason : null,
              kind: updSkipped ? (updResolved.kind || null) : null,
              total: !updSkipped && updResolved ? updResolved.total : null,
              securityCount: !updSkipped && updResolved ? updResolved.securityCount : null,
              securityDetection: !updSkipped && updResolved ? updResolved.securityDetection : null,
            },
            // El índice de hardening es métrica de cabecera, no hallazgo: viajaba como
            // HOST-LYN-IDX y el gauge lo rescataba buscando ese id en el array. La escala va
            // aquí para que las etiquetas no sigan escritas a mano en el HTML.
            lynis: {
              status: enableLynis
                ? (lynisResolved && lynisResolved.skipped ? (lynisResolved.kind || "skipped") : "ok")
                : "disabled",
              reason: (lynisResolved && lynisResolved.skipped) ? lynisResolved.reason : null,
              hardeningIndex: (lynis && lynis.hardeningIndex != null) ? lynis.hardeningIndex : null,
              version: (lynis && lynis.version) || null,
              testsDone: (lynis && lynis.testsDone) || null,
              scale: { deficiente: "<30", mejorable: "30-54", aceptable: ">=55" },
              // Cobertura REAL sobre los controles que ha devuelto ESTE informe (la tabla cubre lo visto en los informes de
              // referencia, no todo Lynis): traducidos, con paso de resolución y, por separado, los que no admiten acción frente
              // a los que la admiten sin paso escrito. La plataforma entra porque un fix puede ser solo de Linux.
              i18n: lynisCoverage(
                [...(lynis?.warnings || []), ...(lynis?.suggestions || [])].map((e) => e.id),
                process.platform
              ),
            },
          },
          raw: { ...raw, osInfo },
          timestamp: new Date().toISOString(),
        };

        // Lista plana para la tabla del grupo "Logs del sistema": ts desc, tope 200.
        if (enableSecEvents && securityEvents) {
          msg.payload.securityEvents = buildEventList(securityEvents);
        }

        const maxSev = summary.maxSeverity || "info";
        const statusColor =
          maxSev === "critical" || maxSev === "high"
            ? "red"
            : maxSev === "medium"
            ? "yellow"
            : "green";

        // Mismo recuento que la cabecera del dashboard, los accionables: un "96 hallazgos ·
        // riesgo: critical" al lado de "nada que arreglar" es la contradicción a evitar.
        const act = summary.actionable.total;
        const inf = summary.informative.total;
        node.status({
          fill: statusColor,
          shape: "dot",
          text: act > 0
            ? `${act} a revisar · riesgo: ${maxSev}${inf ? ` · ${inf} info` : ""}`
            : `Nada que arreglar · ${inf} informativos`,
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
