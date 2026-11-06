"use strict";

/** Nodo audit-host: lanza los módulos de host en paralelo y emite findings normalizados. */

const { ejecutarModuloSistema } = require("./modules/cpu-memory");
const { infoDisco } = require("./modules/disk-storage");
const { inventarioSoftware } = require("./modules/sw-inventory");
const { infoSistema } = require("./modules/os-info");
const { ejecutarLynis } = require("./modules/lynis");
const { ejecutarTrivyFs, ejecutarTrivySecretos } = require("./modules/trivy-fs");
const { ejecutarTrivyRootfs, soportePaquetesSistema } = require("../../lib/trivy-rootfs");
const { ejecutarEventos, listaDeEventos } = require("./modules/security-events");
const { actualizacionesPendientes } = require("./modules/pending-updates");
const { normalizarHost, esNoAplica, resumenOmitidas, coberturaLynis } = require("../../lib/normalizer");
const { detectarGestor, nombreGestor } = require("../../lib/pkg-manager");
const { existeComando } = require("../../lib/executor");
const { resumir } = require("../../lib/severity-map");
const { sinResultados } = require("../../lib/utils");

/** Avisa de un módulo omitido: log si lo apagó el usuario o no aplica, warn si es un fallo. */
function avisarOmitido(node, modulo, res) {
  const kind = res && res.kind;
  const texto = `[audit-host] ${modulo} omitido: ${res && res.reason}`;
  if (kind === "disabled" || esNoAplica(kind)) node.log(texto);
  else node.warn(texto);
}

/** Resultado de un módulo: si lanzó, un skipped 'error' en vez de null, para que no parezca ejecutado sin datos. */
function resolverUOmitir(settled, enabled, what) {
  if (settled.status === "fulfilled") return settled.value;
  if (enabled) {
    return { skipped: true, kind: "error", reason: `${what} falló: ${String(settled.reason)}` };
  } else {
    return null;
  }
}

/** Paquetes inventariados: array plano, u objeto con `packages` si el inventario fue parcial. */
function numeroDePaquetes(sw) {
  if (Array.isArray(sw)) return sw.length;
  if (sw && Array.isArray(sw.packages)) return sw.packages.length;
  return null;
}

/** Herramienta que hizo el inventario ('dpkg', 'brew'…); todas las entradas comparten la misma. */
function fuenteDePaquetes(sw) {
  let list;
  if (Array.isArray(sw)) {
    list = sw;
  } else {
    list = (sw && sw.packages) || [];
  }
  return (list[0] && list[0].source) || null;
}

module.exports = function (RED) {
  function NodoAuditoriaHost(config) {
    RED.nodes.createNode(this, config);
    const node = this;

    // El chat lo sirve /locoaudit/chat con el llm-config cuyo id viaja en el payload.
    if (config.llmConfig) {
      node.llmConfig = RED.nodes.getNode(config.llmConfig);
    } else {
      node.llmConfig = null;
    }
    const llmConfigId = (node.llmConfig && node.llmConfig.id) || null;

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
      // Activo por defecto: sin él el informe parecería completo sin serlo.
      const enableSysPkgs = config.trivySystemPkgs !== false;

      const startTime = Date.now();

      try {
        // Siempre: los fixes y el bloque de alcance necesitan el gestor real.
        let pkgManager = null;
        try {
          pkgManager = await detectarGestor(process.platform);
        } catch (_) { /* la detección no puede tumbar la auditoría */ }

        // El existeComando de trivy-rootfs va en el despacho; trivy-fs tiene el suyo porque también lo usa audit-image.
        let trivyPath;
        if (enableSysPkgs) {
          trivyPath = await existeComando("trivy");
        } else {
          trivyPath = null;
        }

        let tareaCpu;
        if (enableCpu) {
          // En un then: si lanza, cuenta como rechazo del módulo y no tumba el nodo entero.
          tareaCpu = Promise.resolve().then(() => ejecutarModuloSistema());
          // Se espera antes de lanzar el resto: en Windows mide el uso de CPU y no debe medir la propia auditoría.
          // El catch solo evita el rechazo no gestionado; el resultado lo recoge el allSettled de abajo.
          await tareaCpu.catch(() => {});
        } else {
          tareaCpu = Promise.resolve(null);
        }
        let tareaDisco;
        if (enableDisk) {
          tareaDisco = infoDisco();
        } else {
          tareaDisco = Promise.resolve(null);
        }
        let tareaSw;
        if (enableSw) {
          tareaSw = inventarioSoftware();
        } else {
          tareaSw = Promise.resolve(null);
        }
        let tareaLynis;
        if (enableLynis) {
          tareaLynis = ejecutarLynis();
        } else {
          // kind 'disabled' para que el dashboard no lo confunda con una comprobación caída.
          tareaLynis = Promise.resolve({ skipped: true, kind: "disabled", reason: "El análisis de hardening del sistema está desactivado en las opciones del nodo." });
        }
        let tareaTrivy;
        if (enableTrivy) {
          // Sin target se audita el HOME; los paquetes del sistema van en trivy-rootfs.
          tareaTrivy = ejecutarTrivyFs({ target: config.trivyTarget, pkgManager });
        } else {
          tareaTrivy = Promise.resolve({ skipped: true, kind: "disabled", reason: "El análisis de vulnerabilidades de tu carpeta personal está desactivado en las opciones del nodo." });
        }
        let tareaRootfs;
        if (!enableSysPkgs) {
          tareaRootfs = Promise.resolve({ skipped: true, kind: "disabled", reason: "El análisis de los paquetes del sistema está desactivado en las opciones del nodo." });
        } else if (!trivyPath) {
          tareaRootfs = Promise.resolve({ skipped: true, kind: "not-installed", reason: "Trivy no está instalado, y es lo que lee la base de datos de paquetes del sistema." });
        } else {
          tareaRootfs = ejecutarTrivyRootfs();
        }
        let tareaEventos;
        if (enableSecEvents) {
          tareaEventos = ejecutarEventos(secWindow);
        } else {
          tareaEventos = Promise.resolve(null);
        }
        let tareaActualizaciones;
        if (enableUpdates) {
          tareaActualizaciones = actualizacionesPendientes({ pkgManager });
        } else {
          tareaActualizaciones = Promise.resolve(null);
        }
        let tareaSecretos;
        if (enableSecrets) {
          // Mismo ámbito que trivy-fs, en una pasada aparte.
          tareaSecretos = ejecutarTrivySecretos({ target: config.trivyTarget });
        } else {
          tareaSecretos = Promise.resolve({ skipped: true, kind: "disabled", reason: "La búsqueda de secretos y configuraciones inseguras está desactivada en las opciones del nodo." });
        }
        const [cpuResult, diskResult, swResult, lynisResult, trivyResult, rootfsResult, secResult, updResult, secretsResult] =
          await Promise.allSettled([
            tareaCpu,
            tareaDisco,
            tareaSw,
            tareaLynis,
            tareaTrivy,
            tareaRootfs,
            tareaEventos,
            tareaActualizaciones,
            tareaSecretos,
          ]);

        const cpuMemory = resolverUOmitir(cpuResult, enableCpu, "La lectura de procesador y memoria");
        const disk = resolverUOmitir(diskResult, enableDisk, "La lectura del almacenamiento");
        let swInventory;
        if (swResult.status === "fulfilled") {
          swInventory = swResult.value;
        } else {
          swInventory = null;
        }
        let lynis;
        if (lynisResult.status === "fulfilled") {
          lynis = lynisResult.value;
        } else {
          lynis = null;
        }
        // Un throw de Trivy entra como 'error' y lo recoge la rama TRIVY_FATAL.
        const trivy = resolverUOmitir(trivyResult, enableTrivy, "El análisis de vulnerabilidades del home");
        let trivyRootfs;
        if (rootfsResult.status === "fulfilled") {
          trivyRootfs = rootfsResult.value;
        } else {
          trivyRootfs = null;
        }
        const securityEvents = resolverUOmitir(secResult, enableSecEvents, "La lectura de eventos de seguridad");
        let pendingUpdates;
        if (updResult.status === "fulfilled") {
          pendingUpdates = updResult.value;
        } else {
          pendingUpdates = null;
        }

        // Un throw cuenta como skipped con kind 'error'.
        let lynisResolved;
        if (lynis) {
          lynisResolved = lynis;
        } else if (lynisResult.status === "rejected" && enableLynis) {
          lynisResolved = { skipped: true, kind: "error", reason: String(lynisResult.reason) };
        } else {
          lynisResolved = null;
        }

        if (enableLynis && lynisResolved && lynisResolved.skipped) {
          // Se decide por kind, nunca por el texto de reason, que cambia según la plataforma.
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
          // 'unsupported' (p. ej. Windows sin WSL) no es un fallo: se sigue y el motivo va en scanMeta.lynis.
          avisarOmitido(node, "lynis", lynisResolved);
        }
        if (enableTrivy && trivy && trivy.skipped) {
          // Por kind, no por reason: el mismo límite se redacta distinto en cada plataforma.
          if (trivy.kind === "not-installed") {
            node.status({ fill: "red", shape: "ring", text: "Trivy no instalado" });
            done(new Error(
              "Trivy está activado en la configuración del nodo pero no se encontró instalado en el sistema. " +
              "Instala Trivy (https://trivy.dev/) o desactiva el módulo en las opciones del nodo."
            ));
            return;
          }
          // Un fallo no tira el resto del informe: el módulo queda como no completado y el nodo sin verde.
          avisarOmitido(node, "trivy-fs", trivy);
        }

        const osInfo = infoSistema();

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

        // Un fallo aquí no invalida el resto: sale como comprobación no realizada.
        let secretsResolved;
        if (secretsResult.status === "fulfilled") {
          secretsResolved = secretsResult.value;
        } else {
          secretsResolved = { skipped: true, kind: "error", reason: `La búsqueda de secretos falló: ${String(secretsResult.reason)}.` };
        }
        const secretsSkipped = !!(secretsResolved && secretsResolved.skipped);
        if (enableSecrets && secretsSkipped) {
          avisarOmitido(node, "trivy-secrets", secretsResolved);
        }

        // Un throw cuenta como skipped 'error'; si no, el módulo saldría como ejecutado sin datos.
        let swResolved;
        if (swInventory) {
          swResolved = swInventory;
        } else if (swResult.status === "rejected" && enableSw) {
          swResolved = {
            skipped: true,
            kind: "error",
            reason: `El inventario de software falló: ${String(swResult.reason)}`,
          };
        } else {
          swResolved = null;
        }

        // Un throw cuenta como skipped 'error', pero no aborta el nodo como Lynis.
        let updResolved;
        if (pendingUpdates) {
          updResolved = pendingUpdates;
        } else if (updResult.status === "rejected" && enableUpdates) {
          updResolved = {
            skipped: true,
            kind: "error",
            reason: `LoCoAudit no ha podido consultar las actualizaciones pendientes: ${String(updResult.reason)}.`,
          };
        } else {
          updResolved = null;
        }
        // Un throw cuenta como skipped 'error', para que el bloque de alcance sepa el motivo.
        let rootfsResolved;
        if (trivyRootfs) {
          rootfsResolved = trivyRootfs;
        } else if (rootfsResult.status === "rejected") {
          rootfsResolved = {
            skipped: true,
            kind: "error",
            reason: `El análisis de los paquetes del sistema falló: ${String(rootfsResult.reason)}.`,
          };
        } else {
          rootfsResolved = null;
        }
        const rootfsSkipped = !!(rootfsResolved && rootfsResolved.skipped);
        if (enableSysPkgs && rootfsSkipped) {
          avisarOmitido(node, "trivy-rootfs", rootfsResolved);
        }

        const updSkipped = !!(updResolved && updResolved.skipped);
        let updStatus;
        if (!enableUpdates) {
          updStatus = "disabled";
        } else if (updSkipped) {
          updStatus = "skip";
        } else {
          updStatus = "ok";
        }
        if (enableUpdates && updSkipped) {
          avisarOmitido(node, "pending-updates", updResolved);
        }

        // Se calcula una vez y lo leen modulesRun y scanMeta.
        const swSkipped = !!(swResolved && swResolved.skipped);
        const swPartial = !!(swResolved && swResolved.partial);
        let swStatus;
        if (!enableSw) {
          swStatus = "disabled";
        } else if (swSkipped) {
          swStatus = "skip";
        } else if (swPartial) {
          swStatus = "partial";
        } else {
          swStatus = "ok";
        }

        // Un security-events omitido no es error del nodo: el normalizador lo saca como informativo.
        const raw = { cpuMemory, disk, swInventory: swResolved, lynis, trivy, trivyRootfs: rootfsResolved, securityEvents, pendingUpdates: updResolved, trivySecrets: secretsResolved };

        const findings = normalizarHost(raw, { platform: process.platform, pkgManager });
        const summary = resumir(findings);
        const durationMs = Date.now() - startTime;

        let tipoRootfs;
        if (rootfsSkipped) {
          tipoRootfs = rootfsResolved.kind || null;
        } else {
          tipoRootfs = null;
        }
        let etiquetaGestor;
        if (pkgManager) {
          etiquetaGestor = nombreGestor(pkgManager);
        } else {
          etiquetaGestor = null;
        }
        let motivoRootfs;
        if (rootfsSkipped) {
          motivoRootfs = rootfsResolved.reason;
        } else {
          motivoRootfs = null;
        }
        let familiaSo;
        let nombreSo;
        let paquetesSo;
        let versionTrivy;
        let vulnsTotales;
        let paquetesCorregibles;
        let vulnsCorregibles;
        let vulnsSinParche;
        let sinParchePorSeveridad;
        if (!rootfsSkipped && rootfsResolved) {
          familiaSo = rootfsResolved.os.family;
          nombreSo = rootfsResolved.os.name;
          paquetesSo = rootfsResolved.pkgNum;
          versionTrivy = rootfsResolved.trivyVersion;
          vulnsTotales = rootfsResolved.total;
          paquetesCorregibles = rootfsResolved.fixable.length;
          vulnsCorregibles = rootfsResolved.fixableVulnCount;
          vulnsSinParche = rootfsResolved.unfixed.total;
          sinParchePorSeveridad = rootfsResolved.unfixed.bySeverity;
        } else {
          familiaSo = null;
          nombreSo = null;
          paquetesSo = null;
          versionTrivy = null;
          vulnsTotales = null;
          paquetesCorregibles = null;
          vulnsCorregibles = null;
          vulnsSinParche = null;
          sinParchePorSeveridad = null;
        }
        let motivoSw;
        if (swSkipped) {
          motivoSw = swResolved.reason;
        } else if (swPartial) {
          motivoSw = swResolved.partialReason;
        } else {
          motivoSw = null;
        }
        let tipoSw;
        let paquetesSw;
        let fuenteSw;
        if (swSkipped) {
          tipoSw = swResolved.kind || null;
          paquetesSw = null;
          fuenteSw = null;
        } else {
          tipoSw = null;
          paquetesSw = numeroDePaquetes(swResolved);
          fuenteSw = fuenteDePaquetes(swResolved);
        }
        let motivoActualizaciones;
        let tipoActualizaciones;
        if (updSkipped) {
          motivoActualizaciones = updResolved.reason;
          tipoActualizaciones = updResolved.kind || null;
        } else {
          motivoActualizaciones = null;
          tipoActualizaciones = null;
        }
        let totalActualizaciones;
        let recuentoSeguridad;
        let deteccionSeguridad;
        if (!updSkipped && updResolved) {
          totalActualizaciones = updResolved.total;
          recuentoSeguridad = updResolved.securityCount;
          deteccionSeguridad = updResolved.securityDetection;
        } else {
          totalActualizaciones = null;
          recuentoSeguridad = null;
          deteccionSeguridad = null;
        }
        let estadoLynis;
        if (enableLynis) {
          if (lynisResolved && lynisResolved.skipped) {
            estadoLynis = lynisResolved.kind || "skipped";
          } else {
            estadoLynis = "ok";
          }
        } else {
          estadoLynis = "disabled";
        }
        let motivoLynis;
        if (lynisResolved && lynisResolved.skipped) {
          motivoLynis = lynisResolved.reason;
        } else {
          motivoLynis = null;
        }
        let indiceHardening;
        if (lynis && lynis.hardeningIndex != null) {
          indiceHardening = lynis.hardeningIndex;
        } else {
          indiceHardening = null;
        }

        msg.payload = {
          findings,
          summary,
          source: "audit-host",
          auditType: "host",
          llmConfigId,
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
            // Lo que no se comprobó, sacado de los findings `skipped`; el dashboard lo muestra junto al Alcance.
            checksSkipped: resumenOmitidas(findings),
            // Estado de cada módulo: modulesRun no distingue uno apagado de uno caído.
            modules: [
              { id: "cpu-memory",      label: "Procesador y memoria",        requested: enableCpu,       ran: enableCpu && !cpuMemory?.skipped,                    kind: cpuMemory?.kind },
              { id: "disk-storage",    label: "Almacenamiento",              requested: enableDisk,      ran: enableDisk && !disk?.skipped,                        kind: disk?.kind },
              { id: "sw-inventory",    label: "Inventario de software",      requested: enableSw,        ran: enableSw && !swSkipped,                              kind: swResolved?.kind },
              { id: "lynis",           label: "Hardening del sistema",       requested: enableLynis,     ran: enableLynis && !lynis?.skipped,                      kind: lynisResolved?.kind },
              { id: "trivy-fs",        label: "Vulnerabilidades del home",   requested: enableTrivy,     ran: enableTrivy && !trivy?.skipped,                      kind: trivy?.kind },
              { id: "trivy-rootfs",    label: "Paquetes del sistema",        requested: enableSysPkgs,   ran: enableSysPkgs && !rootfsSkipped,                     kind: rootfsResolved?.kind },
              { id: "security-events", label: "Eventos de seguridad",        requested: enableSecEvents, ran: enableSecEvents && !securityEvents?.skipped,         kind: securityEvents?.kind },
              { id: "pending-updates", label: "Actualizaciones pendientes",  requested: enableUpdates,   ran: enableUpdates && !updSkipped,                        kind: updResolved?.kind },
              { id: "trivy-secrets",   label: "Secretos y configuraciones",  requested: enableSecrets,   ran: enableSecrets && !secretsSkipped,                    kind: secretsResolved?.kind },
            ].map((m) => {
              let estado;
              if (!m.requested) {
                estado = "not-requested";
              } else if (m.ran) {
                estado = "ok";
              } else if (esNoAplica(m.kind)) {
                estado = "not-applicable";
              } else {
                estado = "failed";
              }
              return {
                id: m.id,
                label: m.label,
                requested: !!m.requested,
                ran: !!m.ran,
                kind: m.kind || null,
                // Solo 'failed' es un agujero real; 'not-requested' y 'not-applicable' no se pueden arreglar.
                status: estado,
              };
            }),
            modulesRun: [
              enableCpu && !cpuMemory?.skipped && "cpu-memory",
              enableDisk && !disk?.skipped && "disk-storage",
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
            // Siempre presente: "no analizados" no es "limpios". El veredicto sale del informe de trivy-rootfs.
            systemPackages: {
              status: soportePaquetesSistema(process.platform, rootfsResolved, {
                enabled: enableSysPkgs,
              }),
              requested: enableSysPkgs,
              kind: tipoRootfs,
              // Solo para redactar: no decide si se pudo analizar.
              manager: pkgManager,
              managerLabel: etiquetaGestor,
              reason: motivoRootfs,
              // También cuando se omitió: ayuda a diagnosticar.
              durationMs: (rootfsResolved && rootfsResolved.durationMs) || null,
              // Del informe de Trivy; null si se omitió, que no es lo mismo que cero.
              osFamily: familiaSo,
              osName: nombreSo,
              packages: paquetesSo,
              trivyVersion: versionTrivy,
              vulnTotal: vulnsTotales,
              fixablePackages: paquetesCorregibles,
              fixableVulns: vulnsCorregibles,
              unfixedVulns: vulnsSinParche,
              unfixedBySeverity: sinParchePorSeveridad,
            },
            // Estado del módulo, como scanMeta.lynis.
            swInventory: {
              status: swStatus,
              reason: motivoSw,
              kind: tipoSw,
              // La cifra va con su fuente: trivy-rootfs cuenta por otro camino y no se cuadran.
              packages: paquetesSw,
              source: fuenteSw,
            },
            // Estado del módulo, como scanMeta.lynis.
            pendingUpdates: {
              status: updStatus,
              reason: motivoActualizaciones,
              kind: tipoActualizaciones,
              total: totalActualizaciones,
              securityCount: recuentoSeguridad,
              securityDetection: deteccionSeguridad,
            },
            // El índice de hardening es una métrica de cabecera, no un hallazgo; la escala va con él.
            lynis: {
              status: estadoLynis,
              reason: motivoLynis,
              hardeningIndex: indiceHardening,
              version: (lynis && lynis.version) || null,
              testsDone: (lynis && lynis.testsDone) || null,
              scale: { deficiente: "<30", mejorable: "30-54", aceptable: ">=55" },
              // Cobertura de traducciones y fixes sobre los controles de este informe; algunos fixes son solo de Linux.
              i18n: coberturaLynis(
                [...(lynis?.warnings || []), ...(lynis?.suggestions || [])].map((e) => e.id),
                process.platform
              ),
            },
          },
          raw: {
            ...raw,
            trivy: sinResultados(raw.trivy),
            trivyRootfs: sinResultados(raw.trivyRootfs),
            trivySecrets: sinResultados(raw.trivySecrets),
            osInfo,
          },
          timestamp: new Date().toISOString(),
        };

        // Lista plana para la tabla del grupo "Logs del sistema": ts desc, tope 200.
        if (enableSecEvents && securityEvents) {
          msg.payload.securityEvents = listaDeEventos(securityEvents);
        }

        const maxSev = summary.maxSeverity || "info";
        // Un módulo pedido que falló deja un hueco: el nodo no puede quedar en verde.
        const fallidos = msg.payload.scanMeta.modules.filter((m) => m.status === "failed").length;
        let statusColor;
        if (maxSev === "critical" || maxSev === "high") {
          statusColor = "red";
        } else if (maxSev === "medium" || fallidos) {
          statusColor = "yellow";
        } else {
          statusColor = "green";
        }

        // Mismo recuento que la cabecera del dashboard: solo los accionables.
        const act = summary.actionable.total;
        const inf = summary.informative.total;
        let textoFallos;
        if (fallidos) {
          let unidad;
          if (fallidos === 1) {
            unidad = "módulo sin completar";
          } else {
            unidad = "módulos sin completar";
          }
          textoFallos = ` · ${fallidos} ${unidad}`;
        } else {
          textoFallos = "";
        }
        let forma;
        if (fallidos) {
          forma = "ring";
        } else {
          forma = "dot";
        }
        let resumen;
        if (act > 0) {
          let sufijoInfo;
          if (inf) {
            sufijoInfo = ` · ${inf} info`;
          } else {
            sufijoInfo = "";
          }
          resumen = `${act} a revisar · riesgo: ${maxSev}${sufijoInfo}`;
        } else {
          resumen = `Nada que arreglar · ${inf} informativos`;
        }
        node.status({
          fill: statusColor,
          shape: forma,
          text: resumen + textoFallos,
        });

        send(msg);
        done();
      } catch (err) {
        node.status({ fill: "red", shape: "ring", text: "Error" });
        done(err);
      }
    });
  }

  RED.nodes.registerType("audit-host", NodoAuditoriaHost);
};
