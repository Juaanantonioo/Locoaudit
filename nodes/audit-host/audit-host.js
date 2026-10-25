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
const { withoutResults } = require("../../lib/utils");

/** Avisa de un módulo omitido: log si lo apagó el usuario o no aplica, warn si es un fallo. */
function avisarOmitido(node, modulo, res) {
  const kind = res && res.kind;
  const texto = `[audit-host] ${modulo} omitido: ${res && res.reason}`;
  if (kind === "disabled" || esNoAplica(kind)) node.log(texto);
  else node.warn(texto);
}

/** Resultado de un módulo: si lanzó, un skipped 'error' en vez de null, para que no parezca ejecutado sin datos. */
function resolveOrSkip(settled, enabled, what) {
  if (settled.status === "fulfilled") return settled.value;
  return enabled ? { skipped: true, kind: "error", reason: `${what} falló: ${String(settled.reason)}` } : null;
}

/** Paquetes inventariados: array plano, u objeto con `packages` si el inventario fue parcial. */
function swPackageCount(sw) {
  if (Array.isArray(sw)) return sw.length;
  if (sw && Array.isArray(sw.packages)) return sw.packages.length;
  return null;
}

/** Herramienta que hizo el inventario ('dpkg', 'brew'…); todas las entradas comparten la misma. */
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
      // Activo por defecto: sin él el informe parecería completo sin serlo.
      const enableSysPkgs = config.trivySystemPkgs !== false;

      const startTime = Date.now();

      try {
        // Siempre: los fixes y el bloque de alcance necesitan el gestor real.
        let pkgManager = null;
        try {
          pkgManager = await detectPackageManager(process.platform);
        } catch (_) { /* la detección no puede tumbar la auditoría */ }

        // El commandExists de trivy-rootfs va en el despacho; trivy-fs tiene el suyo porque también lo usa audit-image.
        const trivyPath = enableSysPkgs ? await commandExists("trivy") : null;

        const [cpuResult, diskResult, swResult, lynisResult, trivyResult, rootfsResult, secResult, updResult, secretsResult] =
          await Promise.allSettled([
            // En un then: si lanza, cuenta como rechazo del módulo y no tumba el nodo entero.
            enableCpu ? Promise.resolve().then(() => runSystemModule()) : Promise.resolve(null),
            enableDisk ? getDiskInfo() : Promise.resolve(null),
            enableSw ? getSwInventory() : Promise.resolve(null),
            enableLynis
              ? runLynis()
              // kind 'disabled' para que el dashboard no lo confunda con una comprobación caída.
              : Promise.resolve({ skipped: true, kind: "disabled", reason: "El análisis de hardening del sistema está desactivado en las opciones del nodo." }),
            enableTrivy
              // Sin target se audita el HOME; los paquetes del sistema van en trivy-rootfs.
              ? runTrivyFs({ target: config.trivyTarget, pkgManager })
              : Promise.resolve({ skipped: true, kind: "disabled", reason: "El análisis de vulnerabilidades de tu carpeta personal está desactivado en las opciones del nodo." }),
            !enableSysPkgs
              ? Promise.resolve({ skipped: true, kind: "disabled", reason: "El análisis de los paquetes del sistema está desactivado en las opciones del nodo." })
              : !trivyPath
              ? Promise.resolve({ skipped: true, kind: "not-installed", reason: "Trivy no está instalado, y es lo que lee la base de datos de paquetes del sistema." })
              : runTrivyRootfs(),
            enableSecEvents ? runSecurityEvents(secWindow) : Promise.resolve(null),
            enableUpdates ? getPendingUpdates({ pkgManager }) : Promise.resolve(null),
            // Mismo ámbito que trivy-fs, en una pasada aparte.
            enableSecrets
              ? runTrivySecrets({ target: config.trivyTarget })
              : Promise.resolve({ skipped: true, kind: "disabled", reason: "La búsqueda de secretos y configuraciones inseguras está desactivada en las opciones del nodo." }),
          ]);

        const cpuMemory = resolveOrSkip(cpuResult, enableCpu, "La lectura de procesador y memoria");
        const disk = resolveOrSkip(diskResult, enableDisk, "La lectura del almacenamiento");
        const swInventory = swResult.status === "fulfilled" ? swResult.value : null;
        const lynis = lynisResult.status === "fulfilled" ? lynisResult.value : null;
        // Un throw de Trivy entra como 'error' y lo recoge la rama TRIVY_FATAL.
        const trivy = resolveOrSkip(trivyResult, enableTrivy, "El análisis de vulnerabilidades del home");
        const trivyRootfs = rootfsResult.status === "fulfilled" ? rootfsResult.value : null;
        const securityEvents = resolveOrSkip(secResult, enableSecEvents, "La lectura de eventos de seguridad");
        const pendingUpdates = updResult.status === "fulfilled" ? updResult.value : null;

        // Un throw cuenta como skipped con kind 'error'.
        const lynisResolved = lynis || (
          lynisResult.status === "rejected" && enableLynis
            ? { skipped: true, kind: "error", reason: String(lynisResult.reason) }
            : null
        );

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

        // Un fallo aquí no invalida el resto: sale como comprobación no realizada.
        const secretsResolved = secretsResult.status === "fulfilled"
          ? secretsResult.value
          : { skipped: true, kind: "error", reason: `La búsqueda de secretos falló: ${String(secretsResult.reason)}.` };
        const secretsSkipped = !!(secretsResolved && secretsResolved.skipped);
        if (enableSecrets && secretsSkipped) {
          avisarOmitido(node, "trivy-secrets", secretsResolved);
        }

        // Un throw cuenta como skipped 'error'; si no, el módulo saldría como ejecutado sin datos.
        const swResolved = swInventory || (
          swResult.status === "rejected" && enableSw
            ? {
                skipped: true,
                kind: "error",
                reason: `El inventario de software falló: ${String(swResult.reason)}`,
              }
            : null
        );

        // Un throw cuenta como skipped 'error', pero no aborta el nodo como Lynis.
        const updResolved = pendingUpdates || (
          updResult.status === "rejected" && enableUpdates
            ? {
                skipped: true,
                kind: "error",
                reason: `LoCoAudit no ha podido consultar las actualizaciones pendientes: ${String(updResult.reason)}.`,
              }
            : null
        );
        // Un throw cuenta como skipped 'error', para que el bloque de alcance sepa el motivo.
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

        // Se calcula una vez y lo leen modulesRun y scanMeta.
        const swSkipped = !!(swResolved && swResolved.skipped);
        const swPartial = !!(swResolved && swResolved.partial);
        const swStatus = !enableSw
          ? "disabled"
          : swSkipped
          ? "skip"
          : swPartial
          ? "partial"
          : "ok";

        // Un security-events omitido no es error del nodo: el normalizador lo saca como informativo.
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
            // Lo que no se comprobó, sacado de los findings `skipped`; el dashboard lo muestra junto al Alcance.
            checksSkipped: buildSkippedChecksSummary(findings),
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
            ].map((m) => ({
              id: m.id,
              label: m.label,
              requested: !!m.requested,
              ran: !!m.ran,
              kind: m.kind || null,
              // Solo 'failed' es un agujero real; 'not-requested' y 'not-applicable' no se pueden arreglar.
              status: !m.requested
                ? "not-requested"
                : m.ran
                ? "ok"
                : esNoAplica(m.kind)
                ? "not-applicable"
                : "failed",
            })),
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
              status: systemPackagesSupport(process.platform, rootfsResolved, {
                enabled: enableSysPkgs,
              }),
              requested: enableSysPkgs,
              kind: rootfsSkipped ? (rootfsResolved.kind || null) : null,
              // Solo para redactar: no decide si se pudo analizar.
              manager: pkgManager,
              managerLabel: pkgManager ? managerLabel(pkgManager) : null,
              reason: rootfsSkipped ? rootfsResolved.reason : null,
              // También cuando se omitió: ayuda a diagnosticar.
              durationMs: (rootfsResolved && rootfsResolved.durationMs) || null,
              // Del informe de Trivy; null si se omitió, que no es lo mismo que cero.
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
            // Estado del módulo, como scanMeta.lynis.
            swInventory: {
              status: swStatus,
              reason: swSkipped
                ? swResolved.reason
                : swPartial
                ? swResolved.partialReason
                : null,
              kind: swSkipped ? (swResolved.kind || null) : null,
              // La cifra va con su fuente: trivy-rootfs cuenta por otro camino y no se cuadran.
              packages: swSkipped ? null : swPackageCount(swResolved),
              source: swSkipped ? null : swPackageSource(swResolved),
            },
            // Estado del módulo, como scanMeta.lynis.
            pendingUpdates: {
              status: updStatus,
              reason: updSkipped ? updResolved.reason : null,
              kind: updSkipped ? (updResolved.kind || null) : null,
              total: !updSkipped && updResolved ? updResolved.total : null,
              securityCount: !updSkipped && updResolved ? updResolved.securityCount : null,
              securityDetection: !updSkipped && updResolved ? updResolved.securityDetection : null,
            },
            // El índice de hardening es una métrica de cabecera, no un hallazgo; la escala va con él.
            lynis: {
              status: enableLynis
                ? (lynisResolved && lynisResolved.skipped ? (lynisResolved.kind || "skipped") : "ok")
                : "disabled",
              reason: (lynisResolved && lynisResolved.skipped) ? lynisResolved.reason : null,
              hardeningIndex: (lynis && lynis.hardeningIndex != null) ? lynis.hardeningIndex : null,
              version: (lynis && lynis.version) || null,
              testsDone: (lynis && lynis.testsDone) || null,
              scale: { deficiente: "<30", mejorable: "30-54", aceptable: ">=55" },
              // Cobertura de traducciones y fixes sobre los controles de este informe; algunos fixes son solo de Linux.
              i18n: lynisCoverage(
                [...(lynis?.warnings || []), ...(lynis?.suggestions || [])].map((e) => e.id),
                process.platform
              ),
            },
          },
          raw: {
            ...raw,
            trivy: withoutResults(raw.trivy),
            trivyRootfs: withoutResults(raw.trivyRootfs),
            trivySecrets: withoutResults(raw.trivySecrets),
            osInfo,
          },
          timestamp: new Date().toISOString(),
        };

        // Lista plana para la tabla del grupo "Logs del sistema": ts desc, tope 200.
        if (enableSecEvents && securityEvents) {
          msg.payload.securityEvents = buildEventList(securityEvents);
        }

        const maxSev = summary.maxSeverity || "info";
        // Un módulo pedido que falló deja un hueco: el nodo no puede quedar en verde.
        const fallidos = msg.payload.scanMeta.modules.filter((m) => m.status === "failed").length;
        const statusColor =
          maxSev === "critical" || maxSev === "high"
            ? "red"
            : maxSev === "medium" || fallidos
            ? "yellow"
            : "green";

        // Mismo recuento que la cabecera del dashboard: solo los accionables.
        const act = summary.actionable.total;
        const inf = summary.informative.total;
        const textoFallos = fallidos
          ? ` · ${fallidos} ${fallidos === 1 ? "módulo sin completar" : "módulos sin completar"}`
          : "";
        node.status({
          fill: statusColor,
          shape: fallidos ? "ring" : "dot",
          text: (act > 0
            ? `${act} a revisar · riesgo: ${maxSev}${inf ? ` · ${inf} info` : ""}`
            : `Nada que arreglar · ${inf} informativos`) + textoFallos,
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
