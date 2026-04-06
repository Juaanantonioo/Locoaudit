/**
 * lcaudit-dashboard — Nodo dashboard para Node-RED (ui_template)
 *
 * Recibe msg.payload de cualquier nodo lcaudit-* y muestra un dashboard interactivo.
 * También genera un HTML estático en disco.
 */

module.exports = function (RED) {
    const os = require("os");
    const fs = require("fs");
    const path = require("path");

    const { safeFileName, escHtml } = require("../../core/helpers");
    const {
        generateDashboard,
        severityColor,
        severityIcon,
        severityBadge,
    } = require("../../core/reportGenerator");

    function LCAuditDashboard(config) {
        RED.nodes.createNode(this, config);
        const node = this;

        node.on("input", function (msg, send, done) {
            const _send = send || node.send.bind(node);
            const _done = done || function () { };

            try {
                const report = msg.payload;
                if (!report || !report.scanId) {
                    node.status({
                        fill: "yellow",
                        shape: "ring",
                        text: "sin reporte válido",
                    });
                    _send(msg);
                    _done();
                    return;
                }

                // Generar HTML para ui_template
                const dashboardHtml = buildUITemplateDashboard(report);

                // Guardar HTML estático en disco
                const outputPath = (config.outputPath || "").trim();
                const baseDir =
                    outputPath || path.join(os.homedir(), "audit-reports");
                fs.mkdirSync(baseDir, { recursive: true });

                let dashboardPath = null;
                try {
                    dashboardPath = generateDashboard(baseDir);
                } catch (e) {
                    node.warn(
                        "No se pudo generar el dashboard HTML estático: " + e.message
                    );
                }

                // Enviar a ui_template vía msg.template
                msg.template = dashboardHtml;
                msg.audit = {
                    ...(msg.audit || {}),
                    dashboardPath,
                };

                const max = report.summary?.maxSeverity || "INFO";
                const statusColor =
                    max === "CRITICAL" || max === "HIGH"
                        ? "red"
                        : max === "MEDIUM"
                            ? "yellow"
                            : "green";

                const auditTypeMap = {
                    host: "Host",
                    network: "Red",
                    image: "Imagen",
                };

                node.status({
                    fill: statusColor,
                    shape: "dot",
                    text: `${auditTypeMap[report.auditType] || "?"} — ${max}`,
                });

                _send(msg);
                _done();
            } catch (err) {
                node.status({ fill: "red", shape: "ring", text: "error" });
                node.error(err, msg);
                _done(err);
            }
        });
    }

    // ── Generador de HTML para ui_template ──────────────────────────────────

    function buildUITemplateDashboard(report) {
        const summary = report.summary || {};
        const counts = summary.counts || {};
        const findings = report.findings || [];
        const max = summary.maxSeverity || "INFO";

        const auditTypeMap = {
            host: "🖥️ Auditoría de Host",
            network: "🌐 Auditoría de Red",
            image: "📦 Auditoría de Imagen",
        };
        const auditLabel =
            auditTypeMap[report.auditType] || "🔍 Auditoría";

        const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
        const severityOrder = {
            CRITICAL: 4,
            HIGH: 3,
            MEDIUM: 2,
            LOW: 1,
            INFO: 0,
        };

        const findingsSorted = [...findings].sort((a, b) => {
            const sa = severityOrder[a.severity] || 0;
            const sb = severityOrder[b.severity] || 0;
            if (sa !== sb) return sb - sa;
            return String(a.title || "").localeCompare(String(b.title || ""));
        });

        // Resumen
        const host = report.host || {};
        const meta = report.scanMeta || {};
        const scanDate = report.scanId
            ? new Date(report.scanId).toLocaleString("es-ES")
            : "—";

        // Contadores
        const countersHtml = severities
            .map(
                (s) => `
      <div style="text-align:center;background:#1e1e2e;border-radius:10px;padding:12px 16px;min-width:70px;">
        <div style="font-size:1.8rem;font-weight:800;color:${severityColor(s)};">${counts[s] || 0}</div>
        <div style="font-size:0.68rem;font-weight:700;color:#888;margin-top:3px;letter-spacing:0.5px;">${s}</div>
      </div>`
            )
            .join("");

        // Info de red (para auditoría de red)
        let networkInfoHtml = "";
        if (report.auditType === "network") {
            const ns = report.networkSummary || {};
            networkInfoHtml = `
      <div style="background:#1a1a2e;border-radius:10px;padding:14px 18px;margin-bottom:16px;border:1px solid #2d2d44;">
        <div style="font-size:0.78rem;font-weight:600;color:#888;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px;">Resumen de Red</div>
        <div style="display:flex;gap:20px;flex-wrap:wrap;font-size:0.85rem;">
          <div><span style="color:#888;">CIDR:</span> <span style="color:#cdd6f4;font-weight:600;">${escHtml(report.cidr || "")}</span></div>
          <div><span style="color:#888;">Hosts activos:</span> <span style="color:#2ecc71;font-weight:600;">${ns.totalHosts || 0}</span></div>
          <div><span style="color:#888;">Con problemas:</span> <span style="color:#e74c3c;font-weight:600;">${ns.hostsWithIssues || 0}</span></div>
        </div>
      </div>`;
        }

        // Hallazgos por categoría
        const groups = {};
        for (const f of findingsSorted) {
            const cat = f.category || "other";
            if (!groups[cat]) groups[cat] = [];
            groups[cat].push(f);
        }

        const groupOrder = [
            "vulnerability",
            "ports",
            "web",
            "network",
            "system",
            "performance",
            "other",
        ];

        const categoryLabels = {
            vulnerability: "⚠️ Vulnerabilidades",
            ports: "🔌 Puertos y exposición",
            web: "🌐 Servicios web",
            network: "📡 Red",
            system: "💻 Sistema",
            performance: "⚡ Rendimiento",
            other: "📋 Otros",
        };

        const findingsHtml = findingsSorted.length
            ? groupOrder
                .filter((cat) => groups[cat] && groups[cat].length)
                .map((cat) => {
                    const all = groups[cat];
                    const label = categoryLabels[cat] || cat;

                    const items = all
                        .slice(0, 20)
                        .map(
                            (f, i) => `
            <div style="border-left:3px solid ${severityColor(f.severity)};background:#1a1a2e;border-radius:6px;padding:10px 14px;margin-bottom:8px;">
              <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                <span style="font-size:0.9rem;">${severityIcon(f.severity)}</span>
                ${severityBadge(f.severity)}
                <span style="font-weight:600;color:#cdd6f4;flex:1;font-size:0.85rem;">${escHtml(f.title)}</span>
                ${f.category ? `<span style="font-size:0.65rem;background:#2d2d44;padding:2px 6px;border-radius:8px;color:#888;">${f.category}</span>` : ""}
              </div>
              ${f.recommendation ? `<div style="font-size:0.78rem;color:#a0a0b0;margin-top:6px;padding-left:28px;">💡 ${escHtml(f.recommendation)}</div>` : ""}
            </div>`
                        )
                        .join("");

                    const extraCount = all.length > 20 ? all.length - 20 : 0;

                    return `
          <div style="margin-bottom:16px;">
            <div style="font-weight:700;font-size:0.88rem;color:#cdd6f4;margin-bottom:8px;padding-bottom:4px;border-bottom:1px solid #2d2d44;">
              ${label} (${all.length})
            </div>
            ${items}
            ${extraCount > 0 ? `<div style="font-size:0.75rem;color:#888;text-align:center;padding:8px;">... y ${extraCount} hallazgo(s) más</div>` : ""}
          </div>`;
                })
                .join("")
            : `<div style="text-align:center;color:#888;padding:30px;">✅ No se detectaron hallazgos.</div>`;

        // Módulos ejecutados
        const modulesHtml = (meta.modulesRun || [])
            .map(
                (m) =>
                    `<span style="background:#2d2d44;padding:3px 8px;border-radius:8px;font-size:0.7rem;color:#a0a0b0;">${m}</span>`
            )
            .join(" ");

        return `
<style>
  .lcaudit-dash { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #0f0f1a; color: #cdd6f4; padding: 16px; border-radius: 12px; }
  .lcaudit-dash * { box-sizing: border-box; }
</style>
<div class="lcaudit-dash">

  <!-- Header -->
  <div style="background:linear-gradient(135deg,${severityColor(max)}33,#1e1e2e);border:1px solid ${severityColor(max)}66;border-radius:12px;padding:16px 20px;margin-bottom:16px;">
    <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
      <div style="font-size:2.2rem;">${severityIcon(max)}</div>
      <div style="flex:1;">
        <div style="font-size:0.72rem;font-weight:600;color:#888;text-transform:uppercase;letter-spacing:1px;">${auditLabel}</div>
        <div style="font-size:1.2rem;font-weight:800;color:${severityColor(max)};margin-top:2px;">Riesgo: ${max}</div>
        <div style="font-size:0.78rem;color:#888;margin-top:4px;">
          ${escHtml(host.hostname || "?")} · ${escHtml(host.platform || "?")} · ${escHtml(host.arch || "")} · ${scanDate}
        </div>
        <div style="font-size:0.72rem;color:#666;margin-top:4px;">
          ${modulesHtml} · ${meta.durationMs || "?"}ms
        </div>
      </div>
    </div>
  </div>

  <!-- Contadores -->
  <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px;justify-content:center;">
    ${countersHtml}
  </div>

  ${networkInfoHtml}

  <!-- Hallazgos -->
  ${findingsHtml}

</div>`;
    }

    RED.nodes.registerType("lcaudit-dashboard", LCAuditDashboard);
};
