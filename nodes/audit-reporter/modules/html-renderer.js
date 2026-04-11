"use strict";

/**
 * html-renderer.js — Generador del dashboard HTML de LoCoAudit.
 *
 * Exporta:
 *   generateDashboard(baseDir) → string  (ruta del dashboard.html generado)
 *   renderDashboard(reports)   → string  (HTML completo)
 *   renderAuditPanel(report, auditIndex) → string  (HTML de un panel)
 *   severityColor(s)  → string
 *   severityIcon(s)   → string
 *   severityBadge(s)  → string
 */

const fs = require("fs");
const path = require("path");

// ── Escape HTML (inlined para evitar dependencia circular) ──────────────────

function escHtml(str) {
    return String(str || "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}

// ── Color y badges de severidad ─────────────────────────────────────────────

function severityColor(s) {
    return (
        {
            CRITICAL: "#c0392b",
            HIGH: "#e74c3c",
            MEDIUM: "#e67e22",
            LOW: "#f1c40f",
            INFO: "#2ecc71",
        }[s] || "#95a5a6"
    );
}

function severityBadge(s) {
    const colors = {
        CRITICAL: "#c0392b",
        HIGH: "#e74c3c",
        MEDIUM: "#e67e22",
        LOW: "#f1c40f",
        INFO: "#27ae60",
    };
    const bg = colors[s] || "#95a5a6";
    return `<span style="background:${bg};color:#fff;padding:2px 8px;border-radius:12px;font-size:0.75rem;font-weight:700;">${s}</span>`;
}

function severityIcon(s) {
    return (
        { CRITICAL: "🔴", HIGH: "🔴", MEDIUM: "🟡", LOW: "🟡", INFO: "🟢" }[s] ||
        "⚪"
    );
}

// ── Mensajes amigables ─────────────────────────────────────────────────────

const PLAIN_MESSAGES = {
    MEMORY_FREE_RATIO: {
        HIGH: "Tu ordenador tiene muy poca memoria libre. Puede que vaya lento o falle pronto.",
        MEDIUM:
            "La memoria de tu ordenador está bastante llena. Cierra programas que no uses.",
        LOW: "La memoria empieza a estar algo justa. Vigílala.",
        INFO: "La memoria del ordenador está en buen estado.",
    },
    NO_EXTERNAL_IPV4:
        "No se detectó ninguna conexión de red activa. Revisa el cable o el WiFi.",
    EXTERNAL_IPV4_DETECTED:
        "El ordenador tiene conexión a la red. Todo parece normal.",
    NO_OPEN_PORTS_DETECTED:
        "No se encontraron puertas de acceso abiertas. Eso es bueno.",
    OPEN_PORTS_DETECTED:
        "Se encontraron accesos activos en la red. Revisa si todos son necesarios.",
    EXPOSURE_CONTEXT: {
        HIGH: "Hay accesos peligrosos abiertos que cualquiera en la red podría usar para entrar a tu equipo. Actúa pronto.",
        MEDIUM:
            "Algunos accesos están abiertos en tu red local. No es urgente, pero conviene revisarlos.",
        LOW: "Hay algún acceso abierto, pero con riesgo bajo. Mantenlo controlado.",
        INFO: "Los accesos están solo en el propio equipo. No hay riesgo externo.",
    },
    NODE_RED_PORT_1880_OPEN: {
        LOW: "Node-RED solo es accesible desde este equipo. Sin riesgo externo.",
        MEDIUM:
            "Node-RED está abierto a la red. Asegúrate de que tenga contraseña.",
    },
    NMAP_NOT_AVAILABLE:
        "La herramienta de escaneo de red (Nmap) no está instalada.",
    TRIVY_NOT_AVAILABLE:
        "La herramienta de análisis de vulnerabilidades (Trivy) no está instalada.",
    NO_VULNERABILITIES_DETECTED:
        "No se encontraron vulnerabilidades conocidas. ¡Bien!",
    HTTPFP_NO_ENDPOINTS:
        "No se encontraron servicios web activos para analizar.",
};

function getPlainMessage(finding) {
    const entry = PLAIN_MESSAGES[finding.id];
    if (!entry) return null;
    if (typeof entry === "string") return entry;
    if (typeof entry === "object")
        return entry[finding.severity] || entry["INFO"] || null;
    return null;
}

// ── Render de un finding ────────────────────────────────────────────────────

function renderFinding(f, index) {
    const plain = getPlainMessage(f);
    const evidenceJson = JSON.stringify(f.evidence || {}, null, 2);
    const uid = `f-${index}`;

    return `
  <div class="finding" style="border-left: 4px solid ${severityColor(f.severity)}; margin-bottom:12px; background:#fff; border-radius:6px; overflow:hidden; box-shadow:0 1px 3px rgba(0,0,0,0.07);">
    <div class="finding-header" style="display:flex;align-items:center;gap:10px;padding:12px 16px;cursor:pointer;" onclick="toggleDetail('${uid}')">
      <span style="font-size:1.1rem;">${severityIcon(f.severity)}</span>
      ${severityBadge(f.severity)}
      <span style="font-weight:600;flex:1;">${escHtml(f.title)}</span>
      ${f.category ? `<span style="font-size:0.72rem;background:#ecf0f1;padding:2px 7px;border-radius:10px;color:#555;">${f.category}</span>` : ""}
      <span style="color:#aaa;font-size:0.85rem;">▼</span>
    </div>

    ${plain
            ? `
    <div style="padding:4px 16px 10px 16px; background:#f9f9f9; border-top:1px solid #f0f0f0;">
      <span style="font-size:0.88rem;color:#444;">💬 ${escHtml(plain)}</span>
    </div>`
            : ""
        }

    <div id="${uid}" style="display:none; padding:12px 16px; border-top:1px solid #eee;">
      <p style="margin:0 0 8px;font-size:0.85rem;"><strong>Recomendación técnica:</strong> ${escHtml(f.fix || "")}</p>
      <details style="margin-top:8px;">
        <summary style="cursor:pointer;font-size:0.8rem;color:#666;">Ver evidencia técnica</summary>
        <pre style="background:#1e1e2e;color:#cdd6f4;padding:12px;border-radius:6px;font-size:0.75rem;overflow-x:auto;margin-top:8px;">${escHtml(evidenceJson)}</pre>
      </details>
    </div>
  </div>`;
}

// ── Render de panel de auditoría ────────────────────────────────────────────

function renderAuditPanel(report, auditIndex) {
    const summary = report.summary || {};
    const counts = summary.counts || {};

    const hostMax =
        summary.host?.maxSeverity || summary.maxSeverity || "INFO";
    const hostCounts = summary.host?.counts || counts;

    const imageMax = summary.image?.maxSeverity || null;

    const max = hostMax;
    const host = report.host || {};
    const meta = report.scanMeta || {};
    const findings = report.findings || [];

    const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
    const severityOrder = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };

    const findingsSorted = [...findings].sort((a, b) => {
        const sa = severityOrder[a.severity] || 0;
        const sb = severityOrder[b.severity] || 0;
        if (sa !== sb) return sb - sa;
        return String(a.title || "").localeCompare(String(b.title || ""));
    });

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

    function labelForCategory(cat) {
        if (cat === "vulnerability") return "Vulnerabilidades";
        if (cat === "ports") return "Puertos y exposición";
        if (cat === "web") return "Servicios web";
        if (cat === "network") return "Red";
        if (cat === "system") return "Sistema";
        if (cat === "performance") return "Rendimiento";
        return "Otros";
    }

    const maxVisibleVulns = 10;

    const findingsHtml = findingsSorted.length
        ? groupOrder
            .filter((cat) => groups[cat] && groups[cat].length)
            .map((cat) => {
                const all = groups[cat];
                const label = labelForCategory(cat);

                if (cat !== "vulnerability") {
                    const items = all
                        .map((f, i) => renderFinding(f, `${auditIndex}-${cat}-${i}`))
                        .join("");
                    return `
            <details open>
              <summary style="margin:12px 0 6px;font-weight:600;font-size:0.9rem;cursor:pointer;">
                ${label} (${all.length})
              </summary>
              ${items}
            </details>`;
                }

                const top = all.slice(0, maxVisibleVulns);
                const extra = all.slice(maxVisibleVulns);
                const topHtml = top
                    .map((f, i) =>
                        renderFinding(f, `${auditIndex}-vuln-top-${i}`)
                    )
                    .join("");
                const extraHtml = extra
                    .map((f, i) =>
                        renderFinding(f, `${auditIndex}-vuln-extra-${i}`)
                    )
                    .join("");

                return `
          <details open>
            <summary style="margin:12px 0 6px;font-weight:600;font-size:0.9rem;cursor:pointer;">
              ${label} (${all.length})
            </summary>
            ${topHtml}
            ${extra.length
                        ? `
              <div id="vuln-extra-wrapper-${auditIndex}" style="display:none;margin-top:8px;">
                ${extraHtml}
              </div>
              <button type="button"
                      onclick="toggleExtraVulns('${auditIndex}')"
                      style="margin-top:8px;border:none;background:#ecf0f1;border-radius:16px;padding:6px 12px;font-size:0.8rem;cursor:pointer;">
                Mostrar ${extra.length} vulnerabilidade(s) adicional(es)
              </button>
            `
                        : ""
                    }
          </details>`;
            })
            .join("")
        : `<p style="color:#888;text-align:center;padding:20px;">No se generaron hallazgos.</p>`;

    const countersHtml = severities
        .map(
            (s) => `
  <div style="text-align:center;background:#fff;border-radius:8px;padding:10px 18px;box-shadow:0 1px 4px rgba(0,0,0,0.08);">
    <div style="font-size:1.6rem;font-weight:700;color:${severityColor(s)};">${hostCounts[s] || 0}</div>
    <div style="font-size:0.72rem;font-weight:600;color:#888;margin-top:2px;">${s}</div>
  </div>`
        )
        .join("");

    const modulesHtml = (meta.modulesRun || [])
        .map(
            (m) =>
                `<span style="background:#dfe6e9;padding:2px 8px;border-radius:10px;font-size:0.75rem;">${m}</span>`
        )
        .join(" ");

    const auditTypeMap = {
        host: "🖥️ Host",
        network: "🌐 Red",
        image: "📦 Imagen",
    };
    const auditTypeLabel =
        auditTypeMap[report.auditType] || report.targetType || "Auditoría";

    return `
  <div style="padding:20px;">

    <div style="background:linear-gradient(135deg,${severityColor(max)}22,#fff);border:1px solid ${severityColor(max)}55;border-radius:10px;padding:16px 20px;margin-bottom:20px;">
      <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
        <div style="font-size:2rem;">${severityIcon(max)}</div>
        <div>
          <div style="font-size:0.75rem;font-weight:600;color:#888;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:2px;">
            ${auditTypeLabel}
          </div>
          <div style="font-size:1rem;font-weight:700;color:${severityColor(hostMax)};">Riesgo: ${hostMax}</div>
          ${imageMax
            ? `
            <div style="font-size:0.9rem;font-weight:600;color:${severityColor(imageMax)};margin-top:2px;">
              Riesgo en imágenes: ${imageMax}
            </div>`
            : ""
        }
          <div style="font-size:0.82rem;color:#666;margin-top:4px;">
            ${host.hostname || "?"} · ${host.platform || "?"} · ${host.arch || ""} · uptime ${Math.round((host.uptimeSec || 0) / 3600)}h
          </div>
          <div style="font-size:0.78rem;color:#888;margin-top:2px;">
            Módulos: ${modulesHtml || "—"} · Duración: ${meta.durationMs || "?"}ms
          </div>
        </div>
      </div>
    </div>

    <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:8px;">
      ${countersHtml}
    </div>

    <p style="margin:0 0 12px;font-size:0.8rem;color:#666;">
      Riesgo global: ${summary.maxSeverity || hostMax}
    </p>

    <h3 style="margin:0 0 12px;font-size:1rem;color:#2d3436;">Hallazgos</h3>
    ${findingsHtml}

  </div>`;
}

// ── Render del dashboard completo ───────────────────────────────────────────

function renderDashboard(reports) {
    const devices = {};
    for (const r of reports) {
        const key = r.host?.hostname || "unknown";
        if (!devices[key]) devices[key] = [];
        devices[key].push(r);
    }

    for (const key of Object.keys(devices)) {
        devices[key].sort((a, b) => new Date(b.scanId) - new Date(a.scanId));
    }

    const deviceKeys = Object.keys(devices);

    const sidebarHtml = deviceKeys
        .map((key, di) => {
            const latest = devices[key][0];
            const max = latest?.summary?.maxSeverity || "INFO";
            const label = latest?.deviceLabel || key;
            const lastScan = latest?.scanId
                ? new Date(latest.scanId).toLocaleString("es-ES")
                : "—";

            return `
    <div class="device-item ${di === 0 ? "active" : ""}"
         onclick="selectDevice(${di})"
         id="device-btn-${di}"
         style="padding:12px 16px;cursor:pointer;border-left:4px solid ${di === 0 ? severityColor(max) : "transparent"};
                background:${di === 0 ? "#f8f9fa" : "transparent"};transition:all 0.2s;">
      <div style="display:flex;align-items:center;gap:8px;">
        <span style="font-size:1.1rem;">${severityIcon(max)}</span>
        <div style="flex:1;min-width:0;">
          <div style="font-weight:600;font-size:0.9rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${escHtml(label)}</div>
          <div style="font-size:0.72rem;color:#888;margin-top:1px;">${lastScan}</div>
          <div style="font-size:0.7rem;color:#aaa;">${devices[key].length} auditoría${devices[key].length > 1 ? "s" : ""}</div>
        </div>
      </div>
    </div>`;
        })
        .join("");

    const mainPanelsHtml = deviceKeys
        .map((key, di) => {
            const audits = devices[key];

            const tabsHtml = audits
                .map((r, ai) => {
                    const label = r.scanId
                        ? new Date(r.scanId).toLocaleString("es-ES")
                        : `Auditoría ${ai + 1}`;
                    const max = r.summary?.maxSeverity || "INFO";
                    return `
      <button onclick="selectAudit(${di},${ai})"
              id="audit-tab-${di}-${ai}"
              style="padding:6px 12px;border:none;border-radius:20px;cursor:pointer;font-size:0.78rem;font-weight:600;
                     background:${ai === 0 ? severityColor(max) : "#ecf0f1"};
                     color:${ai === 0 ? "#fff" : "#555"};
                     transition:all 0.2s;white-space:nowrap;">
        ${severityIcon(max)} ${escHtml(label)}
      </button>`;
                })
                .join("");

            const auditContentsHtml = audits
                .map(
                    (r, ai) => `
      <div id="audit-content-${di}-${ai}" style="display:${ai === 0 ? "block" : "none"};">
        ${renderAuditPanel(r, `${di}-${ai}`)}
      </div>`
                )
                .join("");

            return `
    <div id="device-panel-${di}" style="display:${di === 0 ? "block" : "none"};height:100%;overflow-y:auto;">
      <div style="padding:16px 20px 8px;border-bottom:1px solid #eee;background:#fff;position:sticky;top:0;z-index:10;">
        <h2 style="margin:0 0 4px;font-size:1.1rem;">${escHtml(devices[key][0]?.deviceLabel || key)}</h2>
        <p style="margin:0;font-size:0.78rem;color:#888;">${key} · ${audits[0]?.host?.platform || ""} · ${audits[0]?.host?.arch || ""}</p>
        <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:10px;padding-bottom:4px;overflow-x:auto;">
          ${tabsHtml}
        </div>
      </div>
      ${auditContentsHtml}
    </div>`;
        })
        .join("");

    const totalDevices = deviceKeys.length;
    const totalAudits = reports.length;
    const generatedAt = new Date().toLocaleString("es-ES");

    return `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>LCAudit Dashboard</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f0f2f5; color: #2d3436; display: flex; flex-direction: column; height: 100vh; overflow: hidden; }

    #topbar { background: #1e1e2e; color: #fff; padding: 12px 24px; display: flex; align-items: center; gap: 16px; flex-shrink: 0; }
    #topbar h1 { font-size: 1.1rem; font-weight: 700; letter-spacing: 0.5px; }
    #topbar .meta { font-size: 0.75rem; color: #a0a0b0; margin-left: auto; }

    #layout { display: flex; flex: 1; overflow: hidden; }

    #sidebar { width: 260px; background: #fff; border-right: 1px solid #e0e0e0; overflow-y: auto; flex-shrink: 0; }
    #sidebar-header { padding: 14px 16px; border-bottom: 1px solid #eee; font-size: 0.78rem; color: #888; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }

    #main { flex: 1; overflow: hidden; position: relative; }

    .device-item:hover { background: #f8f9fa !important; }

    details summary::-webkit-details-marker { display: none; }
    details summary::before { content: "▶ "; font-size: 0.75rem; }
    details[open] summary::before { content: "▼ "; }

    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: #f0f0f0; }
    ::-webkit-scrollbar-thumb { background: #c0c0c0; border-radius: 3px; }
  </style>
</head>
<body>

<div id="topbar">
  <span style="font-size:1.4rem;">🛡️</span>
  <h1>LCAudit Dashboard</h1>
  <span class="meta">${totalDevices} dispositivo${totalDevices !== 1 ? "s" : ""} · ${totalAudits} auditoría${totalAudits !== 1 ? "s" : ""} · Generado: ${generatedAt}</span>
</div>

<div id="layout">
  <div id="sidebar">
    <div id="sidebar-header">Dispositivos auditados (${totalDevices})</div>
    ${sidebarHtml || '<p style="padding:20px;color:#aaa;font-size:0.85rem;">Sin auditorías registradas.</p>'}
  </div>
  <div id="main">
    ${mainPanelsHtml || '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:#aaa;">Sin datos disponibles.</div>'}
  </div>
</div>

<script>
  var _currentDevice = 0;

  function selectDevice(di) {
    document.querySelectorAll('[id^="device-panel-"]').forEach(function(el) { el.style.display = "none"; });
    document.querySelectorAll('[id^="device-btn-"]').forEach(function(el) {
      el.style.background = "transparent";
      el.style.borderLeftColor = "transparent";
    });

    var panel = document.getElementById("device-panel-" + di);
    var btn = document.getElementById("device-btn-" + di);
    if (panel) panel.style.display = "block";
    if (btn) { btn.style.background = "#f8f9fa"; btn.style.borderLeftColor = "#6c5ce7"; }
    _currentDevice = di;
  }

  function selectAudit(di, ai) {
    var idx = 0;
    while (true) {
      var el = document.getElementById("audit-content-" + di + "-" + idx);
      if (!el) break;
      el.style.display = "none";
      idx++;
    }
    idx = 0;
    while (true) {
      var tab = document.getElementById("audit-tab-" + di + "-" + idx);
      if (!tab) break;
      tab.style.background = "#ecf0f1";
      tab.style.color = "#555";
      idx++;
    }

    var content = document.getElementById("audit-content-" + di + "-" + ai);
    var activeTab = document.getElementById("audit-tab-" + di + "-" + ai);
    if (content) content.style.display = "block";
    if (activeTab) { activeTab.style.background = "#6c5ce7"; activeTab.style.color = "#fff"; }
  }

  function toggleDetail(uid) {
    var el = document.getElementById(uid);
    if (el) el.style.display = el.style.display === "none" ? "block" : "none";
  }

  function toggleExtraVulns(auditIndex) {
    var wrapper = document.getElementById("vuln-extra-wrapper-" + auditIndex);
    if (!wrapper) return;
    var btn = event.target;
    var visible = wrapper.style.display === "block";
    wrapper.style.display = visible ? "none" : "block";
    if (btn) {
      btn.textContent = visible
        ? "Mostrar más vulnerabilidades"
        : "Ocultar vulnerabilidades adicionales";
    }
  }
</script>
</body>
</html>`;
}

// ── API Pública ─────────────────────────────────────────────────────────────

/**
 * Lee todos los JSON de auditoría del directorio y regenera dashboard.html.
 * @param {string} baseDir
 * @returns {string} Ruta del dashboard.html generado.
 */
function generateDashboard(baseDir) {
    const files = fs
        .readdirSync(baseDir)
        .filter((f) => f.startsWith("audit-") && f.endsWith(".json"))
        .sort();

    const reports = [];
    for (const file of files) {
        try {
            const raw = fs.readFileSync(path.join(baseDir, file), "utf8");
            reports.push(JSON.parse(raw));
        } catch (_) {
            /* skip ficheros corruptos */
        }
    }

    const html = renderDashboard(reports);
    const outPath = path.join(baseDir, "dashboard.html");
    fs.writeFileSync(outPath, html, "utf8");
    return outPath;
}

module.exports = {
    generateDashboard,
    renderDashboard,
    renderAuditPanel,
    severityColor,
    severityIcon,
    severityBadge,
};
