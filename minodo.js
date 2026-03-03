/**
 * MINODO - Módulo de Auditoría de Seguridad para Node-RED
 *
 * Incluye:
 * - Auditoría sistema (CPU/memoria)
 * - Auditoría red
 * - Escaneo de puertos (Nmap)
 * - Escaneo vulnerabilidades (Trivy)
 * - Fingerprinting HTTP/HTTPS (headers, title, señales tecnológicas)
 */

module.exports = function (RED) {
  const os = require("os");
  const fs = require("fs");
  const path = require("path");
  const { execFile } = require("child_process");
  const http = require("http");
  const https = require("https");
  const { generateDashboard } = require("./reportGenerator");


  // ========== HELPERS ==========

  function safeFileName(iso) {
    return iso.replace(/[:.]/g, "-");
  }

  function bytesToMiB(bytes) {
    return Math.round((bytes / (1024 * 1024)) * 10) / 10;
  }

  function bytesToGiB(bytes) {
    return Math.round((bytes / (1024 * 1024 * 1024)) * 100) / 100;
  }

  function severityRank(s) {
    const map = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
    if (map[s] !== undefined) return map[s];
    return 0;
  }

  /**
   * Mapea severidad de Trivy a severidad interna del nodo.
   * UNKNOWN/NEGLIGIBLE/NONE => INFO (como pediste).
   */
  function mapTrivySeverityToNodeSeverity(trivySeverity) {
    const s = String(trivySeverity || "").trim().toUpperCase();
    if (s === "CRITICAL") return "CRITICAL";
    if (s === "HIGH") return "HIGH";
    if (s === "MEDIUM") return "MEDIUM";
    if (s === "LOW") return "LOW";
    return "INFO";
  }

  function summarize(findings) {
    const counts = { INFO: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
    let max = "INFO";

    for (const f of findings) {
      counts[f.severity] = (counts[f.severity] || 0) + 1;

      // Ignorar performance en el riesgo global
      if (f.category !== "performance") {
        if (severityRank(f.severity) > severityRank(max)) {
          max = f.severity;
        }
      }
    }

    return { maxSeverity: max, counts };
  }

  function which(cmd) {
    const paths = (process.env.PATH || "").split(path.delimiter);
    for (const p of paths) {
      const full = path.join(p, cmd);
      try {
        if (fs.existsSync(full)) return full;
        if (process.platform === "win32" && fs.existsSync(full + ".exe")) return full + ".exe";
      } catch (_) {}
    }
    return null;
  }

  function execFilePromise(file, args, opts = {}) {
    return new Promise((resolve, reject) => {
      execFile(file, args, { ...opts, maxBuffer: 10 * 1024 * 1024 }, (err, stdout, stderr) => {
        if (err) {
          err.stdout = stdout;
          err.stderr = stderr;
          reject(err);
        } else {
          resolve({ stdout, stderr });
        }
      });
    });
  }

  function parsePortsList(input) {
    const s = (input || "").trim();
    if (!s) return null;

    const ports = new Set();
    const parts = s.split(",").map((x) => x.trim()).filter(Boolean);

    for (const p of parts) {
      if (p.includes("-")) {
        const [a, b] = p.split("-").map((x) => parseInt(x.trim(), 10));
        if (!Number.isNaN(a) && !Number.isNaN(b) && a > 0 && b <= 65535 && a <= b) {
          for (let i = a; i <= b; i++) ports.add(i);
        }
      } else {
        const n = parseInt(p, 10);
        if (!Number.isNaN(n) && n > 0 && n <= 65535) ports.add(n);
      }
    }

    return Array.from(ports).sort((x, y) => x - y);
  }

  function isLocalTarget(t) {
    const target = (t || "").trim().toLowerCase();
    return target === "127.0.0.1" || target === "localhost" || target === "::1";
  }

  // ========== MÓDULOS ==========

  function runSystemModule() {
    const cpus = os.cpus() || [];
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;
    const freeRatio = totalMem > 0 ? freeMem / totalMem : null;

    return {
      cpu: {
        model: cpus[0]?.model || "unknown",
        cores: cpus.length,
        loadAvg: typeof os.loadavg === "function" ? os.loadavg() : null,
      },
      memory: {
        totalBytes: totalMem,
        freeBytes: freeMem,
        usedBytes: usedMem,
        totalGiB: bytesToGiB(totalMem),
        freeMiB: bytesToMiB(freeMem),
        usedGiB: bytesToGiB(usedMem),
        freeRatio,
      },
    };
  }

  function runNetworkModule() {
    const ifaces = os.networkInterfaces ? os.networkInterfaces() : {};
    const externalIPv4 = {};

    for (const [name, addrs] of Object.entries(ifaces || {})) {
      const v4 = (addrs || []).filter((a) => a.family === "IPv4" && a.internal === false);
      if (v4.length > 0) {
        externalIPv4[name] = v4.map((a) => ({
          address: a.address,
          cidr: a.cidr,
          mac: a.mac,
        }));
      }
    }

    let primaryIPv4 = null;
    for (const name of Object.keys(externalIPv4)) {
      const addr = externalIPv4[name]?.[0]?.address;
      if (addr) {
        primaryIPv4 = addr;
        break;
      }
    }

    return { primaryIPv4, externalIPv4 };
  }

  // ========== PUERTOS (NMAP) ==========

  const DEFAULT_PORTS = [22, 53, 80, 443, 445, 1880, 3389, 5900, 8080, 3306, 5432, 6379, 27017];

  function parseNmapGrepable(output) {
    const openPorts = [];
    const lines = output.split("\n");
    for (const line of lines) {
      const idx = line.indexOf("Ports:");
      if (idx === -1) continue;

      const portsPart = line.slice(idx + "Ports:".length).trim();
      const entries = portsPart.split(",");

      for (const e of entries) {
        const part = e.trim();
        const bits = part.split("/");
        const port = parseInt(bits[0], 10);
        const state = bits[1];
        const proto = bits[2];
        const service = bits[4] || null;

        if (!Number.isNaN(port) && state === "open") {
          openPorts.push({ port, protocol: proto || "tcp", service });
        }
      }
    }
    return openPorts;
  }

  async function runPortsNmap(target, portsToTest, serviceDetect) {
    const nmapPath = which("nmap");
    if (!nmapPath) {
      return {
        mode: "nmap",
        target,
        available: false,
        portsTested: portsToTest,
        openPorts: [],
        note: "nmap no está instalado o no está en PATH",
      };
    }

    const args = ["-Pn", "-sT"];
    if (serviceDetect) args.push("-sV");
    args.push("--host-timeout", "20s", "-p", portsToTest.join(","), "-oG", "-", target);

    const { stdout } = await execFilePromise(nmapPath, args, { timeout: 30000 });
    const openPorts = parseNmapGrepable(stdout);

    return {
      mode: "nmap",
      target,
      available: true,
      portsTested: portsToTest,
      openPorts,
      serviceDetect: !!serviceDetect,
    };
  }

  async function runPortsModule(target, mode, portsToTest, serviceDetect) {
    return await runPortsNmap(target, portsToTest, serviceDetect);
  }

  // ========== TRIVY ==========

  async function runVulnTrivy(target) {
    const trivyPath = which("trivy");

    if (!trivyPath) {
      return {
        mode: "trivy",
        available: false,
        target,
        vulnerabilities: [],
        note: "trivy no está instalado o no está en PATH",
      };
    }

    const args = ["fs", "--quiet", "-f", "json", target];

    try {
      const { stdout } = await execFilePromise(trivyPath, args, { timeout: 60000 });

      let parsed;
      try {
        parsed = JSON.parse(stdout);
      } catch {
        parsed = null;
      }

      return {
        mode: "trivy",
        available: true,
        target,
        raw: parsed,
      };
    } catch (err) {
      return {
        mode: "trivy",
        available: true,
        target,
        error: err.message,
      };
    }
  }

  function parseTrivyFindings(trivyReport) {
    const vulns = [];

    if (!trivyReport) return vulns;
    if (!trivyReport.raw) return vulns;
    if (!trivyReport.raw.Results) return vulns;

    const results = trivyReport.raw.Results;
    for (const result of results) {
      const vulnerabilities = result.Vulnerabilities || [];
      for (const v of vulnerabilities) {
        const vulnerability = {
          id: v.VulnerabilityID,
          severity: v.Severity || "UNKNOWN",
          package: v.PkgName,
          installedVersion: v.InstalledVersion,
          fixedVersion: v.FixedVersion || null,
          title: v.Title || null,
          description: v.Description || null,
        };
        vulns.push(vulnerability);
      }
    }

    return vulns;
  }

  // ========== HTTP FINGERPRINTING ==========

  function toBaseUrl(protocol, host, port) {
    const defaultPort = protocol === "https" ? 443 : 80;
    const showPort = port !== defaultPort;
    return `${protocol}://${host}${showPort ? ":" + port : ""}`;
  }

  function extractTitle(html) {
    if (!html) return null;
    const m = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
    if (!m) return null;
    const t = m[1].replace(/\s+/g, " ").trim();
    return t || null;
  }

  function detectTechHints(headers, bodyText) {
    const hints = new Set();

    const h = headers || {};
    const server = String(h["server"] || "");
    const powered = String(h["x-powered-by"] || "");
    const ct = String(h["content-type"] || "");

    if (server) hints.add(`server:${server}`);
    if (powered) hints.add(`x-powered-by:${powered}`);
    if (ct) hints.add(`content-type:${ct}`);

    const body = (bodyText || "").toLowerCase();

    // Señales comunes
    if (body.includes("node-red") || body.includes("nodered")) hints.add("node-red");
    if (body.includes("express")) hints.add("express");
    if (body.includes("nginx")) hints.add("nginx");
    if (body.includes("apache")) hints.add("apache");
    if (body.includes("grafana")) hints.add("grafana");
    if (body.includes("prometheus")) hints.add("prometheus");

    // Headers también pueden indicar Node-RED / Express
    if (powered.toLowerCase().includes("express")) hints.add("express");
    if (server.toLowerCase().includes("nginx")) hints.add("nginx");
    if (server.toLowerCase().includes("apache")) hints.add("apache");

    return Array.from(hints);
  }

  function isProbablyNodeRed(headers, bodyText, title) {
    const h = headers || {};
    const powered = String(h["x-powered-by"] || "").toLowerCase();
    const server = String(h["server"] || "").toLowerCase();
    const t = String(title || "").toLowerCase();
    const b = String(bodyText || "").toLowerCase();

    // Señales típicas (heurísticas)
    if (b.includes("node-red")) return true;
    if (t.includes("node-red")) return true;
    if (powered.includes("express") && (b.includes("red") && b.includes("flows"))) return true;

    // Algunas instalaciones de Node-RED pueden ir detrás de nginx/apache
    if ((server.includes("nginx") || server.includes("apache")) && b.includes("node-red")) return true;

    return false;
  }

  /**
   * Hace GET / con límite de bytes y timeout.
   * allowInsecure: si true, permite https self-signed (útil en LAN/lab).
   */
  function httpGetWithLimit(url, { timeoutMs = 2500, maxBytes = 256 * 1024, allowInsecure = false } = {}) {
    return new Promise((resolve) => {
      let finished = false;
      const finish = (data) => {
        if (finished) return;
        finished = true;
        resolve(data);
      };

      try {
        const isHttps = url.startsWith("https://");
        const lib = isHttps ? https : http;

        const req = lib.request(
          url,
          {
            method: "GET",
            headers: {
              "User-Agent": "minodo-httpfp/1.0",
              "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
            },
            ...(isHttps ? { rejectUnauthorized: !allowInsecure } : {}),
          },
          (res) => {
            const headers = res.headers || {};
            const statusCode = res.statusCode || null;

            let received = 0;
            const chunks = [];

            res.on("data", (chunk) => {
              if (!chunk) return;
              received += chunk.length;

              if (received <= maxBytes) chunks.push(chunk);

              // Si nos pasamos, cortamos (fingerprint no necesita el body entero)
              if (received > maxBytes) {
                try { req.destroy(); } catch (_) {}
              }
            });

            res.on("end", () => {
              const buf = Buffer.concat(chunks);
              const bodySnippet = buf.toString("utf8");
              finish({ ok: true, url, statusCode, headers, bodySnippet });
            });
          }
        );

        req.setTimeout(timeoutMs, () => {
          try { req.destroy(); } catch (_) {}
          finish({ ok: false, url, error: "timeout" });
        });

        req.on("error", (err) => {
          finish({ ok: false, url, error: err.code || err.message || "error" });
        });

        req.end();
      } catch (e) {
        finish({ ok: false, url, error: e.message || "exception" });
      }
    });
  }

  /**
   * Ejecuta fingerprinting HTTP/HTTPS en puertos web abiertos.
   * Solo usa los puertos abiertos del reporte de puertos.
   */
  async function runHttpFingerprintModule(portsReport, options = {}) {
    const {
      allowInsecure = false,
      timeoutMs = 2500,
      maxBytes = 256 * 1024,
      portsCandidate = [80, 443, 1880, 8080],
    } = options;

    if (!portsReport || portsReport.available === false) {
      return {
        mode: "httpfp",
        available: false,
        note: "no hay reporte de puertos disponible para fingerprinting",
        endpoints: [],
      };
    }

    const target = portsReport.target;
    const openPorts = (portsReport.openPorts || []).map((p) => p.port);
    const openSet = new Set(openPorts);

    // Solo puertos candidatos que estén abiertos
    const portsToProbe = portsCandidate.filter((p) => openSet.has(p));

    const endpoints = [];
    for (const port of portsToProbe) {
      const protocol = port === 443 ? "https" : "http";
      const base = toBaseUrl(protocol, target, port);
      const url = `${base}/`;

      const r = await httpGetWithLimit(url, { timeoutMs, maxBytes, allowInsecure });

      if (!r.ok) {
        endpoints.push({
          target,
          port,
          protocol,
          url,
          ok: false,
          error: r.error,
        });
        continue;
      }

      const title = extractTitle(r.bodySnippet);
      const techHints = detectTechHints(r.headers, r.bodySnippet);
      const nodeRedDetected = isProbablyNodeRed(r.headers, r.bodySnippet, title);

      endpoints.push({
        target,
        port,
        protocol,
        url,
        ok: true,
        statusCode: r.statusCode,
        headers: r.headers,
        title,
        techHints,
        nodeRedDetected,
        snippet: (r.bodySnippet || "").slice(0, 600),
      });
    }

    return {
      mode: "httpfp",
      available: true,
      target: portsReport.target,
      endpoints,
    };
  }

  // ========== FINDINGS ==========

  function addPortFindings(findings, portsReport, network) {
    if (!portsReport) return;

    if (portsReport.mode === "nmap" && portsReport.available === false) {
      findings.push({
        id: "NMAP_NOT_AVAILABLE",
        severity: "LOW",
        title: "Nmap no disponible",
        evidence: { target: portsReport.target },
        recommendation: "Instalar nmap y volver a ejecutar para un escaneo de puertos más completo.",
      });
      return;
    }

    const open = portsReport.openPorts || [];
    if (open.length === 0) {
      findings.push({
        id: "NO_OPEN_PORTS_DETECTED",
        severity: "INFO",
        title: "No se detectaron puertos abiertos en el objetivo",
        evidence: { target: portsReport.target, portsTested: portsReport.portsTested || DEFAULT_PORTS },
        recommendation: "Sin acción requerida.",
      });
      return;
    }

    findings.push({
      id: "OPEN_PORTS_DETECTED",
      severity: "INFO",
      title: "Puertos abiertos detectados",
      evidence: { target: portsReport.target, openPorts: open },
      recommendation: "Revisar que los servicios expuestos sean necesarios y estén restringidos.",
    });

    const openSet = new Set(open.map((p) => p.port));
    const local = isLocalTarget(portsReport.target);
    const isLanTarget = !local && network?.primaryIPv4 && portsReport.target === network.primaryIPv4;

    const sensitiveHigh = new Set([3389, 445, 5900, 3306, 5432, 6379, 27017]);
    const sensitiveMed = new Set([22, 8080, 1880]);

    const openSensitiveHigh = open.filter(p => sensitiveHigh.has(p.port)).map(p => p.port);
    const openSensitiveMed = open.filter(p => sensitiveMed.has(p.port)).map(p => p.port);

    let severity = local ? "INFO" : (isLanTarget ? "MEDIUM" : "LOW");
    if (!local) {
      if (openSensitiveHigh.length > 0) severity = "HIGH";
      else if (openSensitiveMed.length > 0 && !isLanTarget) severity = "MEDIUM";
      else if (openSensitiveMed.length > 0 && isLanTarget) severity = "MEDIUM";
    }

    const scope = local ? "localhost" : (isLanTarget ? "lan" : "non-localhost");
    const title =
      scope === "localhost"
        ? "Servicios expuestos solo en localhost"
        : (scope === "lan" ? "Servicios expuestos en red local (LAN)" : "Servicios expuestos fuera de localhost");

    const recommendation =
      scope === "localhost"
        ? "Riesgo reducido al estar accesible solo desde el propio equipo. Mantener restringido a localhost si es posible."
        : (severity === "HIGH"
            ? "Riesgo alto por exposición de servicios sensibles. Restringir acceso (firewall/VPN), cerrar puertos no necesarios, limitar binding e imponer autenticación."
            : "Restringir la exposición (firewall/VPN), limitar el binding a interfaces necesarias y habilitar autenticación.");

    findings.push({
      id: "EXPOSURE_CONTEXT",
      severity,
      title,
      evidence: {
        target: portsReport.target,
        primaryIPv4: network?.primaryIPv4 || null,
        openPorts: open,
        scope,
        sensitivePorts: { high: openSensitiveHigh, medium: openSensitiveMed }
      },
      recommendation,
    });

    if (openSet.has(1880)) {
      const local1880 = isLocalTarget(portsReport.target);
      findings.push({
        id: "NODE_RED_PORT_1880_OPEN",
        severity: local1880 ? "LOW" : "MEDIUM",
        title: local1880 ? "Node-RED accesible en localhost (1880)" : "Node-RED expuesto en red (1880)",
        evidence: { target: portsReport.target, port: 1880, primaryIPv4: network?.primaryIPv4 || null },
        recommendation: local1880
          ? "Riesgo bajo si solo está accesible localmente. Si no es necesario, restringir el binding a localhost."
          : "Restringir acceso (firewall/VPN), habilitar autenticación y evitar exposición innecesaria en la red.",
      });
    }
  }

  function addHttpFpFindings(findings, httpFpReport) {
    if (!httpFpReport) return;
    if (httpFpReport.available === false) return;

    const endpoints = httpFpReport.endpoints || [];
    if (endpoints.length === 0) {
      findings.push({
        id: "HTTPFP_NO_ENDPOINTS",
        severity: "INFO",
        title: "Fingerprinting HTTP: no hay endpoints web abiertos para analizar",
        evidence: { target: httpFpReport.target || null },
        recommendation: "Sin acción requerida.",
      });
      return;
    }

    for (const ep of endpoints) {
      if (!ep.ok) {
        findings.push({
          id: `HTTPFP_FAILED_${ep.port}`,
          severity: "INFO",
          title: `Fingerprinting HTTP falló en ${ep.protocol.toUpperCase()} puerto ${ep.port}`,
          evidence: { url: ep.url, error: ep.error },
          recommendation: "Puede ser normal (servicio no HTTP, redirecciones raras, TLS, etc.).",
        });
        continue;
      }

      // Finding informativo base
      findings.push({
        id: `HTTPFP_${ep.port}`,
        severity: "INFO",
        title: `Fingerprinting HTTP en ${ep.protocol.toUpperCase()} puerto ${ep.port}`,
        evidence: {
          url: ep.url,
          statusCode: ep.statusCode,
          title: ep.title,
          techHints: ep.techHints,
          headers: ep.headers,
          snippet: ep.snippet,
        },
        recommendation: "Usar esta información para identificar software expuesto y endurecer configuración si aplica.",
      });

      // Finding específico si parece Node-RED
      if (ep.nodeRedDetected) {
        const local = isLocalTarget(ep.target);
        findings.push({
          id: `HTTPFP_NODE_RED_${ep.port}`,
          severity: local ? "LOW" : "MEDIUM",
          title: local ? "Node-RED detectado (solo localhost)" : "Node-RED detectado y expuesto por red",
          evidence: { url: ep.url, title: ep.title, techHints: ep.techHints },
          recommendation: local
            ? "Si no es necesario, mantenerlo en localhost y habilitar autenticación si procede."
            : "Habilitar autenticación, restringir acceso (firewall/VPN), y evitar exposición innecesaria.",
        });
      }
    }
  }

  function buildFindings(report) {
    const findings = [];

    // ===== MEMORIA =====
    const mem = report.system?.memory;
    if (mem?.freeRatio != null) {
      let sev = "INFO";
      let threshold = "OK";
      const platform = report.host?.platform;

      if (platform === "darwin") {
        if (mem.freeRatio < 0.01) { sev = "HIGH"; threshold = "HIGH < 1% (macOS)"; }
        else if (mem.freeRatio < 0.03) { sev = "MEDIUM"; threshold = "MEDIUM < 3% (macOS)"; }
        else if (mem.freeRatio < 0.07) { sev = "LOW"; threshold = "LOW < 7% (macOS)"; }
      } else {
        if (mem.freeRatio < 0.03) { sev = "HIGH"; threshold = "HIGH < 3%"; }
        else if (mem.freeRatio < 0.07) { sev = "MEDIUM"; threshold = "MEDIUM < 7%"; }
        else if (mem.freeRatio < 0.12) { sev = "LOW"; threshold = "LOW < 12%"; }
      }

      findings.push({
        id: "MEMORY_FREE_RATIO",
        severity: sev,
        category: "performance",
        title: sev === "INFO" ? "Memoria libre dentro de umbral" : "Memoria libre baja",
        evidence: { freeRatio: mem.freeRatio, freeMiB: mem.freeMiB, totalGiB: mem.totalGiB, threshold, platform },
        recommendation: sev === "INFO" ? "Sin acción requerida." : "Cerrar aplicaciones/procesos no necesarios y revisar consumo de memoria.",
      });
    }

    // ===== RED =====
    const ext = report.network?.externalIPv4 ? Object.keys(report.network.externalIPv4) : [];
    if (ext.length === 0) {
      findings.push({
        id: "NO_EXTERNAL_IPV4",
        severity: "LOW",
        title: "No se detectó IPv4 externa",
        evidence: {},
        recommendation: "Revisar conectividad de red o configuración de interfaces.",
      });
    } else {
      findings.push({
        id: "EXTERNAL_IPV4_DETECTED",
        severity: "INFO",
        title: "IPv4 externa detectada",
        evidence: { interfaces: ext, primaryIPv4: report.network?.primaryIPv4 || null },
        recommendation: "Sin acción requerida.",
      });
    }

    // ===== PUERTOS =====
    addPortFindings(findings, report.ports, report.network);

    // ===== HTTP FP =====
    addHttpFpFindings(findings, report.httpFingerprint);

    // ===== TRIVY =====
    const vulnReport = report.vulnerabilities;
    if (!vulnReport) return findings;

    if (vulnReport.available === false) {
      findings.push({
        id: "TRIVY_NOT_AVAILABLE",
        severity: "LOW",
        title: "Trivy no disponible",
        evidence: { target: vulnReport.target || "unknown" },
        recommendation: "Instalar Trivy para habilitar el escaneo de vulnerabilidades del sistema.",
      });
      return findings;
    }

    const vulnerabilities = Array.isArray(vulnReport.parsed) ? vulnReport.parsed : [];
    if (vulnerabilities.length === 0) {
      findings.push({
        id: "NO_VULNERABILITIES_DETECTED",
        severity: "INFO",
        title: "No se detectaron vulnerabilidades",
        evidence: { target: vulnReport.target || "unknown" },
        recommendation: "Sin acción requerida. Mantener el sistema actualizado.",
      });
      return findings;
    }

    for (const vuln of vulnerabilities) {
      const severity = mapTrivySeverityToNodeSeverity(vuln.severity);
      findings.push({
        id: `VULN_${vuln.id}`,
        severity,
        category: "vulnerability",
        title: vuln.title || `Vulnerabilidad detectada: ${vuln.id}`,
        evidence: {
          vulnerabilityId: vuln.id,
          package: vuln.package,
          installedVersion: vuln.installedVersion,
          fixedVersion: vuln.fixedVersion,
          description: vuln.description,
        },
        recommendation: vuln.fixedVersion
          ? `Actualizar ${vuln.package} de versión ${vuln.installedVersion} a ${vuln.fixedVersion} o superior.`
          : "Revisar la vulnerabilidad en bases de datos públicas y aplicar mitigaciones recomendadas.",
      });
    }

    return findings;
  }

  // ========== NODO Node-RED ==========

  function MiNodo(config) {
    RED.nodes.createNode(this, config);
    const node = this;

    node.on("input", async function (msg, send, done) {
      const _send = send || node.send.bind(node);
      const _done = done || function () {};

      const t0 = Date.now();

      try {
        node.status({ fill: "blue", shape: "dot", text: "auditando..." });

        const scanId = new Date().toISOString();

        const report = {
          scanId,
          host: {
            hostname: os.hostname(),
            platform: os.platform(),
            release: os.release(),
            arch: os.arch(),
            uptimeSec: os.uptime(),
          },
          system: null,
          network: null,
          ports: null,
          vulnerabilities: null,
          httpFingerprint: null,
          findings: [],
          summary: null,
          scanMeta: {
            modulesRun: [],
            durationMs: null,
          },
        };

        const runSystem = config.runSystem !== false;
        const runNetwork = config.runNetwork !== false;
        const runPorts = config.runPorts === true;
        const runVuln = config.runVuln === true;
        const runHttpFp = config.runHttpFp === true;

        if (runSystem) {
          report.system = runSystemModule();
          report.scanMeta.modulesRun.push("system");
        }

        if (runNetwork) {
          report.network = runNetworkModule();
          report.scanMeta.modulesRun.push("network");
        }

        if (runPorts) {
          const target = (config.portsTarget || "127.0.0.1").trim() || "127.0.0.1";
          const mode = (config.portsMode || "auto").trim();

          const customPorts = parsePortsList(config.portsList);
          const portsToTest = customPorts && customPorts.length ? customPorts : DEFAULT_PORTS;

          const serviceDetect = config.nmapServiceDetect === true;

          report.ports = await runPortsModule(target, mode, portsToTest, serviceDetect);
          report.scanMeta.modulesRun.push(`ports:${report.ports.mode}`);
        }

        // HTTP Fingerprinting (requiere ports)
        if (runHttpFp) {
          const allowInsecure = config.httpFpAllowInsecure === true;
          const timeoutMs = Number.isFinite(+config.httpFpTimeoutMs) ? +config.httpFpTimeoutMs : 2500;

          report.httpFingerprint = await runHttpFingerprintModule(report.ports, {
            allowInsecure,
            timeoutMs,
          });

          report.scanMeta.modulesRun.push("httpfp");
        }

        if (runVuln) {
          const target = (config.trivyTarget || ".").trim() || ".";
          const vulnReport = await runVulnTrivy(target);

          if (vulnReport.available) {
            vulnReport.parsed = parseTrivyFindings(vulnReport);
            // Si hubo error en ejecución, parsed quedará []
            if (vulnReport.error) vulnReport.parsed = [];
          }


          report.vulnerabilities = vulnReport;
          report.scanMeta.modulesRun.push("vulnerabilities:trivy");
        }

        report.findings = buildFindings(report);
        report.summary = summarize(report.findings);
        report.scanMeta.durationMs = Date.now() - t0;

        const saveReport = config.saveReport !== false;
        const outputPath = (config.outputPath || "").trim();

        let reportPath = null;
        let dashboardPath = null;

        if (saveReport) {
          const baseDir = outputPath || path.join(os.homedir(), "audit-reports");
          fs.mkdirSync(baseDir, { recursive: true });

          reportPath = path.join(baseDir, `audit-${safeFileName(scanId)}.json`);
          fs.writeFileSync(reportPath, JSON.stringify(report, null, 2), "utf8");

          try {
            dashboardPath = generateDashboard(baseDir);
          } catch (e) {
            node.warn("No se pudo generar el dashboard HTML: " + e.message);
          }
        }

        msg.payload = report;
        msg.audit = { saved: saveReport, reportPath, dashboardPath };
        const max = report.summary?.maxSeverity || "INFO";
        
        const statusColor =
          max === "CRITICAL" || max === "HIGH" ? "red" : max === "MEDIUM" ? "yellow" : "green";

        node.status({
          fill: statusColor,
          shape: "dot",
          text: reportPath ? `${max} (guardado)` : max,
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

  RED.nodes.registerType("minodo", MiNodo);
};