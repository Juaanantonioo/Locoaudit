"use strict";

/**
 * build-dashboards.js — Copia lib/snapshot-body.txt como cuerpo de _buildHtmlReport() en los 3 ui_template.
 * Idempotente: también asegura el sentinel LCA-STYLE-DASH y la clase lca-report-root.
 *
 *   node scripts/build-dashboards.js          → aplica
 *   node scripts/build-dashboards.js --check  → solo verifica (no escribe)
 */

const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const BODY_FILE = path.join(ROOT, "lib", "snapshot-body.txt");
const TEMPLATES = [
  { file: "examples/dashboard-host-template.html", type: "host" },
  { file: "examples/dashboard-network-template.html", type: "network" },
  { file: "examples/dashboard-image-template.html", type: "image" },
];

function methodText() {
  const body = fs.readFileSync(BODY_FILE, "utf8").replace(/\s+$/, "");
  return (
    "_buildHtmlReport() {\n" +
    "      try {\n" +
    "        // LCA:SNAPSHOT:START — única fuente: lib/snapshot-body.txt (build-dashboards.js). NO EDITAR.\n" +
    body + "\n" +
    "        // LCA:SNAPSHOT:END\n" +
    "      } catch (e) {\n" +
    "        console.error('[LoCoAudit] export snapshot fallo, uso tabla de respaldo:', e);\n" +
    "        return this._buildHtmlReportFallback();\n" +
    "      }\n" +
    "    },\n" +
    "    _buildHtmlReportFallback()"
  );
}

// Quita el IIFE de export de versiones anteriores (si existiera).
function stripOldLib(txt) {
  return txt.replace(/\n?\/\* LCA:EXPORT-LIB[\s\S]*?\/\* \/LCA:EXPORT-LIB \*\/\n?/g, "\n");
}

// Reemplaza el método completo _buildHtmlReport()…_buildHtmlReportFallback().
function replaceMethod(txt, method) {
  const re = /_buildHtmlReport\(\) \{[\s\S]*?\n {4}_buildHtmlReportFallback\(\)/;
  if (!re.test(txt)) return { txt, ok: false };
  return { txt: txt.replace(re, method), ok: true };
}

function ensureSentinel(txt, type) {
  const tag = "LCA-STYLE-DASH:" + type;
  if (txt.indexOf(tag) >= 0) return txt;
  const specific = "/*" + tag + " — fuente única de estilo del export*/";
  if (/\/\*\s*LCA-STYLE-DASH[^*]*\*\//.test(txt)) {
    return txt.replace(/\/\*\s*LCA-STYLE-DASH[^*]*\*\//, specific);
  }
  return txt.replace(/^<style>\r?\n/m, "<style>\n  " + specific + "\n");
}

function ensureReportRoot(txt) {
  if (/state === 'done' && auditData"\s+class="lca-report-root"/.test(txt)) return txt;
  return txt.replace(
    /<div v-if="state === 'done' && auditData">/,
    '<div v-if="state === \'done\' && auditData" class="lca-report-root">'
  );
}

function main() {
  const check = process.argv.includes("--check");
  const method = methodText();
  let changed = 0;
  let problems = 0;

  for (const { file: rel, type } of TEMPLATES) {
    const file = path.join(ROOT, rel);
    const orig = fs.readFileSync(file, "utf8");
    let out = stripOldLib(orig);
    out = ensureSentinel(out, type);
    out = ensureReportRoot(out);
    const r = replaceMethod(out, method);
    out = r.txt;

    const okMethod = r.ok && out.includes("LCA:SNAPSHOT:START");
    const okSentinel = out.indexOf("LCA-STYLE-DASH:" + type) >= 0;
    const okRoot = out.indexOf("lca-report-root") >= 0;
    const noGlobal = out.indexOf("window.LCA_EXPORT") < 0 && out.indexOf("LCA:EXPORT-LIB") < 0;
    if (!okMethod || !okSentinel || !okRoot || !noGlobal) {
      problems++;
      console.log(`✗ ${rel}: method=${okMethod} sentinel=${okSentinel} report-root=${okRoot} sin-global=${noGlobal}`);
      continue;
    }

    if (out !== orig) {
      if (check) { problems++; console.log(`✗ ${rel}: desactualizado (ejecuta build sin --check)`); }
      else { fs.writeFileSync(file, out); changed++; console.log(`✓ ${rel}: actualizado`); }
    } else {
      console.log(`= ${rel}: ya al día`);
    }
  }

  if (problems) { console.log(`\n${problems} problema(s).`); process.exit(1); }
  console.log(check ? "\nTemplates al día." : `\nListo (${changed} actualizado/s).`);
}

main();
