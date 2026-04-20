"use strict";

/**
 * test-image-audit.js — Test manual del flujo completo de audit-image.
 *
 * Prueba: getDockerInfo → auditDockerConfig → runTrivyImage → normalizeImage → summarize
 *
 * Uso: node test/manual/test-image-audit.js
 */

const { getDockerInfo }     = require("../../nodes/audit-image/modules/docker-api");
const { auditDockerConfig } = require("../../nodes/audit-image/modules/config-audit");
const { runTrivyImage }     = require("../../nodes/audit-image/modules/cve-checker");
const { normalizeImage }    = require("../../lib/normalizer");
const { summarize }         = require("../../lib/severity-map");

// ── Helpers ───────────────────────────────────────────────────────────────────

function sep(title) {
  console.log(`\n${"─".repeat(60)}`);
  if (title) console.log(`  ${title}`);
  console.log("─".repeat(60));
}

function imageRef(img) {
  if (!img.repository || img.repository === "<none>" ||
      !img.tag        || img.tag        === "<none>") {
    return img.id;
  }
  return `${img.repository}:${img.tag}`;
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  const startTime = Date.now();

  // 1. Docker info
  sep("1. Docker info");
  const docker = await getDockerInfo();

  if (docker.skipped) {
    console.log(`Docker no disponible: ${docker.reason}`);
    process.exit(0);
  }

  console.log(`Imágenes encontradas:    ${docker.images.length}`);
  console.log(`Contenedores encontrados: ${docker.containers.length}`);

  if (docker.images.length > 0) {
    console.log("\nImágenes:");
    for (const img of docker.images) {
      const sizeMB = img.sizeBytes ? `${(img.sizeBytes / 1e6).toFixed(0)} MB` : "?";
      console.log(`  · ${imageRef(img).padEnd(45)} ${sizeMB}`);
    }
  }

  if (docker.containers.length > 0) {
    console.log("\nContenedores:");
    for (const c of docker.containers) {
      const state = c.running ? "running" : "stopped";
      console.log(`  · ${c.name.padEnd(30)} image=${c.image.padEnd(25)} [${state}]`);
    }
  }

  // 2. Auditorías en paralelo
  sep("2. Auditorías en paralelo (config + trivy)");
  console.log("Ejecutando...");

  const [configResult, trivyResult] = await Promise.allSettled([
    auditDockerConfig(docker),
    runTrivyImage(docker.images),
  ]);

  // 3. Config-audit findings
  sep("3. Findings de configuración (config-audit)");

  const configFindings = configResult.status === "fulfilled" ? configResult.value : [];

  if (configResult.status === "rejected") {
    console.log(`config-audit falló: ${configResult.reason}`);
  } else {
    console.log(`Findings de configuración: ${configFindings.length}`);
    for (const f of configFindings) {
      console.log(`  [${f.severity.toUpperCase().padEnd(8)}] ${f.id.padEnd(20)} ${f.title}`);
    }
    if (configFindings.length === 0) {
      console.log("  (ninguno)");
    }
  }

  // 4. Trivy section
  sep("4. CVEs en imágenes (trivy image)");

  const trivy = trivyResult.status === "fulfilled" ? trivyResult.value : null;

  let trivyFindings = [];

  if (trivyResult.status === "rejected") {
    console.log(`Trivy falló: ${trivyResult.reason}`);
  } else if (!trivy || trivy.skipped) {
    console.log(`Trivy no disponible: ${trivy ? trivy.reason : "resultado nulo"}`);
  } else {
    console.log(`Imágenes escaneadas: ${trivy.imagesScanned}, saltadas: ${trivy.imagesSkipped}`);
    trivyFindings = normalizeImage(trivy, "trivy");
    console.log(`Findings de Trivy:   ${trivyFindings.length}`);

    const shown = trivyFindings.slice(0, 20);
    for (const f of shown) {
      console.log(`  [${f.severity.toUpperCase().padEnd(8)}] ${f.id.padEnd(20)} ${f.title.slice(0, 70)}`);
    }
    if (trivyFindings.length > 20) {
      console.log(`  ...y ${trivyFindings.length - 20} más`);
    }
    if (trivyFindings.length === 0) {
      console.log("  (ninguno)");
    }
  }

  // 5. Resumen final
  sep("5. Resumen final");

  const allFindings = [...configFindings, ...trivyFindings];
  const summary = summarize(allFindings);
  const durationMs = Date.now() - startTime;

  console.log(`Total findings:  ${allFindings.length}`);
  console.log(`Severidad máxima: ${summary.maxSeverity ?? "ninguna"}`);
  console.log(`Duración total:  ${durationMs} ms`);
  console.log("\nPor severidad:");
  const order = ["critical", "high", "medium", "low", "info"];
  for (const sev of order) {
    const count = summary.counts?.[sev] ?? 0;
    if (count > 0) {
      console.log(`  ${sev.padEnd(10)} ${count}`);
    }
  }

  sep();
}

main().catch((err) => {
  console.error("Error fatal:", err);
  process.exit(1);
});
