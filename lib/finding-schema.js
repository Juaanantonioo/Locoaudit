"use strict";

/**
 * finding-schema.js — Factoría y validador del objeto Finding canónico.
 *
 * Esquema Finding:
 *   {
 *     id:          string,   // UUID v4
 *     title:       string,
 *     description: string,
 *     severity:    "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
 *     category:    string,   // "port" | "vuln" | "config" | "performance" | ...
 *     scope:       string,   // "host" | "network" | "image"
 *     source:      string,   // herramienta origen ("nmap", "trivy", "nuclei", ...)
 *     target:      string,
 *     timestamp:   string,   // ISO 8601
 *     extra:       object    // datos adicionales libres
 *   }
 *
 * Exporta:
 *   create(fields) → Finding
 *   validate(obj)  → boolean
 */

// TODO: implementar

module.exports = {};
