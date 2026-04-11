"use strict";

/**
 * audit-reporter — Nodo agregador de resultados y generador de informes para Node-RED.
 *
 * Recibe findings de audit-host, audit-network y/o audit-image,
 * los consolida y emite un informe unificado (JSON / HTML).
 */

module.exports = function (RED) {
    function AuditReporterNode(config) {
        RED.nodes.createNode(this, config);
        // TODO: implementar
    }

    RED.nodes.registerType("audit-reporter", AuditReporterNode);
};
