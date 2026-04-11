"use strict";

/**
 * audit-host — Nodo de auditoría de host individual para Node-RED.
 *
 * Herramientas: systemInfo, networkInfo, nmap, httpFingerprint, nuclei
 */

module.exports = function (RED) {
    function AuditHostNode(config) {
        RED.nodes.createNode(this, config);
        // TODO: implementar
    }

    RED.nodes.registerType("audit-host", AuditHostNode);
};
