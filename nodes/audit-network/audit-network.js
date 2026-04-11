"use strict";

/**
 * audit-network — Nodo de auditoría de red (escaneo de subred) para Node-RED.
 *
 * Herramientas: nmap (host discovery + port scan), nuclei
 */

module.exports = function (RED) {
    function AuditNetworkNode(config) {
        RED.nodes.createNode(this, config);
        // TODO: implementar
    }

    RED.nodes.registerType("audit-network", AuditNetworkNode);
};
