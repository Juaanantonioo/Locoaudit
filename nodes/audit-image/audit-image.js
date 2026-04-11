"use strict";

/**
 * audit-image — Nodo de auditoría de imágenes de contenedor para Node-RED.
 *
 * Herramientas: trivy
 */

module.exports = function (RED) {
    function AuditImageNode(config) {
        RED.nodes.createNode(this, config);
        // TODO: implementar
    }

    RED.nodes.registerType("audit-image", AuditImageNode);
};
