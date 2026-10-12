"use strict";

/**
 * Lector del subárbol <script> del XML de nmap, sin dependencias.
 * No se usa xml2js porque package.json declara `"dependencies": {}` y el launcher no hace `npm install`: sería la primera
 * dependencia del proyecto y un paso de instalación nuevo en las tres plataformas, para leer cuatro formas de nodo.
 *
 * Se lee solo el subárbol estructurado (<table>, <elem>). El atributo `output` es texto para humanos, sin formato
 * especificado y cambiante entre versiones del script, así que se conserva sin interpretar como evidencia.
 * La gramática son cuatro nodos: <script>, <table> (con `key` o sin él), <elem> (con `key` o sin él) y texto dentro de <elem>.
 */

/**
 * Las cinco entidades predefinidas más las numéricas: el `output` de vulners trae `&#xa;` y `&#x9;`.
 * Una sola pasada y no cinco `.replace()` encadenados, que decodificarían dos veces (`&amp;lt;` acabaría como "<").
 * nmap-wrapper.js tiene aún su copia reducida para el `errormsg`.
 */
const ENTITY_RE = /&(?:#x([0-9a-fA-F]+)|#(\d+)|(lt|gt|quot|apos|amp));/g;
const NAMED = { lt: "<", gt: ">", quot: '"', apos: "'", amp: "&" };

function decodeXmlEntities(s) {
  return String(s == null ? "" : s).replace(ENTITY_RE, (whole, hex, dec, name) => {
    if (name) return NAMED[name];
    const code = parseInt(hex || dec, hex ? 16 : 10);
    // Un código fuera de rango se deja tal cual: preferimos evidencia fea a evidencia inventada.
    if (!Number.isFinite(code) || code < 0 || code > 0x10ffff) return whole;
    try { return String.fromCodePoint(code); } catch (e) { return whole; }
  });
}

/** attrValue('id="vulners" output="x"', "id") → "vulners". */
function attrValue(tag, attr) {
  const m = String(tag).match(new RegExp(`\\b${attr}="([^"]*)"`, "i"));
  return m ? decodeXmlEntities(m[1]) : "";
}

// <script …>, </script>, <table …>, </table>, <elem …>texto</elem>, y sus formas autocerradas.
const TAG_RE = /<(script|table|elem)\b([^>]*?)(\/?)>|<\/(script|table|elem)>/g;

/**
 * Los <script> de UN bloque <port>…</port>, como árbol: [{ id, output, children }], con hijos
 * { type: "table", key, children } | { type: "elem", key, value }. `key` es null cuando el nodo no lo trae:
 * en NSE distingue un diccionario (hijos con key) de una lista (sin key).
 */
function parseScripts(portBlock) {
  const xml     = String(portBlock || "");
  const scripts = [];
  const stack   = [];           // nodos abiertos; el último es el padre actual
  let   pending = null;         // <elem> abierto, esperando su texto
  let   textAt  = 0;            // dónde empieza ese texto

  TAG_RE.lastIndex = 0;
  let m;
  while ((m = TAG_RE.exec(xml)) !== null) {
    const [whole, openName, attrs, selfClose, closeName] = m;

    if (pending && (openName || closeName)) {
      // Cierre del <elem> abierto: todo lo que hay entre su '>' y este tag es su valor.
      pending.value = decodeXmlEntities(xml.slice(textAt, m.index));
      pending = null;
      if (closeName === "elem") continue;   // el </elem> ya no aporta nada
    }

    if (closeName) {
      if (stack.length) stack.pop();
      continue;
    }

    const parent = stack[stack.length - 1] || null;

    if (openName === "script") {
      const node = {
        id: attrValue(attrs, "id"),
        // Se guarda sin interpretar: es la evidencia textual, no la fuente de los datos.
        output: attrValue(attrs, "output"),
        children: [],
      };
      scripts.push(node);
      if (!selfClose) stack.push(node);     // <script … /> sin subárbol: banner, y los vacíos
      continue;
    }

    if (openName === "table") {
      const node = { type: "table", key: attrs.includes("key=") ? attrValue(attrs, "key") : null, children: [] };
      if (parent) parent.children.push(node);
      if (!selfClose) stack.push(node);
      continue;
    }

    // elem
    const node = { type: "elem", key: attrs.includes("key=") ? attrValue(attrs, "key") : null, value: "" };
    if (parent) parent.children.push(node);
    if (!selfClose) { pending = node; textAt = m.index + whole.length; }
  }

  return scripts;
}

/** El <script id="X"> de un bloque de puerto, o null si no salió. La ausencia la interpreta
 *  quien llama —con appliesTo()—, porque aquí no hay contexto para saber si le tocaba. */
function findScript(scripts, id) {
  return (scripts || []).find((s) => s.id === id) || null;
}

/** Los hijos <table> con ese `key`, en orden. */
function tablesByKey(node, key) {
  if (!node || !node.children) return [];
  return node.children.filter((c) => c.type === "table" && c.key === key);
}

/** El valor del <elem key="…"> hijo directo, o "" si no está. */
function elemValue(node, key) {
  if (!node || !node.children) return "";
  const e = node.children.find((c) => c.type === "elem" && c.key === key);
  return e ? e.value : "";
}

/** Los valores de los <elem> sin key: la forma que usa ssh2-enum-algos para sus listas. */
function elemList(node) {
  if (!node || !node.children) return [];
  return node.children.filter((c) => c.type === "elem" && c.key === null).map((c) => c.value);
}

module.exports = {
  decodeXmlEntities,
  parseScripts,
  findScript,
  tablesByKey,
  elemValue,
  elemList,
};
