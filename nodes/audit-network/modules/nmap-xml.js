"use strict";

// Lector del subárbol <script> del XML de nmap, sin dependencias (el proyecto no tiene ninguna).
// Solo se interpreta <table>/<elem>; `output` es texto libre y se guarda tal cual como evidencia.

// Entidades con nombre y numéricas en una sola pasada, para no decodificar dos veces (`&amp;lt;`).
const ENTITY_RE = /&(?:#x([0-9a-fA-F]+)|#(\d+)|(lt|gt|quot|apos|amp));/g;
const NAMED = { lt: "<", gt: ">", quot: '"', apos: "'", amp: "&" };

function decodeXmlEntities(s) {
  return String(s == null ? "" : s).replace(ENTITY_RE, (whole, hex, dec, name) => {
    if (name) return NAMED[name];
    const code = parseInt(hex || dec, hex ? 16 : 10);
    // Fuera de rango se deja tal cual: mejor evidencia fea que inventada.
    if (!Number.isFinite(code) || code < 0 || code > 0x10ffff) return whole;
    try { return String.fromCodePoint(code); } catch (e) { return whole; }
  });
}

// attrValue('id="vulners" output="x"', "id") → "vulners".
function attrValue(tag, attr) {
  const m = String(tag).match(new RegExp(`\\b${attr}="([^"]*)"`, "i"));
  return m ? decodeXmlEntities(m[1]) : "";
}

// <script …>, </script>, <table …>, </table>, <elem …>texto</elem>, y sus formas autocerradas.
const TAG_RE = /<(script|table|elem)\b([^>]*?)(\/?)>|<\/(script|table|elem)>/g;

// Árbol de <script> de un bloque <port>. key null indica lista; con key, diccionario.
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
      // Lo que hay entre el '>' del <elem> y este tag es su valor.
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

// El <script id="X"> o null; qué significa que falte lo decide quien llama con appliesTo().
function findScript(scripts, id) {
  return (scripts || []).find((s) => s.id === id) || null;
}

// Hijos <table> con ese key, en orden.
function tablesByKey(node, key) {
  if (!node || !node.children) return [];
  return node.children.filter((c) => c.type === "table" && c.key === key);
}

// Valor del <elem key="…"> hijo directo, o "" si no está.
function elemValue(node, key) {
  if (!node || !node.children) return "";
  const e = node.children.find((c) => c.type === "elem" && c.key === key);
  return e ? e.value : "";
}

// Valores de los <elem> sin key (las listas de ssh2-enum-algos).
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
