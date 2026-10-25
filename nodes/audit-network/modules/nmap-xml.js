"use strict";

// Lector del subárbol <script> del XML de nmap, sin dependencias (el proyecto no tiene ninguna).
// Solo se interpreta <table>/<elem>; `output` es texto libre y se guarda tal cual como evidencia.

// Entidades con nombre y numéricas en una sola pasada, para no decodificar dos veces (`&amp;lt;`).
const ENTITY_RE = /&(?:#x([0-9a-fA-F]+)|#(\d+)|(lt|gt|quot|apos|amp));/g;
const NAMED = { lt: "<", gt: ">", quot: '"', apos: "'", amp: "&" };

function decodificarEntidades(s) {
  let texto;
  if (s == null) {
    texto = "";
  } else {
    texto = s;
  }
  return String(texto).replace(ENTITY_RE, (whole, hex, dec, name) => {
    if (name) return NAMED[name];
    let base;
    if (hex) {
      base = 16;
    } else {
      base = 10;
    }
    const code = parseInt(hex || dec, base);
    // Fuera de rango se deja tal cual: mejor evidencia fea que inventada.
    if (!Number.isFinite(code) || code < 0 || code > 0x10ffff) return whole;
    try { return String.fromCodePoint(code); } catch (e) { return whole; }
  });
}

// valorAtributo('id="vulners" output="x"', "id") → "vulners".
function valorAtributo(tag, attr) {
  const m = String(tag).match(new RegExp(`\\b${attr}="([^"]*)"`, "i"));
  if (m) {
    return decodificarEntidades(m[1]);
  } else {
    return "";
  }
}

// <script …>, </script>, <table …>, </table>, <elem …>texto</elem>, y sus formas autocerradas.
const TAG_RE = /<(script|table|elem)\b([^>]*?)(\/?)>|<\/(script|table|elem)>/g;

// Árbol de <script> de un bloque <port>. key null indica lista; con key, diccionario.
function leerScripts(portBlock) {
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
      pending.value = decodificarEntidades(xml.slice(textAt, m.index));
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
        id: valorAtributo(attrs, "id"),
        output: valorAtributo(attrs, "output"),
        children: [],
      };
      scripts.push(node);
      if (!selfClose) stack.push(node);     // <script … /> sin subárbol: banner, y los vacíos
      continue;
    }

    if (openName === "table") {
      let claveTabla;
      if (attrs.includes("key=")) {
        claveTabla = valorAtributo(attrs, "key");
      } else {
        claveTabla = null;
      }
      const node = { type: "table", key: claveTabla, children: [] };
      if (parent) parent.children.push(node);
      if (!selfClose) stack.push(node);
      continue;
    }

    // elem
    let clave;
    if (attrs.includes("key=")) {
      clave = valorAtributo(attrs, "key");
    } else {
      clave = null;
    }
    const node = { type: "elem", key: clave, value: "" };
    if (parent) parent.children.push(node);
    if (!selfClose) { pending = node; textAt = m.index + whole.length; }
  }

  return scripts;
}

// El <script id="X"> o null; qué significa que falte lo decide quien llama con aplicaA().
function buscarScript(scripts, id) {
  return (scripts || []).find((s) => s.id === id) || null;
}

// Hijos <table> con ese key, en orden.
function tablasPorClave(node, key) {
  if (!node || !node.children) return [];
  return node.children.filter((c) => c.type === "table" && c.key === key);
}

// Valor del <elem key="…"> hijo directo, o "" si no está.
function valorElemento(node, key) {
  if (!node || !node.children) return "";
  const e = node.children.find((c) => c.type === "elem" && c.key === key);
  if (e) {
    return e.value;
  } else {
    return "";
  }
}

// Valores de los <elem> sin key (las listas de ssh2-enum-algos).
function listaElementos(node) {
  if (!node || !node.children) return [];
  return node.children.filter((c) => c.type === "elem" && c.key === null).map((c) => c.value);
}

module.exports = {
  decodificarEntidades,
  leerScripts,
  buscarScript,
  tablasPorClave,
  valorElemento,
  listaElementos,
};
