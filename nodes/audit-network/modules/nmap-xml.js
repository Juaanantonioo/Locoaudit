"use strict";

/**
 * Lector del subárbol <script> del XML de nmap. 120 líneas y cero dependencias.
 *
 * POR QUÉ NO xml2js. Se midió el coste de las dos opciones en vez de decidir por inercia:
 * package.json declara `"dependencies": {}` —LoCoAudit no tiene hoy ni una dependencia de
 * ejecución— y el launcher no hace `npm install` del repo en ninguna de las tres plataformas.
 * Añadir un parser genérico significaría la primera dependencia del proyecto más un paso de
 * instalación nuevo en macOS, Linux y Windows, para leer cuatro formas de nodo. En una
 * herramienta de auditoría, cero superficie de suministro es un argumento defendible.
 *
 * QUÉ SE LEE, Y POR QUÉ NO EL `output`. Cada script emite dos cosas:
 *
 *   <script id="vulners" output="&#xa;  cpe:…: &#xa;    &#x9;CVE-2026-60002&#x9;9.4&#x9;https://…">
 *     <table key="cpe:/a:openbsd:openssh:10.3">
 *       <table><elem key="type">cve</elem><elem key="id">CVE-…</elem><elem key="cvss">9.4</elem></table>
 *
 * El atributo `output` es texto para leer con los ojos: su formato no está especificado en
 * ningún sitio y cambia entre versiones del script. El subárbol estructurado sí tiene forma.
 * Este módulo lee SOLO el subárbol; `output` se conserva sin interpretar, como evidencia.
 *
 * La gramática entera son cuatro nodos: <script>, <table> (con `key` o sin él), <elem> (con
 * `key` o sin él) y texto dentro de <elem>. No hay atributos que no sean `id`/`key`/`output`,
 * no hay CDATA y no hay texto suelto entre elementos.
 */

/**
 * Las cinco entidades predefinidas MÁS las numéricas. Las numéricas no son un extra teórico:
 * el `output` de vulners viene lleno de `&#xa;` (salto) y `&#x9;` (tabulador), y sin
 * decodificarlas la evidencia llega al informe con la basura literal a la vista.
 *
 * Una sola pasada, no cinco `.replace()` encadenados: encadenar decodifica dos veces lo ya
 * decodificado, y `&amp;lt;` —que es el texto literal "&lt;"— acabaría convertido en "<".
 *
 * nmap-wrapper.js tiene todavía su propia copia reducida para el `errormsg`; converge aquí
 * cuando se toque ese fichero.
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
 * Los <script> de UN bloque <port>…</port>, como árbol.
 *
 * Devuelve [{ id, output, children }], donde cada hijo es
 *   { type: "table", key, children }  |  { type: "elem", key, value }
 *
 * `key` es null cuando el nodo no lo trae: en NSE eso distingue un diccionario (hijos con key)
 * de una lista (hijos sin key), y perder esa diferencia es perder la forma del dato.
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
