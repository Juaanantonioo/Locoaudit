/**
 * contrast-audit.js — Auditoría de contraste sobre un dashboard RENDERIZADO.
 *
 * NO es un script de Node: es una EXPRESIÓN que se evalúa dentro de la página, y se
 * lanza con scripts/cdp.js. Ver la cabecera de ese fichero para el arranque completo.
 *
 *   node scripts/cdp.js http://127.0.0.1:1881/dashboard/Host scripts/contrast-audit.js
 *
 * Por qué renderizado y no estático: el contraste depende del fondo EFECTIVO, que
 * puede venir de un ancestro varios niveles más arriba, de un rgba() a medio
 * componer, o de una clase que resultó tener más alcance del previsto. Leyendo el CSS
 * no se ve. Caso real: al quitar el prefijo `ia-` de image, la regla `.critical` pasó
 * a alcanzar `.header-card.critical` y pintó la cabecera entera de rojo pálido; se
 * detectó porque este auditor devolvió rgb(254,242,242) como fondo de las etiquetas.
 *
 * Criterio: WCAG AA — 4,5:1 para texto normal, 3:1 para texto grande (≥24px, o
 * ≥18,66px en negrita). Solo se miran elementos con texto propio, visibles y dentro
 * de .lca-report-root. Los resultados se deduplican por clase+color: la misma regla
 * repetida en veinte filas es UN fallo, no veinte.
 */
(function () {
  const parse = (c) => {
    const m = c.match(/rgba?\(([\d.]+),\s*([\d.]+),\s*([\d.]+)(?:,\s*([\d.]+))?\)/);
    return m ? { r: +m[1], g: +m[2], b: +m[3], a: m[4] === undefined ? 1 : +m[4] } : null;
  };
  const lin = (v) => { v /= 255; return v <= 0.04045 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); };
  const lum = (c) => 0.2126 * lin(c.r) + 0.7152 * lin(c.g) + 0.0722 * lin(c.b);
  const ratio = (a, b) => {
    const l1 = lum(a), l2 = lum(b);
    return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
  };
  const mezcla = (fg, bg) => ({
    r: fg.r * fg.a + bg.r * (1 - fg.a),
    g: fg.g * fg.a + bg.g * (1 - fg.a),
    b: fg.b * fg.a + bg.b * (1 - fg.a),
    a: 1,
  });

  // Sube por los ancestros acumulando capas semitransparentes hasta el primer fondo
  // opaco. Sin esto, un texto sobre rgba(...) se mide contra "transparent" y sale bien
  // siempre.
  const fondoEfectivo = (el) => {
    let acc = { r: 255, g: 255, b: 255, a: 1 };
    const capas = [];
    for (let n = el; n; n = n.parentElement) {
      const c = parse(getComputedStyle(n).backgroundColor);
      if (c && c.a > 0) capas.push(c);
      if (c && c.a === 1) break;
    }
    for (let i = capas.length - 1; i >= 0; i--) acc = mezcla(capas[i], acc);
    return acc;
  };

  const raiz = document.querySelector('.lca-report-root') || document.body;
  const malos = [];
  raiz.querySelectorAll('*').forEach((el) => {
    // Texto PROPIO: si solo contiene otros elementos, su `color` no pinta nada.
    const propio = [...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim().length > 1);
    if (!propio) return;
    const cs = getComputedStyle(el);
    if (cs.visibility === 'hidden' || cs.display === 'none' || +cs.opacity === 0) return;
    const fg = parse(cs.color);
    if (!fg) return;
    const bg = fondoEfectivo(el);
    const r = ratio(mezcla(fg, bg), bg);
    const px = parseFloat(cs.fontSize);
    const grande = px >= 24 || (px >= 18.66 && +cs.fontWeight >= 700);
    const min = grande ? 3 : 4.5;
    if (r < min) {
      const cls = (el.className && el.className.baseVal !== undefined ? el.className.baseVal : el.className) || el.tagName;
      malos.push({
        clase: cls,
        texto: el.textContent.trim().slice(0, 42),
        color: cs.color,
        fondo: `rgb(${Math.round(bg.r)}, ${Math.round(bg.g)}, ${Math.round(bg.b)})`,
        px, ratio: +r.toFixed(2), minimo: min,
      });
    }
  });

  const vistos = new Map();
  malos.forEach((m) => {
    const k = m.clase + '|' + m.color + '|' + m.fondo;
    if (!vistos.has(k)) vistos.set(k, Object.assign({}, m, { veces: 0 }));
    vistos.get(k).veces++;
  });

  return JSON.stringify({
    url: location.pathname,
    total: malos.length,
    distintos: vistos.size,
    casos: [...vistos.values()].sort((a, b) => a.ratio - b.ratio),
  }, null, 1);
})()
