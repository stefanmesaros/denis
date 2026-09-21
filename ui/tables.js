'use strict';
// Table columns: every table with four or more columns can hide columns, change their order (drag a heading, or the
// arrows in the Columns menu) and resize them (drag the right edge of a heading). The choice is kept per table in this
// browser only (localStorage), so it never reaches other users. Rows are redrawn all the time by the pages; a
// MutationObserver puts each new row into the chosen layout at once. Loaded last but one, started by main.js.

const TABLE_KEY = (id) => 'denis.table.' + id;
const MIN_COL = 40;
const MAX_COL = 900;

function loadLayout(id) {
  try {
    const j = JSON.parse(localStorage.getItem(TABLE_KEY(id)) || 'null');
    if (j && typeof j === 'object') return { order: Array.isArray(j.order) ? j.order.filter(Number.isInteger) : [], hidden: Array.isArray(j.hidden) ? j.hidden.filter(Number.isInteger) : [], widths: j.widths && typeof j.widths === 'object' ? j.widths : {} };
  } catch { /* no storage, or nonsense in it: start from the defaults */ }
  return { order: [], hidden: [], widths: {} };
}

function saveLayout(id, layout) {
  try {
    if (!layout.order.length && !layout.hidden.length && !Object.keys(layout.widths).length) localStorage.removeItem(TABLE_KEY(id));
    else localStorage.setItem(TABLE_KEY(id), JSON.stringify(layout));
  } catch { /* the layout just is not remembered */ }
}

/** The text of a heading (translated), without the resize handle. */
const headText = (th) => [...th.childNodes].filter((n) => n.nodeType === 3).map((n) => n.nodeValue).join('').trim();

function enhanceTable(table) {
  const id = table.id;
  const headRow = table.tHead && table.tHead.rows[0];
  if (!id || !headRow || table.dataset.cols) return;
  const cols = [...headRow.cells].map((th, ci) => { th.dataset.ci = String(ci); return { ci, th, locked: !headText(th) }; });
  if (cols.filter((c) => !c.locked).length < 4) return;
  table.dataset.cols = '1';
  let layout = loadLayout(id);
  const byCi = new Map(cols.map((c) => [c.ci, c]));
  // an order saved for another shape of the table is not trusted
  const sane = () => {
    const known = layout.order.filter((ci) => byCi.has(ci));
    for (const c of cols) if (!known.includes(c.ci)) known.push(c.ci);
    layout.order = [...new Set(known)];
    layout.hidden = layout.hidden.filter((ci) => byCi.has(ci) && !byCi.get(ci).locked);
  };
  const isDefault = () => layout.order.every((ci, i) => ci === i) && !layout.hidden.length && !Object.keys(layout.widths).length;

  /** Put the headings and every row into the layout. */
  const apply = () => {
    sane();
    // the columns the page itself shows right now (it hides some, like Site, by the hidden attribute)
    const shown = cols.filter((c) => !c.th.hidden);
    const rank = new Map(layout.order.map((ci, i) => [ci, i]));
    const sorted = shown.slice().sort((a, b) => rank.get(a.ci) - rank.get(b.ci));
    const current = [...headRow.cells].filter((c) => !c.hidden);
    if (current.length !== sorted.length || current.some((c, i) => c !== sorted[i].th)) {
      // headings that the page hides stay where they are; the rest are put in order
      const hiddenByPage = [...headRow.cells].filter((c) => c.hidden);
      headRow.replaceChildren(...sorted.map((s) => s.th), ...hiddenByPage);
    }
    for (const c of cols) {
      const off = layout.hidden.includes(c.ci);
      c.th.classList.toggle('col-off', off);
      const w = layout.widths[c.ci];
      c.th.style.width = w && !off ? w + 'px' : '';
    }
    const sized = Object.keys(layout.widths).length > 0;
    table.classList.toggle('sized', sized);
    if (sized) {
      const total = sorted.filter((s) => !layout.hidden.includes(s.ci)).reduce((sum, s) => sum + (layout.widths[s.ci] || s.th.getBoundingClientRect().width || 120), 0);
      table.style.width = Math.round(total) + 'px';
    } else {
      table.style.width = '';
    }
    for (const row of table.tBodies[0] ? [...table.tBodies[0].rows] : []) {
      if (row.cells.length !== shown.length) continue; // an empty-state row, or one the page built differently
      const cells = [...row.cells];
      // the cells come in the original order of the columns the page shows
      const map = new Map(shown.map((c, i) => [c.ci, cells[i]]));
      const want = sorted.map((s) => map.get(s.ci));
      if (want.some((cell, i) => cells[i] !== cell)) row.replaceChildren(...want);
      for (const [ci, cell] of map) cell.classList.toggle('col-off', layout.hidden.includes(ci));
    }
  };

  const change = (fn) => { fn(); sane(); saveLayout(id, isDefault() ? { order: [], hidden: [], widths: {} } : layout); apply(); };

  // rows are redrawn by the pages all the time: lay out each new row at once
  let busy = false;
  new MutationObserver(() => { if (busy) return; busy = true; try { apply(); } finally { busy = false; } }).observe(table.tBodies[0], { childList: true });
  // a heading the page shows or hides (Site) changes the shape of the rows
  new MutationObserver(() => { if (!busy) apply(); }).observe(headRow, { attributes: true, attributeFilter: ['hidden'], subtree: true });

  // ---- resizing: the right edge of a heading
  for (const c of cols) {
    const handle = el('span', { class: 'col-resize', title: tr('Drag to resize the column'), 'aria-hidden': 'true' });
    handle.onclick = (ev) => ev.stopPropagation();
    // the heading is draggable (to reorder): a press on the edge must resize, not start that drag
    handle.onmousedown = (ev) => { ev.preventDefault(); ev.stopPropagation(); };
    handle.ondblclick = (ev) => { ev.stopPropagation(); change(() => { delete layout.widths[c.ci]; }); };
    handle.onpointerdown = (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
      // freeze every column at the width it has now, so only this one moves
      for (const s of cols.filter((x) => !x.th.hidden && !layout.hidden.includes(x.ci))) if (!layout.widths[s.ci]) layout.widths[s.ci] = Math.round(s.th.getBoundingClientRect().width);
      const start = ev.clientX;
      const startW = layout.widths[c.ci] || Math.round(c.th.getBoundingClientRect().width);
      // listen on the document, so the drag goes on when the pointer leaves the thin handle
      const move = (e) => { layout.widths[c.ci] = Math.max(MIN_COL, Math.min(MAX_COL, Math.round(startW + e.clientX - start))); apply(); };
      const stop = () => {
        document.removeEventListener('pointermove', move);
        document.removeEventListener('pointerup', stop);
        document.removeEventListener('pointercancel', stop);
        change(() => {});
      };
      document.addEventListener('pointermove', move);
      document.addEventListener('pointerup', stop);
      document.addEventListener('pointercancel', stop);
    };
    c.th.appendChild(handle);
  }

  // ---- reordering: drag a heading onto another
  for (const c of cols.filter((x) => !x.locked)) {
    c.th.draggable = true;
    c.th.ondragstart = (ev) => { ev.dataTransfer.setData('text/plain', id + ':' + c.ci); ev.dataTransfer.effectAllowed = 'move'; };
    c.th.ondragover = (ev) => { if ((ev.dataTransfer.types || []).includes('text/plain')) { ev.preventDefault(); c.th.classList.add('drop-here'); } };
    c.th.ondragleave = () => c.th.classList.remove('drop-here');
    c.th.ondrop = (ev) => {
      ev.preventDefault();
      c.th.classList.remove('drop-here');
      const [tid, from] = (ev.dataTransfer.getData('text/plain') || '').split(':');
      if (tid !== id || Number(from) === c.ci) return;
      change(() => {
        const order = layout.order.filter((ci) => ci !== Number(from));
        order.splice(order.indexOf(c.ci), 0, Number(from)); // the dragged column takes the place of the one it is dropped on
        layout.order = order;
      });
    };
  }

  // ---- the Columns menu
  const wrap = table.closest('.table-wrap') || table;
  const menu = el('div', { class: 'cols-menu', hidden: true, role: 'dialog', 'aria-label': tr('Columns') });
  const button = el('button', { type: 'button', class: 'cols-btn', title: tr('Show or hide columns and change their order'), text: tr('Columns'), 'aria-haspopup': 'dialog' });
  const drawMenu = () => {
    sane();
    const movable = layout.order.filter((ci) => !byCi.get(ci).locked && !byCi.get(ci).th.hidden);
    menu.replaceChildren(
      el('p', { class: 'muted small', text: tr('Tick the columns to show, move them with the arrows or by dragging a heading, and drag the edge of a heading to resize it. Kept in this browser.') }),
      ...movable.map((ci, i) => {
        const c = byCi.get(ci);
        const box = el('input', { type: 'checkbox', checked: !layout.hidden.includes(ci), 'aria-label': headText(c.th) });
        box.onchange = () => { change(() => { layout.hidden = box.checked ? layout.hidden.filter((x) => x !== ci) : [...layout.hidden, ci]; }); };
        // an arrow moves the column past the nearest column that is shown (a hidden one would change nothing you can see)
        const neighbour = (dir) => { for (let j = i + dir; j >= 0 && j < movable.length; j += dir) if (!layout.hidden.includes(movable[j])) return j; return -1; };
        const swap = (dir) => () => { const j = neighbour(dir); if (j < 0) return; change(() => { const a = layout.order.indexOf(ci); const b = layout.order.indexOf(movable[j]); [layout.order[a], layout.order[b]] = [layout.order[b], layout.order[a]]; }); drawMenu(); };
        return el('div', { class: 'cols-row', 'data-ci': String(ci) },
          el('label', { class: 'check' }, box, ' ' + headText(c.th)),
          el('button', { type: 'button', class: 'cols-up', text: '↑', title: tr('Move left'), disabled: neighbour(-1) < 0, onclick: swap(-1) }),
          el('button', { type: 'button', class: 'cols-down', text: '↓', title: tr('Move right'), disabled: neighbour(1) < 0, onclick: swap(1) }));
      }),
      el('div', { class: 'row' }, el('button', { type: 'button', class: 'cols-reset', text: tr('Reset columns'), onclick: () => { change(() => { layout = { order: [], hidden: [], widths: {} }; }); drawMenu(); } })));
  };
  button.onclick = (ev) => {
    ev.stopPropagation();
    menu.hidden = !menu.hidden;
    if (!menu.hidden) drawMenu();
  };
  // (the path is taken when the click happens: a button that redrew the menu is no longer inside it afterwards)
  document.addEventListener('click', (ev) => { if (!menu.hidden && !ev.composedPath().includes(menu)) menu.hidden = true; });
  document.addEventListener('keydown', (ev) => { if (ev.key === 'Escape') menu.hidden = true; });
  const tools = el('div', { class: 'table-tools' }, button, menu);
  wrap.parentNode.insertBefore(tools, wrap);
  apply();
}

function initTables() {
  for (const t of document.querySelectorAll('table[id]')) enhanceTable(t);
}
