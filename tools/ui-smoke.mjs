#!/usr/bin/env node
// A smoke test of the real console in a real browser, run before every release (CI does it too).
//
//   node tools/ui-smoke.mjs                       # uses target/debug/denis (or DENIS_BIN) and Chrome
//   CHROME=/path/to/chrome DENIS_BIN=target/release/denis node tools/ui-smoke.mjs
//
// It loads the built-in demo data into a scratch database, serves it, drives headless Chrome through the
// DevTools protocol (no packages needed: Node 22+ has WebSocket and fetch) and checks what a person would
// notice: every page opens without a script error or failed request, no page shows "null", "undefined" or
// "[object Object]", the lists have their rows, the asset editor's dropdowns have their options (also when the
// first request for them was refused), the icon chooser works and sets the device type, an OT watch can be
// added and removed, every language loads, and the phone layout does not overflow.
// Exit code 0 = all passed. Nothing outside a temporary folder is touched.

import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import net from 'node:net';

import { fileURLToPath } from 'node:url';
const root = fileURLToPath(new URL('..', import.meta.url));
const bin = process.env.DENIS_BIN || join(root, 'target/debug/denis');
const chromePath = process.env.CHROME || [
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/usr/bin/google-chrome', '/usr/bin/google-chrome-stable', '/usr/bin/chromium', '/usr/bin/chromium-browser',
].find((p) => existsSync(p));
if (!existsSync(bin)) { console.error(`no program at ${bin}: run  cargo build  first (or set DENIS_BIN)`); process.exit(2); }
if (!chromePath) { console.error('Chrome not found: set CHROME=/path/to/chrome'); process.exit(2); }
if (typeof WebSocket === 'undefined') { console.error('Node 22 or newer is needed (global WebSocket)'); process.exit(2); }

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const freePort = () => new Promise((res) => { const s = net.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)); }); });

const tmp = mkdtempSync(join(tmpdir(), 'denis-ui-'));
const procs = [];
let failures = 0;
const ok = (name) => console.log(`  ok    ${name}`);
const fail = (name, why) => { failures++; console.log(`  FAIL  ${name}\n        ${why}`); };
async function check(name, fn) { if (process.env.SMOKE_ONLY && !new RegExp(process.env.SMOKE_ONLY).test(name)) return; try { const why = await fn(); if (why) fail(name, why); else ok(name); } catch (e) { fail(name, e.stack || String(e)); } }

function cleanup() {
  for (const p of procs) { try { p.kill('SIGTERM'); } catch { /* gone */ } }
  try { rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ }
}
process.on('exit', cleanup);
process.on('SIGINT', () => process.exit(130));

// ------------------------------------------------------------------ the server, with demo data
const db = join(tmp, 'ui.db');
execFileSync(bin, ['demo', '--db', db, 'load'], { stdio: 'pipe' });
const appPort = await freePort();
const server = spawn(bin, ['serve', '--db', db, '--insecure-no-auth', '--listen', `127.0.0.1:${appPort}`], { stdio: 'ignore' });
procs.push(server);
const base = `http://127.0.0.1:${appPort}`;
for (let i = 0; i < 50; i++) { try { if ((await fetch(base + '/api/status')).ok) break; } catch { /* not yet */ } await sleep(200); }

// ------------------------------------------------------------------ headless Chrome over CDP
const dbgPort = await freePort();
const chrome = spawn(chromePath, [
  '--headless=new', '--disable-gpu', '--no-sandbox', `--remote-debugging-port=${dbgPort}`, `--user-data-dir=${join(tmp, 'chrome')}`,
  '--window-size=1280,900', '--hide-scrollbars', 'about:blank',
], { stdio: 'ignore' });
procs.push(chrome);
let target;
for (let i = 0; i < 50 && !target; i++) {
  try { target = (await (await fetch(`http://127.0.0.1:${dbgPort}/json/list`)).json()).find((t) => t.type === 'page'); } catch { /* not yet */ }
  if (!target) await sleep(200);
}
if (!target) { console.error('could not start Chrome'); process.exit(2); }
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
let nextId = 1;
const waiting = new Map();
const problems = [];      // script errors and failed requests since the last reset
let interceptOptions = 0; // refuse this many requests for the option lists (simulates a forced password change)
ws.onmessage = async (m) => {
  const msg = JSON.parse(m.data);
  if (msg.id && waiting.has(msg.id)) { const { res, rej } = waiting.get(msg.id); waiting.delete(msg.id); msg.error ? rej(new Error(msg.error.message)) : res(msg.result); return; }
  if (msg.method === 'Runtime.exceptionThrown') problems.push('script error: ' + (msg.params.exceptionDetails.exception?.description || msg.params.exceptionDetails.text));
  else if (msg.method === 'Runtime.consoleAPICalled' && msg.params.type === 'error') problems.push('console.error: ' + msg.params.args.map((a) => a.value ?? a.description).join(' '));
  else if (msg.method === 'Network.responseReceived' && msg.params.response.status >= 400 && !msg.params.response.url.includes('/favicon')) problems.push(`HTTP ${msg.params.response.status} ${msg.params.response.url}`);
  else if (msg.method === 'Fetch.requestPaused') {
    const id = msg.params.requestId;
    if (interceptOptions > 0 && msg.params.request.url.includes('/api/meta/options')) {
      interceptOptions--;
      send('Fetch.fulfillRequest', { requestId: id, responseCode: 403, responseHeaders: [{ name: 'Content-Type', value: 'application/json' }], body: btoa('{"code":"must_change","error":"password change required"}') }).catch(() => {});
    } else send('Fetch.continueRequest', { requestId: id }).catch(() => {});
  }
};
const send = (method, params = {}) => new Promise((res, rej) => { const id = nextId++; waiting.set(id, { res, rej }); ws.send(JSON.stringify({ id, method, params })); });
const evaluate = async (expression) => {
  const r = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) throw new Error('in page: ' + (r.exceptionDetails.exception?.description || r.exceptionDetails.text));
  return r.result.value;
};
const load = async (url) => { await navigate('about:blank'); await navigate(url); };
const navigate = async (url) => { const loaded = new Promise((res) => { const h = (m) => { if (JSON.parse(m.data).method === 'Page.loadEventFired') { ws.removeEventListener('message', h); res(); } }; ws.addEventListener('message', h); }); await send('Page.navigate', { url }); await loaded; };
const ready = async () => { for (let i = 0; i < 60; i++) { if (await evaluate("typeof state !== 'undefined' && !!(state.me && state.assets && state.assets.length && state.options)")) return true; await sleep(250); } return false; };
const takeProblems = () => problems.splice(0);

await send('Page.enable'); await send('Runtime.enable'); await send('Network.enable');
await send('Fetch.enable', { patterns: [{ urlPattern: '*/api/meta/options*' }] });

const TABS = ['assets', 'alerts', 'findings', 'topology', 'ot', 'trends', 'events', 'compliance', 'reports', 'health', 'rules', 'alerting', 'agents', 'users', 'settings', 'audit', 'account'];
// text a person must never see on a page
const BAD_TEXT = "(() => { const t = document.getElementById('app').innerText; return ['null', 'undefined', '[object Object]', 'NaN'].filter((w) => new RegExp('(^|[^A-Za-z0-9_])' + w.replace(/[\\[\\]]/g, '\\\\$&') + '([^A-Za-z0-9_]|$)').test(t)); })()";

console.log(`console smoke test (${bin})`);
await load(base + '/#assets');
await check('the console starts, signed in, with the lists it needs', async () => (await ready()) ? null : 'state.me / assets / options never became available: ' + takeProblems().join('; '));

await ready(); // (also when only some checks are selected with SMOKE_ONLY)

// ------------------------------------------------------------------ every page
for (const tab of TABS) {
  await check(`page "${tab}" opens without errors, and shows no null/undefined`, async () => {
    takeProblems();
    await evaluate(`location.hash = '#${tab}'; setTab('${tab}'); 0`);
    await sleep(900);
    const visible = await evaluate(`!document.getElementById('view-${tab}').hidden`);
    if (!visible) return 'the page is not shown';
    const bad = await evaluate(BAD_TEXT);
    const p = takeProblems();
    if (bad.length) return `the page shows: ${bad.join(', ')}`;
    if (p.length) return p.join('\n        ');
    return null;
  });
}

// ------------------------------------------------------------------ what each list must contain
const counts = { assets: ['#assets-table tbody tr', 30], alerts: ['#alerts-table tbody tr', 5], ot: ['#ot-matrix tbody tr', 5], rules: ['#rules-list .rule-card', 15], compliance: ['#compliance-table tbody tr', 8], audit: ['#audit-table tbody tr', 0], users: ['#users-table tbody tr', 0] };
for (const [tab, [sel, min]] of Object.entries(counts)) {
  await check(`"${tab}" lists at least ${min} rows`, async () => {
    await evaluate(`setTab('${tab}'); 0`);
    await sleep(900);
    const n = await evaluate(`document.querySelectorAll(${JSON.stringify(sel)}).length`);
    return n >= min ? null : `only ${n} (${sel})`;
  });
}

// ------------------------------------------------------------------ the asset editor
const printerId = await evaluate("state.assets.find((a) => a.meta && a.meta.display_name === 'Reception printer').id");
await check('the asset editor has its dropdown options, even when the first request for them was refused', async () => {
  takeProblems();
  await evaluate("state.options = null; setTab('assets'); openAssetForm(assetById(" + printerId + ")); 0");
  await sleep(800);
  const r = await evaluate(`(() => { const d = document.getElementById('dialog-form'); const sel = (label) => [...d.querySelectorAll('label')].find((l) => l.firstChild && l.firstChild.textContent.trim() === label)?.querySelector('select'); return { status: sel('Status')?.options.length, crit: sel('Criticality')?.options.length, purdue: sel('Purdue level (OT)')?.options.length, types: sel('Device type')?.options.length, first: sel('Device type')?.options[0]?.textContent }; })()`);
  if (!(r.status >= 6 && r.crit >= 5 && r.purdue >= 8)) return `Status/Criticality/Purdue options: ${JSON.stringify(r)}`;
  if (!(r.types > 100)) return `the device type list has ${r.types} entries`;
  if (!/^Automatic \(detected: printer\)/.test(r.first)) return `the first device type option is "${r.first}"`;
  return null;
});
await check('the asset editor fetches its options itself when they were never loaded (forced password change)', async () => {
  // refuse the next request for the lists, reload: exactly what a forced password change does
  interceptOptions = 1;
  await load(base + '/#assets');
  await sleep(2500);
  const missing = await evaluate('!state.options');
  await evaluate("openAssetForm(assetById(" + printerId + ")); 0");
  await sleep(800);
  const n = await evaluate("[...document.querySelectorAll('#dialog-form select')].map((s) => s.options.length)");
  await evaluate("document.getElementById('form-dialog').close(); 0");
  return (n.length >= 4 && n.every((x) => x > 1)) ? null : `dropdown sizes ${JSON.stringify(n)} (options were ${missing ? 'missing' : 'present'} on the page)`;
});
await ready();
await check('the asset editor fields never overlap, also with the longest device type and on a narrow window', async () => {
  const longId = await evaluate("(state.assets.find((a) => a.meta && a.meta.display_name === 'Engineering workstation') || state.assets[0]).id");
  for (const width of [1280, 900, 700]) {
    await send('Emulation.setDeviceMetricsOverride', { width, height: 900, deviceScaleFactor: 1, mobile: false });
    await evaluate("(() => { const d = document.getElementById('form-dialog'); if (d.open) d.close(); })()");
    await evaluate("openAssetForm(assetById(" + longId + ")); 0");
    await sleep(500);
    // the longest text the type list can show, in the field itself
    await evaluate("(() => { const t = document.getElementById('asset-type'); t.options[0].textContent = 'Automatic (detected: engineering workstation and other long words)'; })()");
    const bad = await evaluate(`(() => {
      const d = document.getElementById('form-dialog');
      const boxes = [...d.querySelectorAll('.form-grid input, .form-grid select, .form-grid textarea')].filter((e) => e.type !== 'checkbox' && e.offsetParent).map((e) => ({ n: (e.closest('label')?.firstChild?.textContent || e.id || e.tagName).trim(), r: e.getBoundingClientRect() }));
      const grid = d.querySelector('.form-grid').getBoundingClientRect();
      const out = [];
      for (const b of boxes) if (b.r.right > grid.right + 1 || b.r.left < grid.left - 1) out.push(b.n + ' sticks out of the form');
      for (let i = 0; i < boxes.length; i++) for (let j = i + 1; j < boxes.length; j++) {
        const a = boxes[i].r, c = boxes[j].r;
        if (a.left < c.right - 1 && c.left < a.right - 1 && a.top < c.bottom - 1 && c.top < a.bottom - 1) out.push(boxes[i].n + ' overlaps ' + boxes[j].n);
      }
      return out;
    })()`);
    await evaluate("document.getElementById('form-dialog').close(); 0");
    if (bad.length) { await send('Emulation.clearDeviceMetricsOverride'); return `at ${width}px: ${bad.join('; ')}`; }
  }
  await send('Emulation.clearDeviceMetricsOverride');
  return null;
});
await check('the icon button sits next to the icon and opens a searchable chooser', async () => {
  await evaluate("setTab('assets'); openAssetForm(assetById(" + printerId + ")); 0");
  await sleep(600);
  const geom = await evaluate("(() => { const row = document.querySelector('#dialog-form .icon-row'); const cur = row.querySelector('.icon-current').getBoundingClientRect(); const b = row.querySelector('button').getBoundingClientRect(); const r = row.getBoundingClientRect(); return { gap: b.left - cur.right, fromRight: r.right - b.right, w: r.width }; })()");
  if (geom.gap > 40 || geom.gap < 0) return `the button is ${geom.gap}px from the icon`;
  if (geom.fromRight < geom.w / 3) return 'the button is at the far right of the row';
  await evaluate("document.querySelector('#dialog-form .icon-row button').click(); 0");
  await sleep(400);
  if (!(await evaluate("!!document.querySelector('dialog.icon-dialog[open]')"))) return 'the chooser did not open';
  const all = await evaluate("document.querySelectorAll('dialog.icon-dialog .icon-tile').length");
  await evaluate("(() => { const s = document.querySelector('dialog.icon-dialog .icon-search'); s.value = 'robot'; s.dispatchEvent(new Event('input')); })()");
  await sleep(200);
  const found = await evaluate("[...document.querySelectorAll('dialog.icon-dialog .icon-tile')].map((t) => t.textContent.trim())");
  if (all < 100) return `only ${all} icons offered`;
  if (found.length < 3 || !found.some((t) => /mower/i.test(t)) || !found.some((t) => /vacuum/i.test(t))) return `searching "robot" found: ${found.join(', ')}`;
  return null;
});
await check('choosing an icon in the chooser sets the matching device type, and it can be saved', async () => {
  await evaluate("[...document.querySelectorAll('dialog.icon-dialog .icon-tile')].find((t) => /mower/i.test(t.textContent)).click(); 0");
  await sleep(300);
  if (await evaluate("!!document.querySelector('dialog.icon-dialog[open]')")) return 'the chooser stayed open after a choice';
  const ty = await evaluate("document.getElementById('asset-type').value");
  if (ty !== 'robot lawn mower') return `the device type is "${ty}"`;
  if (await evaluate("document.querySelector('#dialog-form .muted.small[hidden]') !== null && [...document.querySelectorAll('#dialog-form .muted.small')].every((n) => n.hidden)")) return 'no note says the type was set from the icon';
  await evaluate("document.querySelector('#dialog-form button[type=submit]').click(); 0");
  await sleep(1200);
  const a = await (await fetch(base + '/api/assets/' + printerId)).json();
  if (!(a.meta.icon === 'robot_mower' && a.device_type === 'robot lawn mower')) return `saved icon "${a.meta.icon}", type "${a.device_type}"`;
  return null;
});
await check('choosing "automatic" and clearing the type returns the device to what discovery found', async () => {
  await evaluate("openAssetForm(assetById(" + printerId + ")); 0");
  await sleep(600);
  await evaluate("(() => { const t = document.getElementById('asset-type'); t.value = ''; t.dispatchEvent(new Event('change')); })()");
  await evaluate("document.querySelector('#dialog-form .icon-row button').click(); 0");
  await sleep(300);
  await evaluate("document.querySelector('dialog.icon-dialog .icon-tile').click(); 0"); // the first tile is "Automatic"
  await sleep(200);
  await evaluate("document.querySelector('#dialog-form button[type=submit]').click(); 0");
  await sleep(1200);
  const a = await (await fetch(base + '/api/assets/' + printerId)).json();
  return (!a.meta.icon && a.device_type === 'printer') ? null : `icon "${a.meta.icon}", type "${a.device_type}"`;
});
await check('a type chosen by hand is remembered and the icon follows it', async () => {
  await evaluate("openAssetForm(assetById(" + printerId + ")); 0");
  await sleep(600);
  await evaluate("(() => { const t = document.getElementById('asset-type'); t.value = 'washing machine'; t.dispatchEvent(new Event('change')); })()");
  const shown = await evaluate("document.querySelector('#dialog-form .icon-current svg') && document.querySelector('#dialog-form .icon-current').textContent");
  await evaluate("document.querySelector('#dialog-form button[type=submit]').click(); 0");
  await sleep(1200);
  const a = await (await fetch(base + '/api/assets/' + printerId)).json();
  // undo
  await evaluate("openAssetForm(assetById(" + printerId + ")); 0");
  await sleep(600);
  await evaluate("(() => { const t = document.getElementById('asset-type'); t.value = ''; t.dispatchEvent(new Event('change')); })()");
  await evaluate("document.querySelector('#dialog-form button[type=submit]').click(); 0");
  await sleep(1000);
  if (!/washing machine/.test(shown || '')) return `the icon row said "${shown}" after choosing washing machine`;
  return (a.device_type === 'washing machine') ? null : `saved type "${a.device_type}"`;
});

// ------------------------------------------------------------------ findings: accept a risk, verify a fix
await check('the Findings page offers "Verify fix" and "Accept risk…" on every finding and lists the accepted risks', async () => {
  takeProblems();
  await evaluate("location.hash = '#findings'; setTab('findings'); 0");
  await sleep(1200);
  const r = await evaluate(`(() => { const cards = [...document.querySelectorAll('#findings-list .finding')]; return { cards: cards.length, verify: cards.filter((c) => c.querySelector('.verify-fix')).length, accept: cards.filter((c) => c.querySelector('.accept-risk')).length, accepted: document.querySelectorAll('#accepted-table tbody tr').length, boxHidden: document.getElementById('accepted-box').hidden, until: document.querySelector('#accepted-table tbody tr td:nth-child(5)')?.textContent }; })()`);
  if (r.cards < 3 || r.verify !== r.cards || r.accept !== r.cards) return `findings ${r.cards}, with Verify ${r.verify} and Accept ${r.accept}`;
  if (r.boxHidden || r.accepted < 1) return 'the demo has an accepted risk but the list does not show it';
  if (!/in \d+ days/.test(r.until || '')) return `the accepted risk's end reads "${r.until}"`;
  const p = takeProblems();
  return p.length ? p.join('; ') : null;
});
await check('accepting a risk needs a reason, removes the device from the finding and lists it; withdrawing brings it back', async () => {
  const before = await (await fetch(base + '/api/findings')).json();
  const tel = before.find((f) => f.id === 'telnet_open');
  if (!tel) return 'the demo has no Telnet finding to work with';
  await evaluate("document.querySelector('#finding-telnet_open .accept-risk').click(); 0");
  await sleep(500);
  // no reason: refused, dialog stays
  await evaluate("document.querySelector('#dialog-form button[type=submit]').click(); 0");
  await sleep(400);
  const stillOpen = await evaluate("!!document.querySelector('#form-dialog[open]')");
  const unchanged = await (await fetch(base + '/api/findings')).json();
  if (!stillOpen || !unchanged.some((f) => f.id === 'telnet_open' && f.assets.length === tel.assets.length)) return 'a decision without a reason was not refused';
  await evaluate("document.querySelector('#dialog-form textarea').value = 'Smoke test: isolated VLAN'; document.querySelector('#dialog-form button[type=submit]').click(); 0");
  await sleep(1500);
  const after = await (await fetch(base + '/api/findings')).json();
  if (after.some((f) => f.id === 'telnet_open')) return 'the accepted device is still listed under the finding';
  const rows = await evaluate("[...document.querySelectorAll('#accepted-table tbody tr')].map((r) => r.innerText)");
  if (!rows.some((t) => t.includes('Smoke test: isolated VLAN') && /Telnet/.test(t))) return 'the accepted risk is not listed: ' + JSON.stringify(rows);
  // withdraw it again from the list
  await evaluate("window.confirm = () => true; [...document.querySelectorAll('#accepted-table tbody tr')].find((r) => r.innerText.includes('Smoke test')).querySelector('button[title^=Stop]').click(); 0");
  await sleep(1500);
  const back = await (await fetch(base + '/api/findings')).json();
  return back.some((f) => f.id === 'telnet_open') ? null : 'the finding did not come back after the decision was withdrawn';
});
await check('"Verify fix" answers plainly, also when this console cannot scan', async () => {
  takeProblems();
  await evaluate("document.querySelector('#finding-telnet_open .verify-fix').click(); 0");
  await sleep(1500);
  const text = await evaluate("document.getElementById('msg-dialog').open ? document.getElementById('msg-body').innerText : ''");
  await evaluate("document.getElementById('msg-dialog').close(); 0");
  if (!/Verify fix/.test(text) || !/Not scanned/.test(text) || !/cannot scan/.test(text)) return 'the answer said: ' + text.slice(0, 300);
  const bad = await evaluate(BAD_TEXT);
  const p = takeProblems();
  return bad.length ? `the page shows ${bad.join(', ')}` : p.length ? p.join('; ') : null;
});

// ------------------------------------------------------------------ reports: make, list, open, schedule, delete
await check('the Reports page makes a report, keeps it in the list, serves it and deletes it; the old "Printable report" link is gone', async () => {
  takeProblems();
  if (await evaluate("!!document.getElementById('report-link') || document.body.innerText.includes('Printable report')")) return 'the old "Printable report" link is still on the page';
  await evaluate("window.open = () => null; location.hash = '#reports'; setTab('reports'); 0");
  await sleep(700);
  const before = (await (await fetch(base + '/api/reports')).json()).reports.length;
  await evaluate("document.getElementById('make-report').click(); 0");
  await sleep(2500);
  const list = (await (await fetch(base + '/api/reports')).json()).reports;
  if (list.length !== before + 1) return `the report was not made (${before} -> ${list.length})`;
  const rows = await evaluate("[...document.querySelectorAll('#reports-table tbody tr')].map((r) => r.innerText)");
  if (rows.length !== list.length || !/By hand/.test(rows[0])) return 'the list on the page does not show it: ' + JSON.stringify(rows);
  const page = await (await fetch(base + '/api/reports/' + list[0].id)).text();
  for (const w of ['Compliance overview', 'NIS2', 'ISO/IEC 27001:2022', 'NIST SP 800-82']) if (!page.includes(w)) return `the saved report lacks "${w}"`;
  const links = await evaluate("[...document.querySelectorAll('#reports-table tbody tr:first-child a')].map((a) => a.getAttribute('href'))");
  if (!links.some((h) => h.endsWith('?download=1'))) return 'no download link: ' + JSON.stringify(links);
  // the schedule is saved
  await evaluate("(() => { const s = document.getElementById('rep-schedule'); s.value = 'weekly'; document.getElementById('rep-save').click(); })()");
  await sleep(800);
  if ((await (await fetch(base + '/api/reports/settings')).json()).schedule !== 'weekly') return 'the schedule was not saved';
  await evaluate("window.confirm = () => true; document.querySelector('#reports-table tbody tr:first-child button').click(); 0");
  await sleep(1000);
  if ((await (await fetch(base + '/api/reports')).json()).reports.length !== before) return 'the report was not deleted';
  const bad = await evaluate(BAD_TEXT);
  const p = takeProblems();
  return bad.length ? `the page shows ${bad.join(', ')}` : p.length ? p.join('; ') : null;
});

// ------------------------------------------------------------------ table columns: hide, reorder, resize, remember
await check('table columns can be hidden, reordered and resized, stay so when the rows are redrawn and after a reload, and can be reset', async () => {
  takeProblems();
  await evaluate("localStorage.removeItem('denis.table.assets-table'); location.hash = '#assets'; setTab('assets'); 0");
  await load(base + '/#assets');
  if (!(await ready())) return 'the console did not start';
  const heads = () => evaluate("[...document.querySelectorAll('#assets-table thead th')].filter((t) => getComputedStyle(t).display !== 'none').map((t) => t.textContent.trim())");
  const firstRow = () => evaluate("[...document.querySelector('#assets-table tbody tr').cells].filter((c) => getComputedStyle(c).display !== 'none').map((c) => c.textContent.trim())");
  const start = await heads();
  if (!start.includes('Vendor') || !start.includes('Name')) return 'unexpected headings: ' + JSON.stringify(start);
  const row0 = await firstRow();
  if (row0.length !== start.length) return `a row has ${row0.length} cells for ${start.length} headings`;
  // hide Vendor from the Columns menu
  await evaluate("document.querySelector('#view-assets .cols-btn').click(); 0");
  await sleep(200);
  await evaluate("[...document.querySelectorAll('#view-assets .cols-row')].find((r) => r.textContent.includes('Vendor')).querySelector('input').click(); 0");
  await sleep(300);
  let now_ = await heads();
  if (now_.includes('Vendor') || now_.length !== start.length - 1) return 'Vendor was not hidden: ' + JSON.stringify(now_);
  if ((await firstRow()).length !== now_.length) return 'the rows did not follow the hidden column';
  // move Name one place to the left
  const before = now_.indexOf('Name');
  await evaluate("[...document.querySelectorAll('#view-assets .cols-row')].find((r) => r.textContent.includes('Name')).querySelector('.cols-up').click(); 0");
  await sleep(300);
  now_ = await heads();
  if (now_.indexOf('Name') !== before - 1) return `Name did not move left: ${JSON.stringify(now_)}`;
  const nameCell = await evaluate("(() => { const i = [...document.querySelectorAll('#assets-table thead th')].filter((t) => getComputedStyle(t).display !== 'none').findIndex((t) => t.textContent.trim() === 'Name'); return [...document.querySelector('#assets-table tbody tr').cells].filter((c) => getComputedStyle(c).display !== 'none')[i].classList.contains('namecell'); })()");
  if (!nameCell) return 'the cells did not move with their heading';
  // (the menu stays open while columns are moved; close it, and resize: drag the edge of the Name heading 80 px to the right)
  if (!(await evaluate("!document.querySelector('#view-assets .cols-menu').hidden"))) return 'the Columns menu closed by itself when a column was moved';
  await evaluate("document.querySelector('#view-assets .cols-btn').click(); 0");
  const box = await evaluate("(() => { const th = [...document.querySelectorAll('#assets-table thead th')].find((t) => t.textContent.trim() === 'Name'); const r = th.querySelector('.col-resize').getBoundingClientRect(); return { x: r.x + r.width / 2, y: r.y + r.height / 2, w: th.getBoundingClientRect().width }; })()");
  await send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: box.x, y: box.y });
  await send('Input.dispatchMouseEvent', { type: 'mousePressed', x: box.x, y: box.y, button: 'left', clickCount: 1 });
  for (const dx of [20, 50, 80]) await send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: box.x + dx, y: box.y, buttons: 1 });
  await send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: box.x + 80, y: box.y, button: 'left', clickCount: 1 });
  await sleep(400);
  const w1 = await evaluate("[...document.querySelectorAll('#assets-table thead th')].find((t) => t.textContent.trim() === 'Name').getBoundingClientRect().width");
  if (Math.abs(w1 - (box.w + 80)) > 6) return `the column is ${Math.round(w1)} px wide, expected about ${Math.round(box.w + 80)} (stored: ${await evaluate("localStorage.getItem('denis.table.assets-table')")})`;
  // the pages redraw their rows every few seconds: the layout must survive that
  await evaluate("renderAssets(); 0");
  await sleep(300);
  const redrawn = await heads();
  if (JSON.stringify(redrawn) !== JSON.stringify(now_) || (await firstRow()).length !== redrawn.length) return 'the layout was lost when the rows were redrawn';
  // and a reload
  await load(base + '/#assets');
  if (!(await ready())) return 'the console did not start again';
  await sleep(500);
  const reloaded = await heads();
  const w2 = await evaluate("[...document.querySelectorAll('#assets-table thead th')].find((t) => t.textContent.trim() === 'Name').getBoundingClientRect().width");
  if (JSON.stringify(reloaded) !== JSON.stringify(now_) || Math.abs(w2 - w1) > 6) return `after a reload: ${JSON.stringify(reloaded)}, width ${Math.round(w2)} instead of ${Math.round(w1)}`;
  // reset
  await evaluate("document.querySelector('#view-assets .cols-btn').click(); 0");
  await sleep(200);
  await evaluate("document.querySelector('#view-assets .cols-reset').click(); 0");
  await sleep(300);
  const reset = await heads();
  const stored = await evaluate("localStorage.getItem('denis.table.assets-table')");
  if (JSON.stringify(reset) !== JSON.stringify(start) || stored) return `reset gave ${JSON.stringify(reset)}, stored ${stored}`;
  const bad = await evaluate(BAD_TEXT);
  const p = takeProblems();
  return bad.length ? `the page shows ${bad.join(', ')}` : p.length ? p.join('; ') : null;
});

// ------------------------------------------------------------------ health and backups
await check('the Health page shows the database and the backups; a backup can be made, listed, downloaded and deleted', async () => {
  takeProblems();
  await evaluate("location.hash = '#health'; setTab('health'); 0");
  await sleep(1200);
  const cards = await evaluate("[...document.querySelectorAll('#health-cards .measure')].map((c) => c.innerText)");
  if (!cards.some((t) => /Database/.test(t)) || !cards.some((t) => /Free disk/.test(t))) return 'the cards are missing: ' + JSON.stringify(cards);
  const before = (await (await fetch(base + '/api/backups')).json()).backups.length;
  await evaluate("document.getElementById('backup-now').click(); 0");
  await sleep(2500);
  const list = (await (await fetch(base + '/api/backups')).json()).backups;
  if (list.length !== before + 1) return `the backup was not made (${before} -> ${list.length})`;
  const rows = await evaluate("[...document.querySelectorAll('#backups-table tbody tr')].map((r) => r.innerText)");
  if (rows.length !== list.length || !/By hand/.test(rows[0])) return 'the list on the page does not show it: ' + JSON.stringify(rows);
  const file = await fetch(base + '/api/backups/' + list[0].name);
  const head = new TextDecoder().decode((await file.arrayBuffer()).slice(0, 15));
  if (head !== 'SQLite format 3') return 'the download is not a database: ' + JSON.stringify(head);
  await evaluate("window.confirm = () => true; document.querySelector('#backups-table tbody tr:first-child button').click(); 0");
  await sleep(1000);
  if ((await (await fetch(base + '/api/backups')).json()).backups.length !== before) return 'the backup was not deleted';
  const bad = await evaluate(BAD_TEXT);
  const p = takeProblems();
  return bad.length ? `the page shows ${bad.join(', ')}` : p.length ? p.join('; ') : null;
});

// ------------------------------------------------------------------ rules: an OT watch
await check('an OT command watch can be added from the Rules page and removed again', async () => {
  takeProblems();
  await evaluate("location.hash = '#rules'; setTab('rules'); 0");
  await sleep(1000);
  await evaluate("document.querySelector('#watches .row button.primary').click(); 0");
  await sleep(500);
  await evaluate("(() => { const d = document.getElementById('dialog-form'); d.querySelector('input[required]').value = 'Smoke test watch'; const p = d.querySelectorAll('select')[0]; p.value = '2'; p.dispatchEvent(new Event('change')); d.querySelector('button[type=submit]').click(); })()");
  await sleep(1500);
  const r = await (await fetch(base + '/api/rules')).json();
  if (!(r.ot_watches || []).some((w) => w.name === 'Smoke test watch' && w.proto === 's7')) return 'the watch was not saved: ' + JSON.stringify(r.ot_watches);
  await evaluate("window.confirm = () => true; [...document.querySelectorAll('#watches .watch-actions button')].find((b) => b.textContent === 'Delete').click(); 0");
  await sleep(1200);
  const r2 = await (await fetch(base + '/api/rules')).json();
  const p = takeProblems();
  if ((r2.ot_watches || []).length) return 'the watch was not deleted';
  return p.length ? p.join('; ') : null;
});
await check('a network watch can be added from the Rules page, is listed in words, and removed again', async () => {
  takeProblems();
  await evaluate("location.hash = '#rules'; setTab('rules'); 0");
  await sleep(1000);
  await evaluate("document.getElementById('add-it-watch').click(); 0");
  await sleep(500);
  // the first preset: devices talking to the internet
  await evaluate("(() => { const d = document.getElementById('dialog-form'); const p = d.querySelector('select'); p.value = '0'; p.dispatchEvent(new Event('change')); d.querySelector('input[required]').value = 'Smoke test net watch'; d.querySelector('button[type=submit]').click(); })()");
  await sleep(1500);
  const r = await (await fetch(base + '/api/rules')).json();
  const w = (r.it_watches || []).find((x) => x.name === 'Smoke test net watch');
  if (!w || w.remotes_mode !== 'only' || w.remotes[0] !== 'public') return 'the watch was not saved: ' + JSON.stringify(r.it_watches);
  const text = await evaluate("document.querySelector('#it-watches .watch')?.innerText || ''");
  if (!/the internet/.test(text)) return 'the list does not describe it in words: ' + text;
  // refused: a watch that lists ports but no port
  await evaluate("document.querySelector('#it-watches .watch-actions button').click(); 0");
  await sleep(500);
  await evaluate("(() => { const d = document.getElementById('dialog-form'); const s = d.querySelectorAll('select'); const m = [...s].find((x) => [...x.options].some((o) => o.value === 'except')); m.value = 'only'; d.querySelector('button[type=submit]').click(); })()");
  await sleep(1000);
  const open = await evaluate("!!document.querySelector('#form-dialog[open]')");
  const err = await evaluate("document.querySelector('#dialog-form .form-error')?.textContent || ''");
  if (!open || !err) return 'a watch with "only these ports" and no port was not refused';
  takeProblems(); // the 400 was the point
  await evaluate("document.querySelector('#form-dialog').close(); 0");
  await evaluate("window.confirm = () => true; [...document.querySelectorAll('#it-watches .watch-actions button')].find((b) => b.textContent === 'Delete').click(); 0");
  await sleep(1200);
  const r2 = await (await fetch(base + '/api/rules')).json();
  const p = takeProblems();
  if ((r2.it_watches || []).length) return 'the watch was not deleted';
  return p.length ? p.join('; ') : null;
});

// ------------------------------------------------------------------ languages and the phone layout
for (const lang of ['de', 'fr', 'es', 'sk']) {
  await check(`the console loads in ${lang}: pages open without errors`, async () => {
    takeProblems();
    await evaluate(`localStorage.setItem('denis-lang', '${lang}'); 0`);
    await load(base + '/#assets');
    if (!(await ready())) return 'the console did not start';
    if ((await evaluate('document.documentElement.lang')) !== lang) return 'the language did not change';
    for (const tab of ['assets', 'alerts', 'rules', 'ot', 'settings', 'account']) {
      await evaluate(`setTab('${tab}'); 0`);
      await sleep(500);
      const bad = await evaluate(BAD_TEXT);
      if (bad.length) return `page ${tab} shows: ${bad.join(', ')}`;
    }
    const p = takeProblems();
    return p.length ? p.join('\n        ') : null;
  });
}
await evaluate("localStorage.removeItem('denis-lang'); 0");

await send('Emulation.setDeviceMetricsOverride', { width: 390, height: 800, deviceScaleFactor: 2, mobile: true });
await load(base + '/#assets');
await ready();
for (const tab of ['assets', 'alerts', 'ot', 'rules', 'settings', 'account']) {
  await check(`on a phone the "${tab}" page does not overflow sideways`, async () => {
    await evaluate(`setTab('${tab}'); 0`);
    await sleep(600);
    const w = await evaluate('[document.documentElement.scrollWidth, window.innerWidth]');
    return w[0] <= w[1] + 2 ? null : `the page is ${w[0]}px wide on a ${w[1]}px screen`;
  });
}

console.log(failures ? `\n${failures} check(s) FAILED` : '\nall checks passed');
ws.close();
process.exit(failures ? 1 : 0);
