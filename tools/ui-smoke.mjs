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
import { createHmac, randomBytes } from 'node:crypto';
import dgram from 'node:dgram';

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
const ready2 = async () => { for (let i = 0; i < 60; i++) { if (await evaluate("typeof state !== 'undefined' && !!(state.me && state.options)")) return true; await sleep(250); } return false; };

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
const counts = { assets: ['#assets-table tbody tr', 30], alerts: ['#alerts-table tbody tr', 5], ot: ['#ot-matrix tbody tr', 5], rules: ['#rules-list .rule-card', 15], compliance: ['#compliance-groups tbody tr', 8], audit: ['#audit-table tbody tr', 0], users: ['#users-table tbody tr', 0] };
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

// ------------------------------------------------------------------ Devices: group by, and filter by several fields
await check('Devices can be grouped by room/type/owner, and filters combine (type AND OS) to narrow the list', async () => {
  takeProblems();
  await evaluate("location.hash = '#assets'; setTab('assets'); 0");
  await sleep(900);
  const total = await evaluate("state.assets.length");
  // group by device type: every row is either a group header (1 visible cell) or a data row
  await evaluate("document.getElementById('group-by').value = 'device_type'; document.getElementById('group-by').dispatchEvent(new Event('change')); 0");
  await sleep(400);
  const grouped = await evaluate("[...document.querySelectorAll('#assets-table tbody tr')].map((r) => ({ group: r.classList.contains('group-row'), cells: r.cells.length }))");
  if (!grouped.some((r) => r.group) || !grouped.some((r) => !r.group)) return 'grouping produced no group headers or no data rows: ' + JSON.stringify(grouped.slice(0, 4));
  await evaluate("document.getElementById('group-by').value = 'none'; document.getElementById('group-by').dispatchEvent(new Event('change')); 0");
  await sleep(300);
  // filters: type + a free-text OS substring, combined with AND
  await evaluate("document.getElementById('filters-btn').click(); 0");
  await sleep(300);
  const type = await evaluate("(() => { const s = document.querySelectorAll('#filters-menu select')[0]; const opt = [...s.options].find((o) => o.value === 'computer'); if (opt) s.value = 'computer'; else s.selectedIndex = 1; s.dispatchEvent(new Event('change')); return s.value; })()");
  await sleep(300);
  const afterType = await evaluate("state.assets.filter((a) => a === a).length, document.getElementById('count-assets').textContent");
  await evaluate("(() => { const i = document.querySelector('#filters-menu input'); i.value = 'zzz-does-not-exist'; i.dispatchEvent(new Event('input')); })()");
  await sleep(300);
  const noneLeft = await evaluate("document.querySelectorAll('#assets-table tbody tr').length");
  if (noneLeft !== 0) return `a nonsense OS filter combined with type=${type} still shows ${noneLeft} rows`;
  const badge = await evaluate("document.getElementById('filters-count').textContent");
  if (badge !== '2') return 'the filter count badge: ' + badge;
  // clear filters: back to the full list
  await evaluate("document.querySelector('#filters-menu .cols-reset').click(); 0");
  await sleep(300);
  const restored = await evaluate("document.querySelectorAll('#assets-table tbody tr').length");
  if (restored !== total) return `clearing filters gave ${restored} rows, expected ${total}`;
  if (!(await evaluate("document.getElementById('filters-count').hidden"))) return 'the filter badge did not clear';
  void afterType;
  const bad = await evaluate(BAD_TEXT);
  const p = takeProblems();
  return bad.length ? `the page shows ${bad.join(', ')}` : p.length ? p.join('; ') : null;
});

// ------------------------------------------------------------------ Devices: lazy rendering for a large list
await check('Devices past a few hundred rows are rendered lazily (windowed), filtering and grouping still see all of them', async () => {
  takeProblems();
  await evaluate("location.hash = '#assets'; setTab('assets'); 0");
  await sleep(500);
  // fabricate a large in-memory list (no server round-trip needed: this exercises the rendering path only)
  // and stop the periodic refresh so it is not overwritten mid-check.
  const injected = await evaluate(`(() => {
    for (let i = 1; i < 99999; i++) clearInterval(i);
    const fake = (i) => ({
      id: 100000 + i, ip: '10.0.' + (i % 255) + '.' + (i % 200), mac: '02:00:00:' + i.toString(16).padStart(6, '0').match(/../g).join(':'),
      vendor: 'Acme', randomized_mac: false, hostnames: [], display_name: 'lazydev-' + i, device_type: i % 3 === 0 ? 'computer' : 'printer',
      os_guess: i % 2 === 0 ? 'Linux' : 'Windows', open_ports: [], fingerprint: { mdns_names: [] },
      risk: { score: i % 100, level: 'low', factors: [] }, meta: { location: 'Room ' + (i % 5), owner: 'user' + (i % 4) },
      last_seen: Math.floor(Date.now() / 1000), first_seen: Math.floor(Date.now() / 1000), is_self: false, agent_id: null,
      ip_history: [], guess_reasons: [],
    });
    state.assets = Array.from({ length: 2000 }, (_, i) => fake(i));
    renderAssets();
    return { total: state.assets.length, domRows: document.querySelectorAll('#assets-table tbody tr').length, virtual: document.getElementById('assets-scroll').classList.contains('virtual'), count: document.getElementById('count-assets').textContent };
  })()`);
  if (!injected.virtual) return 'a 2000-device list did not switch #assets-scroll to windowed rendering';
  if (injected.count !== '(2000)') return 'the count label: ' + injected.count;
  if (injected.domRows >= 200) return `${injected.domRows} rows were put in the DOM for a 2000-device list: not windowed`;
  // scrolling moves the window
  const scrolled = await evaluate(`(async () => {
    const scroller = document.getElementById('assets-scroll');
    scroller.scrollTop = scroller.scrollHeight / 2;
    scroller.dispatchEvent(new Event('scroll'));
    await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
    return [...document.querySelectorAll('#assets-table tbody tr:not(.vspacer)')].slice(0, 1).map((r) => r.cells[6].textContent)[0];
  })()`);
  if (scrolled === 'lazydev-0') return 'scrolling did not move the rendered window';
  // filtering still searches the whole 2000, not just what happens to be on screen
  await evaluate("document.getElementById('search').value = 'lazydev-19'; document.getElementById('search').dispatchEvent(new Event('input')); 0");
  await sleep(200);
  const filtered = await evaluate("({ count: document.getElementById('count-assets').textContent, domRows: document.querySelectorAll('#assets-table tbody tr:not(.vspacer)').length })");
  if (filtered.count !== '(111/2000)') return 'filtering a 2000-row list: ' + filtered.count; // lazydev-19, -190..-199, -1900..-1999
  if (filtered.domRows !== 111) return `filtering found the 111 matches but only ${filtered.domRows} are in the DOM (should be under the windowing threshold)`;
  await evaluate("document.getElementById('search').value = ''; document.getElementById('search').dispatchEvent(new Event('input')); 0");
  await sleep(200);
  // grouping combines correctly with windowing (group headers and data rows both appear near the scroll position)
  await evaluate("document.getElementById('group-by').value = 'location'; document.getElementById('group-by').dispatchEvent(new Event('change')); 0");
  await sleep(200);
  const grouped = await evaluate("[...document.querySelectorAll('#assets-table tbody tr')].map((r) => r.className)");
  if (!grouped.includes('group-row')) return 'grouping a windowed list produced no group headers: ' + JSON.stringify(grouped.slice(0, 6));
  await evaluate("document.getElementById('group-by').value = 'none'; document.getElementById('group-by').dispatchEvent(new Event('change')); location.reload(); 0");
  await sleep(1200); // the reload restores the real (small) demo dataset and the periodic refresh
  const bad = await evaluate(BAD_TEXT);
  const p = takeProblems();
  return bad.length ? `the page shows ${bad.join(', ')}` : p.length ? p.join('; ') : null;
});

// ------------------------------------------------------------------ export buttons: Devices CSV / Alerts CSV
await check('Devices CSV is a button next to Import CSV, and Alerts CSV is a button only on the Alerts page', async () => {
  takeProblems();
  await evaluate("location.hash = '#assets'; setTab('assets'); 0");
  await sleep(500);
  const onAssets = await evaluate("({ devicesIsButton: document.getElementById('export-assets').classList.contains('button'), devicesVisible: !document.getElementById('exports-assets').hidden, alertsHidden: document.getElementById('exports-alerts').hidden })");
  if (!onAssets.devicesIsButton || !onAssets.devicesVisible || !onAssets.alertsHidden) return 'on Devices: ' + JSON.stringify(onAssets);
  await evaluate("location.hash = '#alerts'; setTab('alerts'); 0");
  await sleep(500);
  const onAlerts = await evaluate("({ alertsIsButton: document.getElementById('export-alerts').classList.contains('button'), alertsVisible: !document.getElementById('exports-alerts').hidden, devicesHidden: document.getElementById('exports-assets').hidden })");
  if (!onAlerts.alertsIsButton || !onAlerts.alertsVisible || !onAlerts.devicesHidden) return 'on Alerts: ' + JSON.stringify(onAlerts);
  const p = takeProblems();
  return p.length ? p.join('; ') : null;
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
  // move columns several times: after each move every heading must still sit over its own data
  const pairs = () => evaluate("(() => { const t = document.getElementById('assets-table'); const vis = (c) => getComputedStyle(c).display !== 'none'; const hs = [...t.tHead.rows[0].cells].filter(vis).map((c) => c.textContent.trim()); const r = [...t.tBodies[0].rows[0].cells].filter(vis); return hs.map((h, i) => [h, r[i].textContent.trim(), r[i].className]); })()");
  for (const name of ['MAC', 'Name', 'IP', 'Name']) {
    await evaluate(`[...document.querySelectorAll('#view-assets .cols-row')].find((r) => r.textContent.trim().startsWith(${JSON.stringify(name)})).querySelector('.cols-up').click(); 0`);
    await sleep(250);
    const p = await pairs();
    const ip = p.find((x) => x[0] === 'IP'), mac = p.find((x) => x[0] === 'MAC'), nm = p.find((x) => x[0] === 'Name'), ty = p.find((x) => x[0] === 'Type');
    if (!/^\d+\.\d+\.\d+\.\d+$/.test(ip[1]) || !/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/.test(mac[1]) || !/namecell/.test(nm[2]) || !ty[1]) return `after moving ${name}, a heading is over the wrong data: ` + JSON.stringify(p);
  }
  now_ = await heads();
  const before = now_.indexOf('Name');
  // hide a column after the moves, then let the page redraw its rows (it does every few seconds): still the right data, still hidden
  await evaluate("[...document.querySelectorAll('#view-assets .cols-row')].find((r) => r.textContent.trim().startsWith('MAC')).querySelector('input').click(); 0");
  await sleep(250);
  for (const again of [false, true]) {
    if (again) { await evaluate("renderAssets(); 0"); await sleep(300); }
    const p = await pairs();
    if (p.some((x) => x[0] === 'MAC') || p.some((x) => /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/.test(x[1])) || !/^\d+\.\d+\.\d+\.\d+$/.test(p.find((x) => x[0] === 'IP')[1])) return (again ? 'after the page redrew its rows: ' : 'after hiding MAC: ') + JSON.stringify(p);
  }
  await evaluate("[...document.querySelectorAll('#view-assets .cols-row')].find((r) => r.textContent.trim().startsWith('MAC')).querySelector('input').click(); 0");
  await sleep(250);
  // move Name one place to the left
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

// ------------------------------------------------------------------ the setup guide
await check('the setup guide opens from Settings with its steps, its buttons lead to the pages, and "Mark as done" is remembered', async () => {
  takeProblems();
  await fetch(base + '/api/setup', { method: 'PUT', headers: { 'Content-Type': 'application/json', 'X-Denis': '1' }, body: '{"completed":false}' });
  await evaluate("location.hash = '#settings'; setTab('settings'); 0");
  await sleep(600);
  // a console that only views a copy never opens it by itself
  if (await evaluate("!!document.querySelector('#msg-dialog[open]')")) return 'the guide opened by itself in a viewer console';
  await evaluate("document.getElementById('setup-open').click(); 0");
  await sleep(700);
  const steps = await evaluate("[...document.querySelectorAll('#msg-body .setup-step')].map((s) => s.dataset.step + (s.classList.contains('done') ? ':done' : ''))");
  if (steps.map((s) => s.split(':')[0]).join() !== 'network,security,alerts,people,backups,branding') return 'steps: ' + JSON.stringify(steps);
  // (demo devices are not real ones, so "network" is not done; the backup schedule is on by default)
  if (steps.includes('network:done') || steps.includes('security:done') || !steps.includes('backups:done')) return 'the marks do not match the state of the demo: ' + JSON.stringify(steps);
  if (!(await evaluate("!!document.getElementById('setup-done') && !!document.getElementById('setup-later')"))) return 'the buttons are missing';
  // a step's button closes the guide and goes to that page
  await evaluate("document.querySelector('#msg-body .setup-step[data-step=alerts] button').click(); 0");
  await sleep(600);
  if ((await evaluate('location.hash')) !== '#alerting' || (await evaluate("!!document.querySelector('#msg-dialog[open]')"))) return 'the button did not go to the Alerting page';
  await evaluate("setTab('settings'); document.getElementById('setup-open').click(); 0");
  await sleep(700);
  await evaluate("document.getElementById('setup-done').click(); 0");
  await sleep(700);
  if (!(await (await fetch(base + '/api/setup')).json()).completed) return 'Mark as done was not remembered';
  await evaluate("document.getElementById('setup-open').click(); 0");
  await sleep(700);
  const again = await evaluate("({ done: !!document.getElementById('setup-done'), text: document.getElementById('msg-body').innerText })");
  await evaluate("document.getElementById('msg-dialog').close(); 0");
  if (again.done) return 'a guide that is finished still offers Mark as done';
  const bad = await evaluate(BAD_TEXT);
  const p = takeProblems();
  return bad.length ? `the page shows ${bad.join(', ')}` : p.length ? p.join('; ') : null;
});

// ------------------------------------------------------------------ the second sign-in step, with real sign-ins
// A separate console with sign-in switched on, made for this test: an empty database in the temporary folder and
// the one-time password the program itself prints at its first start (never shown in the output).
await check('the authenticator-app second step: set-up with a QR code and recovery codes, a code at sign-in, a wrong current password does not sign you out', async () => {
  let srv = null;
  try { return await (async () => {
  const otp = (b32, offset = 0) => {
    const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = ''; for (const c of b32.replace(/\s/g, '')) bits += A.indexOf(c).toString(2).padStart(5, '0');
    const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
    const step = Math.floor(Date.now() / 30000) + offset;
    const msg = Buffer.alloc(8); msg.writeBigUInt64BE(BigInt(step));
    const h = createHmac('sha1', key).update(msg).digest();
    const o = h[19] & 15;
    return String(((h.readUInt32BE(o) & 0x7fffffff) % 1000000)).padStart(6, '0');
  };
  const port = await freePort();
  const dbFile = join(tmp, 'secured.db');
  srv = spawn(bin, ['serve', '--db', dbFile, '--listen', `127.0.0.1:${port}`], { stdio: ['ignore', 'ignore', 'pipe'] });
  procs.push(srv);
  let firstPassword = null;
  srv.stderr.on('data', (d) => { const m = /password: (\S+)/.exec(String(d)); if (m) firstPassword = m[1]; });
  const url = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 50 && !firstPassword; i++) await sleep(200);
  for (let i = 0; i < 50; i++) { try { if ((await fetch(url + '/api/health')).ok) break; } catch { /* not yet */ } await sleep(200); }
  if (!firstPassword) return 'the test console did not print its first password';
  const newPassword = 'Smoke-' + randomBytes(9).toString('hex');
  takeProblems();
  await load(url + '/');
  await sleep(700);
  const type = (id, v) => evaluate(`(() => { const e = document.getElementById(${JSON.stringify(id)}); e.value = ${JSON.stringify(v)}; e.dispatchEvent(new Event('input')); })()`);
  const signIn = async (user, pw) => { await type('login-user', user); await type('login-pass', pw); await evaluate("document.querySelector('#login-form button[type=submit]').click(); 0"); await sleep(1800); };
  await signIn('admin', firstPassword);
  // the forced change of password: a wrong current password is refused and does NOT end the session
  const dialogInputs = () => evaluate("[...document.querySelectorAll('#dialog-form input')].map((i) => i.type)");
  if ((await dialogInputs()).length !== 3) return 'the forced password change did not open: ' + JSON.stringify(await dialogInputs());
  await evaluate(`(() => { const i = document.querySelectorAll('#dialog-form input'); i[0].value = 'not-the-password-1'; i[1].value = ${JSON.stringify(newPassword)}; i[2].value = ${JSON.stringify(newPassword)}; document.querySelector('#dialog-form button[type=submit]').click(); })()`);
  await sleep(1200);
  if (!(await evaluate("document.getElementById('login').hidden")) || !(await evaluate("!!document.querySelector('#form-dialog[open]')"))) return 'a wrong current password signed the person out (or closed the dialog)';
  await evaluate(`(() => { const i = document.querySelectorAll('#dialog-form input'); i[0].value = ${JSON.stringify(firstPassword)}; i[1].value = ${JSON.stringify(newPassword)}; i[2].value = ${JSON.stringify(newPassword)}; document.querySelector('#dialog-form button[type=submit]').click(); })()`);
  await sleep(2500);
  if (!(await ready2())) return 'the console did not open after the password change';
  // My account: set up the app
  await evaluate("location.hash = '#account'; setTab('account'); 0");
  await sleep(1000);
  await evaluate("document.getElementById('totp-setup').click(); 0");
  await sleep(500);
  await evaluate(`(() => { document.querySelector('#dialog-form input[type=password]').value = ${JSON.stringify(newPassword)}; document.querySelector('#dialog-form button[type=submit]').click(); })()`);
  await sleep(1500);
  const qrOk = await evaluate("(async () => { const i = document.getElementById('totp-qr'); if (!i) return 'no QR image'; await new Promise((r) => (i.complete ? r() : (i.onload = i.onerror = r))); return i.naturalWidth > 0 ? 'ok' : 'the QR image did not load'; })()");
  if (qrOk !== 'ok') return qrOk;
  const secret = await evaluate("document.getElementById('totp-secret').textContent");
  if (!/^[A-Z2-7 ]{30,}$/.test(secret)) return 'the secret to type by hand looks wrong';
  await evaluate("document.getElementById('totp-code').value = '000000'; document.querySelector('#dialog-form button[type=submit]').click(); 0");
  await sleep(1000);
  if (!(await evaluate("!!document.querySelector('#form-dialog[open]') && document.querySelector('#dialog-form .form-error').textContent.length > 0"))) return 'a wrong code was not refused';
  await evaluate(`document.getElementById('totp-code').value = ${JSON.stringify(otp(secret))}; document.querySelector('#dialog-form button[type=submit]').click(); 0`);
  await sleep(1500);
  const codes = await evaluate("(document.getElementById('recovery-codes') || {}).textContent || ''");
  const recovery = codes.split('\n').filter(Boolean);
  if (recovery.length !== 10 || !recovery.every((c) => /^[a-z2-9]{5}-[a-z2-9]{5}$/.test(c))) return 'the recovery codes are missing: ' + JSON.stringify(recovery.length);
  await evaluate("document.getElementById('msg-dialog').close(); 0");
  await sleep(600);
  if (!/An authenticator app is set up/.test(await evaluate("document.getElementById('totp-body').innerText"))) return 'the account page does not say it is on';
  // sign out, sign in: the password alone gets the code step and no session
  await evaluate("document.getElementById('logout').click(); 0");
  await sleep(800);
  await signIn('admin', newPassword);
  if (!(await evaluate("!document.getElementById('login-mfa').hidden && !document.getElementById('login').hidden"))) return 'the code step did not appear after the right password';
  if (await evaluate("!document.getElementById('app').hidden")) return 'the app opened before the code was typed';
  await type('login-code', '000000');
  await evaluate("document.querySelector('#login-form button[type=submit]').click(); 0");
  await sleep(1200);
  if (!(await evaluate("document.getElementById('login-error').textContent.length > 0 && document.getElementById('app').hidden"))) return 'a wrong code was not refused';
  // the code of the next 30-second step is accepted too (the clock may be a little off) and the one that confirmed the set-up is used up
  await type('login-code', otp(secret, 1));
  await evaluate("document.querySelector('#login-form button[type=submit]').click(); 0");
  await sleep(2000);
  if (!(await ready2())) return 'a right code did not open the console';
  // an administrator can require a second step for everybody, and the choice is saved
  await evaluate("location.hash = '#settings'; setTab('settings'); 0");
  await sleep(1000);
  await evaluate("document.getElementById('mfa-policy').value = 'all'; document.getElementById('mfa-policy').dispatchEvent(new Event('change')); document.getElementById('mfa-save').click(); 0");
  await sleep(1000);
  const policy = await evaluate("fetch('/api/security').then((r) => r.json()).then((j) => j.mfa_required)");
  if (policy !== 'all') return 'the policy was not saved: ' + policy;
  // a recovery code signs in once
  await evaluate("document.getElementById('logout').click(); 0");
  await sleep(800);
  await signIn('admin', newPassword);
  await type('login-code', recovery[0].toUpperCase());
  await evaluate("document.querySelector('#login-form button[type=submit]').click(); 0");
  await sleep(2000);
  if (!(await ready2())) return 'a recovery code did not sign in';
  await evaluate("document.getElementById('logout').click(); 0");
  await sleep(800);
  await signIn('admin', newPassword);
  await type('login-code', recovery[0]);
  await evaluate("document.querySelector('#login-form button[type=submit]').click(); 0");
  await sleep(1200);
  if (!(await evaluate("document.getElementById('app').hidden"))) return 'a recovery code worked twice';
  // a second step is required for everybody, and this person has none any more (an administrator removed it): the guide to set one up opens
  await type('login-code', recovery[1]);
  await evaluate("document.querySelector('#login-form button[type=submit]').click(); 0");
  await sleep(2000);
  if (!(await ready2())) return 'the second recovery code did not sign in';
  await evaluate("api('DELETE', '/api/users/' + state.me.id + '/totp').then(() => 0)");
  await sleep(800);
  await load(url + '/');
  await sleep(800);
  await signIn('admin', newPassword);
  await sleep(500);
  const forced = await evaluate("({ open: !!document.querySelector('#form-dialog[open]'), title: (document.querySelector('#dialog-form h3') || {}).textContent, cancel: [...document.querySelectorAll('#dialog-form button')].some((b) => b.textContent === 'Cancel') })");
  if (!forced.open || forced.title !== 'Set up a second sign-in step' || forced.cancel) return 'the required set-up did not open (or can be cancelled): ' + JSON.stringify(forced);
  await evaluate("document.querySelector('#dialog-form button[type=submit]').click(); 0");
  await sleep(800);
  await evaluate(`(() => { document.querySelector('#dialog-form input[type=password]').value = ${JSON.stringify(newPassword)}; document.querySelector('#dialog-form button[type=submit]').click(); })()`);
  await sleep(1500);
  const secret2 = await evaluate("(document.getElementById('totp-secret') || {}).textContent || ''");
  if (!secret2) return 'no new secret was offered';
  await evaluate(`document.getElementById('totp-code').value = ${JSON.stringify(otp(secret2))}; document.querySelector('#dialog-form button[type=submit]').click(); 0`);
  await sleep(1500);
  await evaluate("document.getElementById('msg-dialog').close(); 0"); // closing the recovery codes reloads the console
  await sleep(2500);
  if (!(await ready2())) return 'the console did not open after the required set-up';
  if (!(await evaluate("fetch('/api/auth/totp').then((r) => r.json()).then((j) => j.enabled)"))) return 'the app is not on after the required set-up';
  const bad = await evaluate("['null', 'undefined', '[object Object]'].filter((w) => document.body.innerText.includes(w))");
  takeProblems(); // wrong codes and passwords are refused with 401/403 on purpose
  srv.kill('SIGTERM');
  return bad.length ? 'the page shows ' + bad.join(', ') : null;
  })(); } finally {
    // back to the main console for the checks that follow
    if (srv) srv.kill('SIGTERM');
    await load(base + '/#assets');
    await ready();
  }
});

// ------------------------------------------------------------------ switches over SNMP: an independent little agent
// (written here in JavaScript from the protocol description, not from the program's own code, so the two check each other)
const snmpAgent = (table, community) => {
  const berLen = (n) => { if (n < 128) return Buffer.from([n]); const b = []; while (n > 0) { b.unshift(n & 255); n >>= 8; } return Buffer.from([0x80 | b.length, ...b]); };
  const tlv = (tag, body) => Buffer.concat([Buffer.from([tag]), berLen(body.length), body]);
  const int = (v) => { const b = []; let n = v; do { b.unshift(n & 255); n = Math.floor(n / 256); } while (n > 0); if (b[0] & 0x80) b.unshift(0); return tlv(2, Buffer.from(b)); };
  const oidEnc = (arcs) => { const out = [arcs[0] * 40 + arcs[1]]; for (const a of arcs.slice(2)) { const g = [a & 127]; let n = a >> 7; while (n > 0) { g.unshift((n & 127) | 128); n >>= 7; } out.push(...g); } return tlv(6, Buffer.from(out)); };
  const read = (buf, pos) => { const tag = buf[pos]; let len = buf[pos + 1]; let hdr = 2; if (len & 0x80) { const n = len & 0x7f; len = 0; for (let i = 0; i < n; i++) len = len * 256 + buf[pos + 2 + i]; hdr = 2 + n; } return { tag, start: pos + hdr, end: pos + hdr + len }; };
  const oidDec = (b) => { const arcs = [Math.floor(b[0] / 40), b[0] % 40]; let cur = 0; for (const x of b.slice(1)) { cur = cur * 128 + (x & 127); if (!(x & 128)) { arcs.push(cur); cur = 0; } } return arcs; };
  const cmp = (a, b) => { for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i]; return a.length - b.length; };
  const rows = [...table.entries()].map(([k, v]) => [k.split('.').map(Number), v]).sort((x, y) => cmp(x[0], y[0]));
  const val = (v) => (typeof v === 'number' ? int(v) : tlv(4, Buffer.from(v)));
  const sock = dgram.createSocket('udp4');
  sock.on('message', (msg, rinfo) => {
    try {
      const top = read(msg, 0);
      let p = top.start;
      const ver = read(msg, p); p = ver.end;
      const com = read(msg, p); p = com.end;
      if (msg.subarray(com.start, com.end).toString() !== community) return;
      const pdu = read(msg, p);
      let q = pdu.start;
      const id = read(msg, q); q = id.end;
      const a = read(msg, q); q = a.end;
      const b = read(msg, q); q = b.end;
      const maxRep = msg.subarray(b.start, b.end).readUIntBE(0, b.end - b.start);
      const list = read(msg, q);
      const vb = read(msg, list.start);
      const name = read(msg, vb.start);
      const from = oidDec(msg.subarray(name.start, name.end));
      let out = [];
      if (pdu.tag === 0xa0) { const hit = rows.find(([k]) => cmp(k, from) === 0); out = [[from, hit ? hit[1] : null]]; }
      else if (pdu.tag === 0xa1 || pdu.tag === 0xa5) {
        const following = rows.filter(([k]) => cmp(k, from) > 0).slice(0, pdu.tag === 0xa5 ? maxRep : 1);
        out = following.length ? following : [[from, undefined]];
      } else return;
      const binds = Buffer.concat(out.map(([k, v]) => tlv(0x30, Buffer.concat([oidEnc(k), v === null ? tlv(0x81, Buffer.alloc(0)) : v === undefined ? tlv(0x82, Buffer.alloc(0)) : val(v)]))));
      const resp = tlv(0x30, Buffer.concat([int(1), tlv(4, Buffer.from(community)), tlv(0xa2, Buffer.concat([msg.subarray(id.start - 2, id.end), int(0), int(0), tlv(0x30, binds)]))]));
      sock.send(resp, rinfo.port, rinfo.address);
    } catch { /* a malformed request: no answer */ }
  });
  return new Promise((res) => sock.bind(0, '127.0.0.1', () => res({ port: sock.address().port, close: () => sock.close() })));
};

await check('a switch read over SNMP shows which port a device is plugged into: added, read, drawn, listed on the device, removed', async () => {
  takeProblems();
  await load(base + '/#assets');
  if (!(await ready())) return 'the console did not start';
  const mac = await evaluate("state.assets.find((a) => a.mac && !a.randomized_mac).mac");
  const table = new Map([['1.3.6.1.2.1.1.1.0', 'Smoke switch'], ['1.3.6.1.2.1.1.5.0', 'smoke-sw'],
    ['1.3.6.1.2.1.31.1.1.1.1.1', 'Gi1/0/1'], ['1.3.6.1.2.1.31.1.1.1.1.2', 'Gi1/0/2'], ['1.3.6.1.2.1.31.1.1.1.18.2', 'smoke cable'],
    ['1.3.6.1.2.1.17.1.4.1.2.1', 1], ['1.3.6.1.2.1.17.1.4.1.2.2', 2],
    ['1.3.6.1.2.1.17.7.1.2.2.1.2.1.' + mac.split(':').map((h) => parseInt(h, 16)).join('.'), 2]]);
  const agent = await snmpAgent(table, 'smoke-ro');
  try {
    await evaluate("location.hash = '#settings/switches'; setTab('settings'); 0");
    await sleep(900);
    await evaluate("document.getElementById('add-switch').click(); 0");
    await sleep(500);
    await evaluate(`(() => { const d = document.getElementById('dialog-form'); d.querySelector('input[required]').value = 'Smoke switch'; document.getElementById('switch-address').value = '127.0.0.1:${agent.port}'; document.getElementById('switch-community').value = 'smoke-ro'; d.querySelector('button[type=submit]').click(); })()`);
    await sleep(1500);
    if (!(await evaluate("!!document.querySelector('#switches-body .watch[data-switch]')"))) return 'the switch was not added: ' + await evaluate("(document.querySelector('#dialog-form .form-error') || {}).textContent");
    await evaluate("document.querySelector('#switches-body .poll-switch').click(); 0");
    await sleep(2500);
    const said = await evaluate("document.getElementById('msg-body').innerText");
    await evaluate("document.getElementById('msg-dialog').close(); 0");
    if (!/Read: 2 ports, 0 neighbours, 1 MAC/.test(said)) return 'reading it said: ' + said;
    // drawn
    await evaluate("location.hash = '#topology'; setTab('topology'); document.querySelector('#topo-mode button[data-mode=physical]').click(); 0");
    await sleep(1500);
    const drawn = await evaluate("({ switches: document.querySelectorAll('#topo-physical-body .switch-node').length, devices: document.querySelectorAll('#topo-physical-body circle.node').length, label: [...document.querySelectorAll('#topo-physical-body svg text')].map((t) => t.textContent) })");
    if (drawn.switches !== 1 || drawn.devices !== 1 || !drawn.label.includes('Gi1/0/2')) return 'the map: ' + JSON.stringify(drawn);
    // the only learned MAC belongs to a known device, so there is no "unknown MACs" line: check
    // this does not leave a stray "null" behind (regression: box.replaceChildren(..., null, ...))
    const physicalBad = await evaluate(BAD_TEXT);
    if (physicalBad.length) return 'the physical map shows ' + physicalBad.join(', ');
    // on the device itself
    const id = await evaluate(`state.assets.find((a) => a.mac === ${JSON.stringify(mac)}).id`);
    await evaluate(`showDetail(${id}); 0`);
    await sleep(1200);
    const detail = await evaluate("document.getElementById('detail-body').innerText");
    if (!/Connected to\s*\n?\s*Smoke switch · Gi1\/0\/2 \(smoke cable\)/.test(detail)) return 'the device does not say where it is plugged in: ' + detail.slice(0, 400);
    await evaluate("document.getElementById('close').click(); document.querySelector('#topo-mode button[data-mode=logical]').click(); 0");
    // removed again
    await evaluate("location.hash = '#settings/switches'; setTab('settings'); 0");
    await sleep(800);
    await evaluate("window.confirm = () => true; [...document.querySelectorAll('#switches-body .watch-actions button')].find((b) => b.textContent === 'Delete').click(); 0");
    await sleep(1200);
    if ((await (await fetch(base + '/api/switches')).json()).targets.length) return 'the switch was not removed';
    const bad = await evaluate(BAD_TEXT);
    const p = takeProblems();
    return bad.length ? `the page shows ${bad.join(', ')}` : p.length ? p.join('; ') : null;
  } finally {
    agent.close();
  }
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

// ------------------------------------------------------------------ software versions from banners
await check('findings about software versions list what was read per device, and the device panel shows its banners', async () => {
  takeProblems();
  await evaluate("location.hash = '#findings'; setTab('findings'); 0");
  await sleep(1200);
  const cards = await evaluate("[...document.querySelectorAll('#findings-list .finding')].map((c) => ({ id: c.id, text: c.innerText }))");
  const kev = cards.find((c) => c.id === 'finding-kev_software');
  const eol = cards.find((c) => c.id === 'finding-eol_software');
  if (!kev || !/Apache HTTP Server 2\.4\.49 is in the range affected by CVE-2021-4/.test(kev.text)) return 'the known-exploited finding is missing or lacks its evidence: ' + (kev ? kev.text.slice(0, 300) : 'no card');
  if (!eol || !/nginx 1\.10\.3: support for the 1\.10 series ended on 2017-04-12/.test(eol.text) || !/distribution may still patch it/.test(eol.text)) return 'the end-of-support finding is missing or lacks its evidence: ' + (eol ? eol.text.slice(0, 300) : 'no card');
  // the device that announces it
  const id = await evaluate("state.assets.find((a) => (a.fingerprint.identity || {})['banner.http'] === 'Server: Apache/2.4.49 (Unix)').id");
  await evaluate(`showDetail(${id}); 0`);
  await sleep(1000);
  const detail = await evaluate("document.getElementById('detail-body').innerText");
  await evaluate("document.getElementById('close').click(); 0");
  if (!/Web server banner\s*\n?\s*Server: Apache\/2\.4\.49 \(Unix\)/.test(detail)) return 'the banner is not in the device panel: ' + detail.slice(0, 300);
  // the settings box
  await evaluate("location.hash = '#settings/vulndata'; setTab('settings'); 0");
  await sleep(1000);
  const box = await evaluate("document.getElementById('vuln-body').innerText");
  if (!/Support dates for \d+ products and \d+ known-exploited vulnerabilities, as of 20\d\d-\d\d-\d\d/.test(box)) return 'the software data box says: ' + box.slice(0, 300);
  const bad = await evaluate(BAD_TEXT);
  const p = takeProblems();
  return bad.length ? `the page shows ${bad.join(', ')}` : p.length ? p.join('; ') : null;
});

// ------------------------------------------------------------------ Pushover and ntfy channels
await check('Pushover and ntfy channels can be added from Alerting with the right fields, never show their secrets, and are removed again', async () => {
  takeProblems();
  await evaluate("location.hash = '#alerting'; setTab('alerting'); 0");
  await sleep(900);
  const pick = (k) => evaluate(`(() => { const s = document.getElementById('ch-kind'); s.value = ${JSON.stringify(k)}; s.dispatchEvent(new Event('change')); return { user: !document.getElementById('ch-user-row').hidden, url: !document.getElementById('ch-url-row').hidden, secret: document.getElementById('ch-secret-row').firstChild.textContent }; })()`);
  const po = await pick('pushover');
  if (!po.user || po.url || po.secret !== 'Application token') return 'the Pushover form: ' + JSON.stringify(po);
  await evaluate(`(() => { document.getElementById('ch-name').value = 'Smoke phone'; document.getElementById('ch-secret').value = 'a'.repeat(30); document.getElementById('ch-user').value = 'u'.repeat(30); document.querySelector('#channel-form button[type=submit]').click(); })()`);
  await sleep(1200);
  const nt = await pick('ntfy');
  if (nt.user || !nt.url || nt.secret !== 'Access token (optional)') return 'the ntfy form: ' + JSON.stringify(nt);
  await evaluate(`(() => { document.getElementById('ch-name').value = 'Smoke topic'; document.getElementById('ch-url').value = 'https://ntfy.sh/smoke-test-topic-123456'; document.querySelector('#channel-form button[type=submit]').click(); })()`);
  await sleep(1200);
  const list = await (await fetch(base + '/api/channels')).json();
  const mine = list.filter((c) => c.name.startsWith('Smoke '));
  if (mine.length !== 2 || JSON.stringify(list).includes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa') || JSON.stringify(list).includes('smoke-test-topic')) return 'saved: ' + JSON.stringify(mine) + ' (or a secret was shown)';
  const rows = await evaluate("[...document.querySelectorAll('#channels-table tbody tr')].map((r) => r.innerText)");
  if (!rows.some((r) => /Smoke phone[\s\S]*Pushover/.test(r)) || !rows.some((r) => /Smoke topic[\s\S]*ntfy/.test(r))) return 'the list: ' + JSON.stringify(rows);
  for (const c of mine) await fetch(base + '/api/channels/' + c.id, { method: 'DELETE', headers: { 'X-Denis': '1' } });
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
  await evaluate("(() => { const d = document.getElementById('dialog-form'); d.querySelector('input[required]').value = 'Smoke test watch'; const p = d.querySelectorAll('select')[0]; p.value = '3'; p.dispatchEvent(new Event('change')); d.querySelector('button[type=submit]').click(); })()");
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
await check('an allow-list watch ("any communication", also encrypted) can be added from the OT watches and is described in words', async () => {
  takeProblems();
  await evaluate("location.hash = '#rules'; setTab('rules'); 0");
  await sleep(1000);
  await evaluate("document.querySelector('#watches .row button.primary').click(); 0");
  await sleep(500);
  const plc = await evaluate("state.assets.find((a) => a.device_type === 'plc').id");
  await evaluate(`(() => { const d = document.getElementById('dialog-form'); const p = d.querySelector('select'); p.value = '0'; p.dispatchEvent(new Event('change')); if (!d.querySelector('input[type=checkbox]').checked) throw new Error('the preset did not tick "any communication"'); d.querySelector('input[required]').value = 'Smoke allow-list'; d.querySelector('button[type=submit]').click(); })()`);
  await sleep(1500);
  const r = await (await fetch(base + '/api/rules')).json();
  const w = (r.ot_watches || []).find((x) => x.name === 'Smoke allow-list');
  if (!w || !w.any_traffic || w.proto !== 'any') return 'the watch was not saved: ' + JSON.stringify(r.ot_watches);
  const text = await evaluate("[...document.querySelectorAll('#watches .watch')].map((x) => x.innerText).find((x) => x.includes('Smoke allow-list')) || ''");
  if (!/any communication/.test(text)) return 'the list does not describe it: ' + text;
  await evaluate("window.confirm = () => true; [...document.querySelectorAll('#watches .watch')].find((x) => x.innerText.includes('Smoke allow-list')).querySelector('.watch-actions button:last-child').click(); 0");
  await sleep(1200);
  const r2 = await (await fetch(base + '/api/rules')).json();
  const p = takeProblems();
  if ((r2.ot_watches || []).some((x) => x.name === 'Smoke allow-list')) return 'the watch was not deleted';
  void plc;
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
