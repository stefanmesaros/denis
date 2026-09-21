'use strict';
// Translations. The English text itself is the key: tr('Devices') returns the translation
// of "Devices" in the chosen language, or "Devices" when there is none (so a missing
// translation shows readable English, never a code). Placeholders look like {name}:
// tr('{n} devices', { n: 3 }).
//
// The catalog for a language is ui/i18n/<lang>.json, generated from tools/i18n/strings.tsv.
// It is loaded *synchronously* before the other scripts run, so text built at start-up is
// translated too. The language is: the person's own choice (remembered in this browser), else the
// administrator's default (Settings → Branding), else English.

const LANGS = { en: 'English', de: 'Deutsch', fr: 'Français', es: 'Español', sk: 'Slovenčina' };
const LOCALES = { en: 'en-GB', de: 'de-DE', fr: 'fr-FR', es: 'es-ES', sk: 'sk-SK' };
let LANG = 'en';
let CATALOG = {};

function readStore(key) {
  try { return localStorage.getItem(key); } catch (e) { return null; }
}
function writeStore(key, value) {
  try { localStorage.setItem(key, value); } catch (e) { /* storage blocked: the choice lasts until reload */ }
}

/** The language to use: own choice, else the remembered administrator default, else English. */
function pickLanguage() {
  for (const k of ['denis-lang', 'denis-default-lang']) {
    const v = readStore(k);
    if (v && LANGS[v]) return v;
  }
  return 'en';
}

function loadCatalogSync(lang) {
  if (lang === 'en') return {};
  try {
    const x = new XMLHttpRequest();
    x.open('GET', '/i18n/' + lang + '.json', false);
    x.send();
    if (x.status === 200) return JSON.parse(x.responseText);
  } catch (e) { /* offline or blocked: English */ }
  return {};
}

LANG = pickLanguage();
CATALOG = loadCatalogSync(LANG);
document.documentElement.lang = LANG;

/** Translate `key` and fill in {placeholders}. */
function tr(key, vars) {
  let s = Object.prototype.hasOwnProperty.call(CATALOG, key) ? CATALOG[key] : key;
  if (vars) s = s.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k]) : m));
  return s;
}

/** Locale for dates and numbers. */
const locale = () => LOCALES[LANG] || 'en-GB';

/** Translate the static page: text nodes and placeholder/title/aria-label attributes. */
function translateDom(root = document.body) {
  if (LANG === 'en') return;
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  const nodes = [];
  while (walker.nextNode()) nodes.push(walker.currentNode);
  for (const n of nodes) {
    const raw = n.nodeValue;
    const key = raw.trim();
    if (key && Object.prototype.hasOwnProperty.call(CATALOG, key)) n.nodeValue = raw.replace(key, CATALOG[key]);
  }
  for (const el of root.querySelectorAll('[placeholder],[title],[aria-label]')) {
    for (const a of ['placeholder', 'title', 'aria-label']) {
      const v = el.getAttribute(a);
      if (v && Object.prototype.hasOwnProperty.call(CATALOG, v.trim())) el.setAttribute(a, CATALOG[v.trim()]);
    }
  }
}

/** Fill the language pickers (header and sign-in page) and remember a change. */
function initLanguagePickers() {
  for (const id of ['lang', 'login-lang']) {
    const sel = document.getElementById(id);
    if (!sel) continue;
    sel.replaceChildren(...Object.entries(LANGS).map(([code, name]) => {
      const o = document.createElement('option');
      o.value = code;
      o.textContent = name;
      return o;
    }));
    sel.value = LANG;
    sel.onchange = () => { writeStore('denis-lang', sel.value); location.reload(); };
  }
}

/**
 * The administrator's default language (from branding) applies to people who never chose one.
 * It is remembered so the *next* page load already starts in it; if it differs from what is
 * showing now, reload once.
 */
function applyDefaultLanguage(defaultLang) {
  if (!defaultLang || !LANGS[defaultLang]) return;
  writeStore('denis-default-lang', defaultLang);
  if (!readStore('denis-lang') && defaultLang !== LANG) location.reload();
}

/** Links into the documentation carry the language, so its menu and header follow the console's. */
function tagDocLinks() {
  if (LANG === 'en') return;
  for (const a of document.querySelectorAll('a[href^="/docs/"]')) {
    const href = a.getAttribute('href');
    if (href.includes('?')) continue;
    const [path, anchor] = href.split('#');
    a.setAttribute('href', (path === '/docs/' ? '/docs/index' : path) + '?lang=' + LANG + (anchor ? '#' + anchor : ''));
  }
}

translateDom();
initLanguagePickers();
tagDocLinks();
