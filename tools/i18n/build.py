#!/usr/bin/env python3
"""Build the console's language catalogs.

    tools/i18n/*.tsv   ->   ui/i18n/{de,fr,es,sk}.json

Each .tsv line is `English || Deutsch || Français || Español || Slovenčina`; lines starting with # and
blank lines are ignored. English is the key (the UI calls tr('English text')). `{name}` placeholders
must appear in every language.

    python3 tools/i18n/build.py           write the JSON catalogs
    python3 tools/i18n/build.py --check   also list strings the UI uses that have no translation

The Rust test `i18n::tests` enforces the same rules in CI, so a missing translation fails the build.
"""
import glob
import html
import json
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
LANGS = ['de', 'fr', 'es', 'sk']
PLACEHOLDER = re.compile(r'\{(\w+)\}')


def load():
    catalog = {}
    for path in sorted(glob.glob(os.path.join(ROOT, 'tools', 'i18n', '*.tsv'))):
        for n, line in enumerate(open(path, encoding='utf-8'), 1):
            line = line.rstrip('\n')
            if not line.strip() or line.startswith('#'):
                continue
            cols = [c.strip() for c in line.split(' || ')]
            where = f'{os.path.basename(path)}:{n}'
            if len(cols) != 5:
                sys.exit(f'{where}: expected 5 columns, found {len(cols)}: {line[:60]}')
            key = cols[0]
            if key in catalog:
                sys.exit(f'{where}: duplicate key {key!r}')
            want = sorted(PLACEHOLDER.findall(key))
            for lang, text in zip(LANGS, cols[1:]):
                if not text:
                    sys.exit(f'{where}: empty {lang} translation for {key!r}')
                if sorted(PLACEHOLDER.findall(text)) != want:
                    sys.exit(f'{where}: {lang} placeholders differ from English for {key!r}')
            catalog[key] = dict(zip(LANGS, cols[1:]))
    return catalog


def write(catalog):
    out = os.path.join(ROOT, 'ui', 'i18n')
    os.makedirs(out, exist_ok=True)
    for lang in LANGS:
        data = {k: v[lang] for k, v in sorted(catalog.items())}
        with open(os.path.join(out, lang + '.json'), 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=0, sort_keys=True)
            f.write('\n')
    print(f'{len(catalog)} strings x {len(LANGS)} languages written to ui/i18n/')


def js_keys():
    keys = {}
    for name in ('app.js', 'admin.js', 'rules.js', 'findings.js', 'reports.js', 'main.js', 'icons.js'):
        text = open(os.path.join(ROOT, 'ui', name), encoding='utf-8').read()
        for m in re.finditer(r"\btr\(\s*'((?:[^'\\]|\\.)*)'", text):
            keys.setdefault(m.group(1).replace("\\'", "'"), name)
    # the icon chooser's group titles are passed to tr() as variables
    icons = open(os.path.join(ROOT, 'ui', 'icons.js'), encoding='utf-8').read()
    block = icons[icons.index('const ICON_CATEGORIES = ['):]
    for m in re.finditer(r"^  \['([^']+)', \[", block, flags=re.M):
        keys.setdefault(m.group(1), 'icons.js')
    keys.setdefault('Other', 'admin.js')
    # icon names, as shown ("smart_plug" -> "smart plug")
    for m in re.finditer(r"^  ([a-z0-9_]+): \[\[", icons[:icons.index('const NAV_SHAPES')], flags=re.M):
        keys.setdefault(m.group(1).replace('_', ' '), 'icons.js')
    return keys


def html_keys():
    text = open(os.path.join(ROOT, 'ui', 'index.html'), encoding='utf-8').read()
    text = re.sub(r'<script.*?</script>', '', text, flags=re.S)
    keys = {}
    for m in re.finditer(r'>([^<>]+)<', text):
        t = ' '.join(html.unescape(m.group(1)).split())
        if len(t) >= 2 and re.search(r'[A-Za-z]{2}', t):
            keys.setdefault(t, 'index.html')
    for m in re.finditer(r'(?:placeholder|title|aria-label)="([^"]+)"', text):
        keys.setdefault(html.unescape(m.group(1)), 'index.html')
    return keys


def unesc(x):
    return x.replace('\\"', '"').replace('\\n', '\n').replace('\\\\', '\\')


def rust(name):
    return open(os.path.join(ROOT, 'src', name), encoding='utf-8').read()


def server_keys():
    """English text the server sends for the UI to translate (rules, findings, advice, compliance, lists)."""
    out = {}
    q = r'"((?:[^"\\]|\\.)*)"'
    s = rust('rules.rs')
    a = s.index('pub static RULE_INFO')
    for m in re.finditer(r'(?:title|summary|needs): ' + q, s[a:s.index('];', a)]):
        out[unesc(m.group(1))] = 'rules.rs'
    a = s.index('pub static PARAMS')
    for m in re.finditer(r'param\("\w+", ' + q + ', ' + q + ', ' + q, s[a:s.index('];', a)]):
        for g in (1, 2, 3):
            out[unesc(m.group(g))] = 'rules.rs'
    s = rust('findings.rs')
    for m in re.finditer(r'kind\("\w+",\s*"\w+",\s*' + q + r',\s*' + q + r',\s*' + q + r'\)', s):
        for g in (1, 2, 3):
            out[unesc(m.group(g))] = 'findings.rs'
    s = rust('detect.rs')
    a = s.index('pub const ADVICE')
    for m in re.finditer(r'\(\s*(?:RULE_\w+|"\w+"),\s*' + q + r'\)', s[a:s.index('];', a)]):
        out[unesc(m.group(1))] = 'detect.rs'
    s = rust('compliance.rs')
    body = s[s.index('pub fn assess'):s.index('#[cfg(test)]')]
    for pat in (r'(?:label|detail|title|evidence|note|disclaimer): (?:if [^{]*\{ )?' + q, r'else \{ ' + q, r'\{ ' + q + r' \}'):
        for m in re.finditer(pat, body):
            t = unesc(m.group(1))
            if t not in ('in_place', 'partial', 'not_in_place'):
                out[t] = 'compliance.rs'
    # short words the UI shows from server-side lists
    for fname, const in (('fingerprint.rs', 'DEVICE_TYPES'), ('tracking.rs', 'STATUSES'), ('tracking.rs', 'CRITICALITIES'), ('tracking.rs', 'ICONS')):
        s = rust(fname)
        a = s.index('pub const ' + const)
        for w in re.findall(r'"([^"]+)"', s[a:s.index('];', a)]):
            out[w.replace('_', ' ')] = fname
    return out


CODE_LIKE = ('--', 'Authorization:')


def check(catalog):
    missing = {}
    for source in (js_keys(), html_keys(), server_keys()):
        for k, where in source.items():
            if k not in catalog and not k.startswith(CODE_LIKE):
                missing[k] = where
    for k, where in missing.items():
        print(f'missing [{where}]: {k}')
    print(f'{len(missing)} UI strings without translation')
    return not missing


if __name__ == '__main__':
    cat = load()
    write(cat)
    if '--check' in sys.argv and not check(cat):
        sys.exit(1)
