//! The user documentation, served from the console at `/docs/`.
//!
//! The Markdown files in `docs/` are compiled into the binary (so the help is
//! always the version that matches the running program, and works offline) and
//! rendered to HTML on request.
//!
//! Safety: the pages are ours, but they are still rendered defensively. Raw HTML
//! in the Markdown is escaped, not passed through; the response carries a CSP that
//! allows inline *styles* only (no script at all); and only page names from the
//! fixed table of contents are served, so no path can reach any other file.

use pulldown_cmark::{html, CowStr, Event, HeadingLevel, Options, Parser, Tag, TagEnd};
use rust_embed::RustEmbed;

use crate::branding::{self, Branding};

#[derive(RustEmbed)]
#[folder = "docs/"]
struct DocFiles;

/// Page id (file stem), menu title. The order is the menu order.
pub const PAGES: &[(&str, &str)] = &[
    ("index", "Overview"),
    ("quickstart", "Quick start"),
    ("tour", "Console tour"),
    ("concepts", "Concepts"),
    ("asset-management", "Asset management"),
    ("detection-rules", "Detection rules"),
    ("ot-guide", "OT guide"),
    ("switches", "Switches (SNMP)"),
    ("alerting", "Alerting"),
    ("branding", "Branding"),
    ("licensing", "Licensing"),
    ("export", "Export & SIEM"),
    ("deployment", "Deployment"),
    ("docker", "Docker"),
    ("operations", "Operations"),
    ("updates", "Updates"),
    ("security", "Security"),
    ("api", "API"),
    ("troubleshooting", "Troubleshooting"),
];

/// The words around the documentation (menu, header). The pages themselves are English; this is
/// what lets someone whose console is in another language find their way around them.
struct Chrome {
    lang: &'static str,
    documentation: &'static str,
    back: &'static str,
    notice: &'static str,
    /// Menu titles, in `PAGES` order.
    menu: [&'static str; 19],
}

const CHROME: &[Chrome] = &[
    Chrome {
        lang: "de", documentation: "Dokumentation", back: "← Zurück zur Konsole", notice: "Die Dokumentation ist auf Englisch verfasst.",
        menu: ["Überblick", "Schnellstart", "Konsolenrundgang", "Konzepte", "Geräteverwaltung", "Erkennungsregeln", "OT-Leitfaden", "Switches (SNMP)", "Alarmierung", "Branding", "Lizenzierung", "Export & SIEM", "Bereitstellung", "Docker", "Betrieb", "Aktualisierungen", "Sicherheit", "API", "Fehlerbehebung"],
    },
    Chrome {
        lang: "fr", documentation: "Documentation", back: "← Retour à la console", notice: "La documentation est rédigée en anglais.",
        menu: ["Vue d'ensemble", "Démarrage rapide", "Visite de la console", "Concepts", "Gestion des appareils", "Règles de détection", "Guide OT", "Commutateurs (SNMP)", "Alertes sortantes", "Personnalisation", "Licences", "Export & SIEM", "Déploiement", "Docker", "Exploitation", "Mises à jour", "Sécurité", "API", "Dépannage"],
    },
    Chrome {
        lang: "es", documentation: "Documentación", back: "← Volver a la consola", notice: "La documentación está escrita en inglés.",
        menu: ["Resumen", "Inicio rápido", "Recorrido por la consola", "Conceptos", "Gestión de dispositivos", "Reglas de detección", "Guía OT", "Conmutadores (SNMP)", "Alertas externas", "Marca", "Licencias", "Exportación y SIEM", "Despliegue", "Docker", "Operación", "Actualizaciones", "Seguridad", "API", "Solución de problemas"],
    },
    Chrome {
        lang: "sk", documentation: "Dokumentácia", back: "← Späť do konzoly", notice: "Dokumentácia je napísaná po anglicky.",
        menu: ["Prehľad", "Rýchly štart", "Prehliadka konzoly", "Pojmy", "Správa zariadení", "Detekčné pravidlá", "Sprievodca OT", "Switche (SNMP)", "Upozorňovanie", "Vzhľad", "Licencovanie", "Export a SIEM", "Nasadenie", "Docker", "Prevádzka", "Aktualizácie", "Bezpečnosť", "API", "Riešenie problémov"],
    },
];

/// Add `?lang=xx` to the links between documentation pages so the language stays chosen.
fn keep_language(html: &str, lang: &str) -> String {
    let mut out = String::with_capacity(html.len() + 256);
    let mut rest = html;
    while let Some(i) = rest.find("href=\"/docs/") {
        let (head, tail) = rest.split_at(i + 6);
        out.push_str(head);
        let end = tail.find('"').unwrap_or(tail.len());
        let (link, after) = tail.split_at(end);
        if link.starts_with("/docs/img/") || link.contains('?') {
            out.push_str(link);
        } else if let Some((path, anchor)) = link.split_once('#') {
            out.push_str(&format!("{path}?lang={lang}#{anchor}"));
        } else {
            out.push_str(&format!("{link}?lang={lang}"));
        }
        rest = after;
    }
    out.push_str(rest);
    out
}

/// GitHub-style heading anchor: lower case, punctuation dropped, spaces to `-`.
fn slug(text: &str) -> String {
    text.to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric() || matches!(c, ' ' | '-' | '_'))
        .map(|c| if c == ' ' { '-' } else { c })
        .collect()
}

/// `other-page.md#part` -> `/docs/other-page#part` (relative Markdown links only).
fn rewrite_link(dest: &str) -> String {
    let scheme = dest.split(['/', '#', '?']).next().unwrap_or("").split_once(':').map(|(s, _)| s.to_ascii_lowercase());
    match scheme.as_deref() {
        Some("http" | "https" | "mailto") => return dest.to_string(),
        Some(_) => return "#".to_string(), // javascript:, data:, … are never linked
        None => {}
    }
    if dest.starts_with('#') || dest.starts_with('/') {
        return dest.to_string();
    }
    let (file, frag) = dest.split_once('#').map_or((dest, ""), |(f, a)| (f, a));
    match file.strip_suffix(".md") {
        Some(stem) if PAGES.iter().any(|(id, _)| *id == stem) => {
            if frag.is_empty() { format!("/docs/{stem}") } else { format!("/docs/{stem}#{frag}") }
        }
        _ => dest.to_string(),
    }
}

/// A screenshot from `docs/img/`, by file name (`devices.png`). Only lower-case letters, digits
/// and `-` before `.png` are accepted, so no path can reach any other file.
pub fn image(file: &str) -> Option<Vec<u8>> {
    let stem = file.strip_suffix(".png")?;
    if stem.is_empty() || stem.len() > 60 || !stem.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
        return None;
    }
    DocFiles::get(&format!("img/{file}")).map(|f| f.data.into_owned())
}

/// Markdown image destinations: only our own `img/<name>.png` screenshots. Anything else
/// (an external picture would leak the reader's address) is dropped.
fn rewrite_image(dest: &str) -> String {
    match dest.strip_prefix("img/") {
        Some(f) if image_name_ok(f) => format!("/docs/img/{f}"),
        _ => String::new(),
    }
}

fn image_name_ok(f: &str) -> bool {
    f.strip_suffix(".png").is_some_and(|s| !s.is_empty() && s.len() <= 60 && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'))
}

/// Render Markdown to an HTML fragment.
pub fn render_markdown(md: &str) -> String {
    let opts = Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH;
    let mut events: Vec<Event> = Vec::new();
    let mut heading: Option<(HeadingLevel, Vec<Event>, String)> = None;
    for ev in Parser::new_ext(md, opts) {
        let ev = match ev {
            // never pass raw HTML through
            Event::Html(s) | Event::InlineHtml(s) => Event::Text(s),
            Event::Start(Tag::Link { link_type, dest_url, title, id }) => {
                Event::Start(Tag::Link { link_type, dest_url: CowStr::from(rewrite_link(&dest_url)), title, id })
            }
            Event::Start(Tag::Image { link_type, dest_url, title, id }) => {
                Event::Start(Tag::Image { link_type, dest_url: CowStr::from(rewrite_image(&dest_url)), title, id })
            }
            other => other,
        };
        match (&mut heading, ev) {
            (None, Event::Start(Tag::Heading { level, .. })) => heading = Some((level, Vec::new(), String::new())),
            (Some((level, inner, text)), Event::End(TagEnd::Heading(_))) => {
                let id = slug(text);
                let (level, inner) = (*level, std::mem::take(inner));
                heading = None;
                events.push(Event::Html(CowStr::from(format!("<{level} id=\"{id}\">"))));
                events.extend(inner);
                events.push(Event::Html(CowStr::from(format!("</{level}>\n"))));
            }
            (Some((_, inner, text)), ev) => {
                if let Event::Text(t) | Event::Code(t) = &ev {
                    text.push_str(t);
                }
                inner.push(ev);
            }
            (None, ev) => events.push(ev),
        }
    }
    let mut out = String::new();
    html::push_html(&mut out, events.into_iter());
    out
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

const CSS: &str = "\
:root{--bg:#f7f8fa;--panel:#fff;--text:#1b1f24;--muted:#6a737d;--line:#e3e6ea;--accent:#2563eb;--code:#eef1f5}\
@media(prefers-color-scheme:dark){:root{--bg:#0f1216;--panel:#171b21;--text:#e6e9ed;--muted:#8b95a1;--line:#262c34;--accent:#6ea0ff;--code:#1f252d}}\
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 system-ui,-apple-system,sans-serif}\
header{display:flex;align-items:center;gap:16px;padding:10px 20px;background:var(--panel);border-bottom:1px solid var(--line)}\
header a{color:var(--accent);text-decoration:none}header b{font-size:16px}\
.wrap{display:flex;gap:28px;max-width:1150px;margin:0 auto;padding:20px}\
nav{flex:0 0 190px;position:sticky;top:16px;align-self:flex-start}nav a{display:block;padding:5px 10px;border-radius:6px;color:var(--text);text-decoration:none}\
nav a:hover{background:var(--code)}nav a.cur{background:var(--accent);color:#fff}\
main{flex:1;min-width:0;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:8px 28px 28px}\
h1,h2,h3{line-height:1.25}h2{border-bottom:1px solid var(--line);padding-bottom:4px;margin-top:1.8em}\
a{color:var(--accent)}code{background:var(--code);padding:1px 5px;border-radius:4px;font-size:13px}\
img{max-width:100%;height:auto;border:1px solid var(--line);border-radius:8px;margin:8px 0}pre{background:var(--code);padding:12px 14px;border-radius:8px;overflow-x:auto}pre code{padding:0;background:none}\
table{border-collapse:collapse;display:block;overflow-x:auto}th,td{border:1px solid var(--line);padding:6px 10px;text-align:left;vertical-align:top}\
th{background:var(--code)}blockquote{margin:0;padding:0 14px;border-left:3px solid var(--line);color:var(--muted)}\
@media(max-width:760px){.wrap{flex-direction:column;padding:10px}nav{position:static;flex:none;display:flex;flex-wrap:wrap}main{padding:4px 16px 20px}}";

/// A complete documentation page, or `None` for an unknown page name.
pub fn page(id: &str, brand: &Branding, lang: Option<&str>) -> Option<String> {
    let (index, (_, title)) = PAGES.iter().enumerate().find(|(_, (p, _))| *p == id)?;
    // the language asked for, else the administrator's default; English when neither is a translated one
    let lang = lang.filter(|l| branding::LANGUAGES.contains(l)).unwrap_or(&brand.default_language);
    let chrome = CHROME.iter().find(|c| c.lang == lang);
    let file = DocFiles::get(&format!("{id}.md"))?;
    let mut body = render_markdown(&String::from_utf8_lossy(&file.data));
    if chrome.is_some() {
        body = keep_language(&body, lang);
    }
    let title = chrome.map_or(*title, |c| c.menu[index]);
    let accent = brand
        .accent
        .as_deref()
        .and_then(branding::valid_color)
        .map(|c| format!(":root{{--accent:{c}}}"))
        .unwrap_or_default();
    let nav: String = PAGES
        .iter()
        .enumerate()
        .map(|(i, (p, t))| {
            let (label, query) = chrome.map_or((*t, String::new()), |c| (c.menu[i], format!("?lang={lang}")));
            format!("<a href=\"/docs/{p}{query}\"{}>{}</a>", if *p == id { " class=\"cur\"" } else { "" }, esc(label))
        })
        .collect();
    let (documentation, back, notice) = chrome.map_or(("Documentation", "← Back to the console", ""), |c| (c.documentation, c.back, c.notice));
    let notice = if notice.is_empty() { String::new() } else { format!("<p class=\"muted\">{}</p>", esc(notice)) };
    Some(format!(
        "<!doctype html><html lang=\"{lang}\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>{} · {}</title><style>{CSS}{accent}</style></head><body>\
         <header><b>{}</b><span>{documentation}</span><span style=\"flex:1\"></span><a href=\"/\">{back}</a></header>\
         <div class=\"wrap\"><nav>{nav}</nav><main>{notice}{body}</main></div></body></html>",
        esc(title),
        esc(&brand.product_name),
        esc(&brand.product_name),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_page_in_the_menu_exists_and_every_doc_file_is_in_the_menu() {
        for (id, _) in PAGES {
            let h = page(id, &Branding::default(), None).unwrap_or_else(|| panic!("missing docs/{id}.md"));
            assert!(h.contains("<h1 id="), "{id} has a title");
        }
        for f in DocFiles::iter().filter(|f| f.ends_with(".md")) {
            let stem = f.trim_end_matches(".md");
            assert!(PAGES.iter().any(|(p, _)| *p == stem), "docs/{f} is not in the menu");
        }
        assert!(page("../secret", &Branding::default(), None).is_none());
        assert!(page("nope", &Branding::default(), None).is_none());
    }

    #[test]
    fn markdown_links_between_pages_and_anchors_work() {
        let h = render_markdown("See [concepts](concepts.md#visibility-what-can-be-seen-from-where) and [x](https://example.com) and [y](#local).\n\n## Findings: standing problems, with a fix\n");
        assert!(h.contains("href=\"/docs/concepts#visibility-what-can-be-seen-from-where\""), "{h}");
        assert!(h.contains("href=\"https://example.com\"") && h.contains("href=\"#local\""));
        assert!(h.contains("<h2 id=\"findings-standing-problems-with-a-fix\">"), "{h}");
        // every internal link in the real docs points at a real page and, if given, a real heading
        for (id, _) in PAGES {
            let md = String::from_utf8_lossy(&DocFiles::get(&format!("{id}.md")).unwrap().data).to_string();
            for cap in md.split("](").skip(1) {
                let dest = cap.split(')').next().unwrap();
                let Some((file, frag)) = dest.split_once('#').map(|(f, a)| (f, Some(a))).or(Some((dest, None))) else { continue };
                if !file.ends_with(".md") {
                    continue;
                }
                let target = file.trim_end_matches(".md");
                assert!(PAGES.iter().any(|(p, _)| *p == target), "{id}: link to unknown page {file}");
                if let Some(a) = frag {
                    let tmd = String::from_utf8_lossy(&DocFiles::get(&format!("{target}.md")).unwrap().data).to_string();
                    let th = render_markdown(&tmd);
                    assert!(th.contains(&format!("id=\"{a}\"")), "{id}: link {dest} has no such heading");
                }
            }
        }
    }

    #[test]
    fn every_screenshot_a_page_shows_exists_and_only_our_own_images_can_be_shown() {
        for (id, _) in PAGES {
            let md = String::from_utf8_lossy(&DocFiles::get(&format!("{id}.md")).unwrap().data).to_string();
            for part in md.split("![").skip(1) {
                let dest = part.split("](").nth(1).unwrap().split(')').next().unwrap();
                let file = dest.strip_prefix("img/").unwrap_or_else(|| panic!("{id}: image {dest} is not under img/"));
                assert!(image(file).is_some(), "{id}: missing docs/img/{file} (run tools/screenshots.py)");
            }
        }
        // an external or odd image address is dropped, not fetched
        for bad in ["https://evil.example/x.png", "img/../secret.png", "img/x.svg", "/etc/passwd", "img/A.png", "data:image/png;base64,AAAA"] {
            let h = render_markdown(&format!("![x]({bad})"));
            assert!(!h.contains("evil.example") && !h.contains("passwd") && !h.contains("data:") && !h.contains("secret") && !h.contains(".svg"), "{bad}: {h}");
        }
        assert!(image("../Cargo.toml").is_none() && image("a.png/../b.png").is_none() && image("nope.png").is_none());
    }

    #[test]
    fn raw_html_and_script_in_markdown_is_escaped() {
        let h = render_markdown("<script>alert(1)</script>\n\nhi <img src=x onerror=alert(1)> there\n\n[a](javascript:alert(1))");
        assert!(!h.contains("<script>") && !h.contains("<img"), "{h}");
        assert!(h.contains("&lt;script&gt;"));
    }

    #[test]
    fn the_brand_name_and_accent_are_escaped_and_validated() {
        let b = Branding { product_name: "<b>X</b>".into(), accent: Some("red;}</style><script>".into()), ..Default::default() };
        let h = page("index", &b, None).unwrap();
        assert!(!h.contains("<b>X</b>") && h.contains("&lt;b&gt;X"));
        assert!(!h.contains("</style><script>"), "a hostile accent value is dropped");
    }

    #[test]
    fn the_menu_follows_the_language_and_links_keep_it() {
        let b = Branding::default();
        // English by default; a translated language changes the words around the page, not the page
        let en = page("index", &b, None).unwrap();
        assert!(en.contains(">Quick start<") && !en.contains("?lang="));
        let de = page("index", &b, Some("de")).unwrap();
        assert!(de.contains(">Schnellstart<") && de.contains("<html lang=\"de\"") && de.contains("/docs/quickstart?lang=de\""));
        assert!(de.contains("Die Dokumentation ist auf Englisch verfasst."));
        // links inside the pages keep the language, including their anchors; images are left alone
        assert!(keep_language("<a href=\"/docs/tour#x\">t</a><img src=\"/docs/img/a.png\"><a href=\"/docs/api\">", "sk")
            == "<a href=\"/docs/tour?lang=sk#x\">t</a><img src=\"/docs/img/a.png\"><a href=\"/docs/api?lang=sk\">");
        // an unknown language falls back to the administrator's default, and every language has a full menu
        assert!(page("index", &b, Some("xx")).unwrap().contains(">Quick start<"));
        let sk = Branding { default_language: "sk".into(), ..Default::default() };
        assert!(page("index", &sk, None).unwrap().contains(">Rýchly štart<"));
        assert!(CHROME.iter().all(|c| c.menu.iter().all(|m| !m.is_empty())));
    }
}
