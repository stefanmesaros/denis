//! White-label branding: the product name, accent colour, default theme, login
//! message and logo an operator (an MSP, say) shows their customers.
//!
//! Everything here is validated because it is rendered into pages seen by
//! other people: names are length-limited and stripped of control characters,
//! colours must be `#rrggbb`, and the logo must be a real raster image (checked
//! by its magic bytes, never by the client-supplied type). **SVG is refused**:
//! an SVG can carry script, and this file is served from the application's own
//! origin.

use serde::{Deserialize, Serialize};

use crate::store::{Store};

pub const KEY: &str = "branding";
pub const LOGO_KEY: &str = "branding.logo";
pub const LOGO_TYPE_KEY: &str = "branding.logo_type";
pub const MAX_LOGO_BYTES: usize = 256 * 1024;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Branding {
    pub product_name: String,
    /// `#rrggbb`; `None` = the built-in blue.
    pub accent: Option<String>,
    /// `auto`, `light` or `dark`: what a user who never chose sees.
    pub theme_default: String,
    /// Shown on the sign-in page.
    pub login_message: Option<String>,
    /// `en`, `de`, `fr`, `es` or `sk`: the interface language for people who never chose one.
    #[serde(default = "default_language")]
    pub default_language: String,
}

fn default_language() -> String {
    "en".into()
}

/// The interface languages the console is translated into.
pub const LANGUAGES: &[&str] = &["en", "de", "fr", "es", "sk"];

impl Default for Branding {
    fn default() -> Self {
        Branding { product_name: "DENIS".into(), accent: None, theme_default: "auto".into(), login_message: None, default_language: default_language() }
    }
}

/// `#rrggbb` (case-insensitive) -> normalised lower-case.
pub fn valid_color(s: &str) -> Option<String> {
    let b = s.as_bytes();
    (b.len() == 7 && b[0] == b'#' && b[1..].iter().all(u8::is_ascii_hexdigit)).then(|| s.to_ascii_lowercase())
}

/// Black or white text, whichever is more legible on `hex` (WCAG contrast).
pub fn text_on(hex: &str) -> &'static str {
    let ch = |i: usize| {
        let v = u8::from_str_radix(&hex[i..i + 2], 16).unwrap_or(0) as f64 / 255.0;
        if v <= 0.03928 { v / 12.92 } else { ((v + 0.055) / 1.055).powf(2.4) }
    };
    let l = 0.2126 * ch(1) + 0.7152 * ch(3) + 0.0722 * ch(5);
    // contrast with white = 1.05 / (l + .05); with near-black = (l + .05) / .05...: pick the larger
    if 1.05 / (l + 0.05) >= (l + 0.05) / 0.0525 { "#ffffff" } else { "#0b1220" }
}

fn clean(s: &str, max: usize) -> Result<Option<String>, String> {
    let t = s.trim();
    if t.chars().count() > max {
        return Err(format!("too long (max {max} characters)"));
    }
    if t.chars().any(char::is_control) {
        return Err("contains control characters".into());
    }
    Ok((!t.is_empty()).then(|| t.to_string()))
}

impl Branding {
    /// Apply a partial JSON update. Atomic: on error `self` is untouched.
    pub fn apply(&mut self, patch: &serde_json::Value) -> Result<(), String> {
        let obj = patch.as_object().ok_or("expected a JSON object")?;
        let mut next = self.clone();
        for (k, v) in obj {
            match k.as_str() {
                "product_name" => {
                    next.product_name = clean(v.as_str().ok_or("product_name must be a string")?, 40)?
                        .ok_or("product_name must not be empty")?;
                }
                "accent" => {
                    next.accent = match v {
                        serde_json::Value::Null => None,
                        serde_json::Value::String(s) if s.trim().is_empty() => None,
                        serde_json::Value::String(s) => Some(valid_color(s.trim()).ok_or("accent must look like #2563eb")?),
                        _ => return Err("accent must be a string or null".into()),
                    }
                }
                "theme_default" => {
                    let t = v.as_str().ok_or("theme_default must be a string")?;
                    if !["auto", "light", "dark"].contains(&t) {
                        return Err("theme_default must be auto, light or dark".into());
                    }
                    next.theme_default = t.to_string();
                }
                "login_message" => {
                    next.login_message = match v {
                        serde_json::Value::Null => None,
                        serde_json::Value::String(s) => clean(s, 300)?,
                        _ => return Err("login_message must be a string or null".into()),
                    }
                }
                "default_language" => {
                    let l = v.as_str().ok_or("default_language must be a string")?;
                    if !LANGUAGES.contains(&l) {
                        return Err(format!("default_language must be one of {}", LANGUAGES.join(", ")));
                    }
                    next.default_language = l.to_string();
                }
                other => return Err(format!("unknown field {other:?}")),
            }
        }
        *self = next;
        Ok(())
    }
}

pub fn load(store: &dyn Store) -> anyhow::Result<Branding> {
    Ok(store
        .get_setting(KEY)?
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default())
}

pub fn save(store: &dyn Store, b: &Branding, now: i64) -> anyhow::Result<()> {
    store.set_setting(KEY, &serde_json::to_vec(b)?, now)
}

/// The image type for `bytes`, judged only by their content. `None` for
/// anything that is not a PNG, JPEG, GIF or WebP (in particular SVG).
pub fn sniff_image(bytes: &[u8]) -> Option<&'static str> {
    match bytes {
        [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, ..] => Some("image/png"),
        [0xff, 0xd8, 0xff, ..] => Some("image/jpeg"),
        [b'G', b'I', b'F', b'8', b'7' | b'9', b'a', ..] => Some("image/gif"),
        [b'R', b'I', b'F', b'F', _, _, _, _, b'W', b'E', b'B', b'P', ..] => Some("image/webp"),
        _ => None,
    }
}

/// The stored logo, if any: `(content type, bytes, version)`.
pub fn load_logo(store: &dyn Store) -> anyhow::Result<Option<(&'static str, Vec<u8>)>> {
    let Some(bytes) = store.get_setting(LOGO_KEY)? else { return Ok(None) };
    // Re-verify on the way out: whatever is in the database, only a real
    // raster image is ever served.
    Ok(sniff_image(&bytes).map(|t| (t, bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::SettingsStore;
    use crate::store::sqlite::SqliteStore;
    use serde_json::json;

    #[test]
    fn colours_are_strictly_validated_and_text_contrast_is_chosen() {
        assert_eq!(valid_color("#2563EB").as_deref(), Some("#2563eb"));
        for bad in ["2563eb", "#2563e", "#2563ebf", "#25 3eb", "red", "#ggg000", "#2563eb;}", "url(x)", ""] {
            assert!(valid_color(bad).is_none(), "{bad:?}");
        }
        assert_eq!(text_on("#ffffff"), "#0b1220");
        assert_eq!(text_on("#000000"), "#ffffff");
        assert_eq!(text_on("#2563eb"), "#ffffff", "a mid blue takes white text");
        assert_eq!(text_on("#facc15"), "#0b1220", "yellow takes dark text");
    }

    #[test]
    fn branding_patches_are_validated_and_atomic() {
        let mut b = Branding::default();
        b.apply(&json!({"product_name": " Acme Guard ", "accent": "#DC2626", "theme_default": "dark", "login_message": "Welcome"})).unwrap();
        assert_eq!((b.product_name.as_str(), b.accent.as_deref(), b.theme_default.as_str(), b.login_message.as_deref()), ("Acme Guard", Some("#dc2626"), "dark", Some("Welcome")));
        let before = b.clone();
        for bad in [
            json!({"product_name": "ok", "accent": "javascript:alert(1)"}),
            json!({"product_name": ""}),
            json!({"product_name": "x".repeat(41)}),
            json!({"product_name": "a\u{7}b"}),
            json!({"theme_default": "neon"}),
            json!({"login_message": "x".repeat(301)}),
            json!({"logo": "x"}),
            json!(["not", "an", "object"]),
        ] {
            assert!(b.apply(&bad).is_err(), "{bad}");
            assert_eq!(b, before, "nothing applied on error: {bad}");
        }
        b.apply(&json!({"accent": null, "login_message": ""})).unwrap();
        assert_eq!((b.accent, b.login_message), (None, None));
    }

    #[test]
    fn only_real_raster_images_are_accepted_and_svg_never() {
        let png = [&[0x89u8, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a][..], &[0; 20]].concat();
        assert_eq!(sniff_image(&png), Some("image/png"));
        assert_eq!(sniff_image(&[0xff, 0xd8, 0xff, 0xe0, 0, 0]), Some("image/jpeg"));
        assert_eq!(sniff_image(b"GIF89a\x01\x00"), Some("image/gif"));
        assert_eq!(sniff_image(b"RIFF\x10\x00\x00\x00WEBPVP8 "), Some("image/webp"));
        for hostile in [
            &b"<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'/>"[..],
            b"<?xml version='1.0'?><svg/>",
            b"<html><script>alert(1)</script></html>",
            b"GIF89",            // truncated magic
            b"RIFF\x10\x00\x00\x00WAVEfmt ", // RIFF but not WebP
            b"\x89PNG",          // truncated
            b"",
        ] {
            assert_eq!(sniff_image(hostile), None, "{hostile:?}");
        }
        // a script hidden behind a valid PNG header is still just an image to a browser, and is
        // served with nosniff; the point here is that the *type* comes from the bytes alone
        assert_eq!(sniff_image(&[&png[..], b"<script>alert(1)</script>"].concat()), Some("image/png"));
    }

    #[test]
    fn branding_and_logo_persist_and_bad_stored_data_falls_back_safely() {
        let s = SqliteStore::open_in_memory().unwrap();
        assert_eq!(load(&s).unwrap(), Branding::default());
        let mut b = Branding::default();
        b.apply(&json!({"product_name": "Acme"})).unwrap();
        save(&s, &b, 1).unwrap();
        assert_eq!(load(&s).unwrap().product_name, "Acme");
        // corrupted JSON in the database must not break the sign-in page
        s.set_setting(KEY, b"{not json", 2).unwrap();
        assert_eq!(load(&s).unwrap(), Branding::default());
        // a non-image stored under the logo key is never served
        s.set_setting(LOGO_KEY, b"<svg onload=alert(1)>", 3).unwrap();
        assert!(load_logo(&s).unwrap().is_none());
        let png = [&[0x89u8, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a][..], &[1; 8]].concat();
        s.set_setting(LOGO_KEY, &png, 4).unwrap();
        assert_eq!(load_logo(&s).unwrap().unwrap().0, "image/png");
    }
}
