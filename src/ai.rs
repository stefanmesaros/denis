//! "Explain with AI": an optional, opt-in, bring-your-own-key summary of one alert or finding in
//! plain language, from whichever provider an administrator has given a key for. Nothing here
//! runs on its own — it is called once, when someone clicks the button, never automatically, and
//! never on more than the one alert or finding they asked about.
//!
//! Deliberately out of scope: no DENIS-hosted or DENIS-paid-for API access. Every call is billed
//! to the administrator's own account with the provider they chose; if none is configured, the
//! button does not appear. This project does not want to run, fund or be liable for a shared AI
//! backend for every installation.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::store::SettingsStore;

pub const KEY: &str = "ai";

pub const PROVIDERS: &[&str] = &["claude", "openai", "gemini", "grok"];

pub fn provider_name(id: &str) -> &'static str {
    match id {
        "claude" => "Claude (Anthropic)",
        "openai" => "ChatGPT (OpenAI)",
        "gemini" => "Gemini (Google)",
        "grok" => "Grok (xAI)",
        _ => "AI",
    }
}

/// Individually-controllable AI capabilities (see AI.md's build order: shipped one at a time, a
/// field added here as each one lands). Every field defaults to `false` for a fresh install —
/// the administrator opts in per capability, never gets one silently turned on — except where
/// `load`'s own migration logic below preserves what an existing install already had.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct AiFeatures {
    /// "Explain with AI" on one alert or finding, on click — the only capability that exists so
    /// far (see `explain` below). Not the same thing as the global `AiConfig.enabled` switch: both
    /// must be on for the button to appear or the endpoint to answer.
    #[serde(default)]
    pub alert_explanations: bool,
    /// AI triage (`triage` below): an assessment alongside DENIS's own severity, on click, never
    /// a replacement for it. Independent of `alert_explanations` — either, both, or neither.
    #[serde(default)]
    pub alert_triage: bool,
}

/// One API key per provider an administrator has set up, and which one the "Explain" button
/// uses by default. Keys are never sent back to the browser once saved (see `web_ai::Redacted`).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct AiConfig {
    #[serde(default)]
    pub keys: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub default_provider: String,
    /// Global on/off switch (AI.md section 4): when `false`, no AI call is ever made for any
    /// capability, regardless of what `features` below says — checked first, everywhere this is
    /// checked at all.
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub features: AiFeatures,
}

impl AiConfig {
    /// Providers with a key set, in the fixed `PROVIDERS` order (stable for the UI).
    pub fn configured(&self) -> Vec<&'static str> {
        PROVIDERS.iter().copied().filter(|p| self.keys.get(*p).is_some_and(|k| !k.is_empty())).collect()
    }

    pub fn key_for(&self, provider: &str) -> Option<&str> {
        self.keys.get(provider).map(|s| s.as_str()).filter(|s| !s.is_empty())
    }
}

/// Loads the config, migrating a pre-`enabled`/`features` install (every one saved before this
/// pair of fields existed) so it keeps working exactly as it did: if a provider key was already
/// configured, alert explanation effectively already worked (there was no separate toggle for it),
/// so both the global switch and the alert-explanations feature default to *on* for that install —
/// never for a fresh one, which opts in explicitly. This only ever applies once: the check is
/// against the raw stored JSON literally lacking an `"enabled"` key, so a later, real save (which
/// always writes one, `true` or `false`) is respected exactly as saved from then on.
pub fn load(store: &dyn SettingsStore) -> Result<AiConfig> {
    let raw = store.get_setting(KEY)?;
    let mut cfg: AiConfig = raw.as_deref().and_then(|b| serde_json::from_slice(b).ok()).unwrap_or_default();
    let pre_migration = raw.as_deref().and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok()).is_some_and(|v| v.get("enabled").is_none());
    if pre_migration && !cfg.keys.is_empty() {
        cfg.enabled = true;
        cfg.features.alert_explanations = true;
    }
    Ok(cfg)
}

pub fn save(store: &dyn SettingsStore, c: &AiConfig, now: i64) -> Result<()> {
    store.set_setting(KEY, &serde_json::to_vec(c)?, now)
}

const SYSTEM_PROMPT: &str = "You are helping a network administrator understand one security alert from DENIS, a \
network monitoring tool. You are given the alert's own summary, its scored reasons, and the device it concerns — \
nothing else about their network. In 3-6 short sentences: explain in plain language why this likely fired, how \
serious it really is in context, and what to check or do next. Do not invent facts not given to you; say plainly \
when you are not sure. Do not repeat the input back verbatim.";

/// Triage's own system prompt: unlike `SYSTEM_PROMPT` (free-form prose), this must return exactly
/// one JSON object DENIS can safely parse and act on — see `TriageResult`/`parse_triage` below for
/// why `assessment` is validated against a fixed set rather than trusted as free text.
const TRIAGE_SYSTEM_PROMPT: &str = "You are triaging one security alert from DENIS, a network monitoring tool, for \
a network administrator. You are given the alert's own summary, its scored reasons, and the device it concerns — \
nothing else about their network. Reply with exactly one JSON object and nothing else (no markdown fencing, no \
commentary before or after): {\"assessment\": one of \"likely_benign\", \"suspicious\", \"requires_investigation\", \
\"confidence\": a number from 0 to 1, \"reasoning\": 1-3 short sentences, \"recommended_action\": one short \
sentence of advisory next step}. This is an additional signal alongside DENIS's own severity score, never a \
replacement for it - do not claim to change or override anything. Do not invent facts not given to you.";

fn call_ureq_json(url: &str, headers: &[(&str, String)], body: &serde_json::Value) -> Result<serde_json::Value> {
    let agent: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(std::time::Duration::from_secs(30))).build().into();
    let mut req = agent.post(url).header("Content-Type", "application/json");
    for (k, v) in headers {
        req = req.header(*k, v);
    }
    let mut resp = req.send_json(body.clone()).map_err(|e| anyhow!("the provider could not be reached, or answered with an error: {e}"))?;
    resp.body_mut().read_json::<serde_json::Value>().map_err(|e| anyhow!("the provider's answer was not valid JSON: {e}"))
}

fn claude(key: &str, system: &str, prompt: &str) -> Result<String> {
    let body = json!({
        "model": "claude-haiku-4-5-20251001",
        "max_tokens": 500,
        "system": system,
        "messages": [{"role": "user", "content": prompt}],
    });
    let v = call_ureq_json("https://api.anthropic.com/v1/messages", &[("x-api-key", key.to_string()), ("anthropic-version", "2023-06-01".to_string())], &body)?;
    v["content"][0]["text"].as_str().map(str::to_string).ok_or_else(|| anyhow!("no answer in the response: {v}"))
}

fn openai_style(url: &str, key: &str, model: &str, system: &str, prompt: &str) -> Result<String> {
    let body = json!({
        "model": model,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
        "max_tokens": 500,
    });
    let v = call_ureq_json(url, &[("Authorization", format!("Bearer {key}"))], &body)?;
    v["choices"][0]["message"]["content"].as_str().map(str::to_string).ok_or_else(|| anyhow!("no answer in the response: {v}"))
}

fn gemini(key: &str, system: &str, prompt: &str) -> Result<String> {
    let url = format!("https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={key}");
    let body = json!({
        "system_instruction": {"parts": [{"text": system}]},
        "contents": [{"parts": [{"text": prompt}]}],
    });
    let v = call_ureq_json(&url, &[], &body)?;
    v["candidates"][0]["content"]["parts"][0]["text"].as_str().map(str::to_string).ok_or_else(|| anyhow!("no answer in the response: {v}"))
}

/// Ask one provider `prompt`, under `system`'s instructions. Shared by `explain` (free-form prose)
/// and `triage` (must return parseable JSON) — the two differ only in which system prompt and
/// what they do with the text that comes back.
fn ask(cfg: &AiConfig, provider: &str, system: &str, prompt: &str) -> Result<String> {
    let key = cfg.key_for(provider).ok_or_else(|| anyhow!("no API key is set for {}", provider_name(provider)))?;
    let text = match provider {
        "claude" => claude(key, system, prompt)?,
        "openai" => openai_style("https://api.openai.com/v1/chat/completions", key, "gpt-5-mini", system, prompt)?,
        "gemini" => gemini(key, system, prompt)?,
        "grok" => openai_style("https://api.x.ai/v1/chat/completions", key, "grok-4-fast", system, prompt)?,
        other => return Err(anyhow!("unknown provider {other:?}")),
    };
    Ok(text.trim().to_string())
}

/// Ask one provider to explain `prompt` (already built from an alert's or finding's own data).
pub fn explain(cfg: &AiConfig, provider: &str, prompt: &str) -> Result<String> {
    ask(cfg, provider, SYSTEM_PROMPT, prompt)
}

/// The controlled set of triage assessments (spec section 12): never arbitrary text, so nothing
/// downstream can be driven by a value DENIS did not itself define. `Other` exists only so a
/// provider that returns something outside this set is a visible, reportable case, not silently
/// dropped or panicking - see `parse_triage`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Assessment {
    LikelyBenign,
    Suspicious,
    RequiresInvestigation,
}

impl Assessment {
    fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "likely_benign" => Some(Assessment::LikelyBenign),
            "suspicious" => Some(Assessment::Suspicious),
            "requires_investigation" => Some(Assessment::RequiresInvestigation),
            _ => None,
        }
    }
}

/// AI triage's structured answer (spec section 12) — an *additional* signal shown alongside
/// DENIS's own deterministic severity, never a replacement for it: nothing in this codebase ever
/// writes an `Assessment` back into an `Event`'s own `severity`/`score`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TriageResult {
    pub assessment: Assessment,
    /// Clamped to `[0, 1]` — a provider returning `1.4` or `-0.2` is a real thing to guard against,
    /// not hypothetical, given nothing about the response format is actually enforced on their end.
    pub confidence: f64,
    pub reasoning: String,
    pub recommended_action: String,
    pub generated_at: i64,
}

/// Ask one provider to triage `prompt`, returning DENIS's own validated structure — never the
/// provider's raw text. `now` is DENIS's own clock, not trusted from the model (see `TriageResult`
/// doc: `generated_at` records when *this* triage ran).
pub fn triage(cfg: &AiConfig, provider: &str, prompt: &str, now: i64) -> Result<TriageResult> {
    let text = ask(cfg, provider, TRIAGE_SYSTEM_PROMPT, prompt)?;
    parse_triage(&text, now)
}

/// Extracts and validates one `TriageResult` from a provider's raw text. Tolerant of the common
/// ways a model fails to follow "JSON only" (markdown code fences, leading/trailing prose around
/// the object) by finding the first `{...}` span rather than requiring the whole response to be
/// nothing else — but never tolerant of an `assessment` outside the fixed set: that always fails
/// rather than guessing, per spec ("a controlled set... rather than allowing arbitrary text to
/// drive application logic").
fn parse_triage(text: &str, now: i64) -> Result<TriageResult> {
    let start = text.find('{').ok_or_else(|| anyhow!("no JSON object in the response: {text}"))?;
    let end = text.rfind('}').ok_or_else(|| anyhow!("no JSON object in the response: {text}"))?;
    if end < start {
        return Err(anyhow!("no JSON object in the response: {text}"));
    }
    let v: serde_json::Value = serde_json::from_str(&text[start..=end]).map_err(|e| anyhow!("the response was not valid JSON: {e}"))?;
    let assessment = v["assessment"].as_str().and_then(Assessment::parse).ok_or_else(|| anyhow!("the response's \"assessment\" was missing or not one of the allowed values: {v}"))?;
    let confidence = v["confidence"].as_f64().unwrap_or(0.0).clamp(0.0, 1.0);
    let reasoning = v["reasoning"].as_str().unwrap_or_default().trim().to_string();
    let recommended_action = v["recommended_action"].as_str().unwrap_or_default().trim().to_string();
    Ok(TriageResult { assessment, confidence, reasoning, recommended_action, generated_at: now })
}

/// The prompt for one alert: exactly what the console already shows for it, nothing more.
pub fn alert_prompt(alert_type: &str, score: i32, severity: &str, summary: &str, reasons: &[String], device_label: &str) -> String {
    format!(
        "Alert type: {alert_type}\nSeverity: {severity} (score {score}/100)\nDevice: {device_label}\nSummary: {summary}\nScored reasons: {}",
        if reasons.is_empty() { "(none given)".to_string() } else { reasons.join("; ") }
    )
}

/// The prompt for one finding: its title, why it matters, and the fix already shown, plus how
/// many devices it currently affects (not their identities beyond a count).
pub fn finding_prompt(title: &str, why: &str, fix: &str, device_count: usize) -> String {
    format!("Standing finding: {title}\nWhy it matters (already known to the administrator): {why}\nSuggested fix (already known): {fix}\nAffects {device_count} device(s) right now.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_key_means_no_button_and_a_plain_refusal_to_call_out() {
        let cfg = AiConfig::default();
        assert!(cfg.configured().is_empty());
        assert!(explain(&cfg, "claude", "x").is_err());
    }

    #[test]
    fn configured_lists_only_providers_with_a_real_key_in_a_stable_order() {
        let mut cfg = AiConfig::default();
        cfg.keys.insert("grok".into(), "gk".into());
        cfg.keys.insert("claude".into(), "".into()); // blank: not configured
        cfg.keys.insert("openai".into(), "ok".into());
        assert_eq!(cfg.configured(), vec!["openai", "grok"]);
    }

    #[test]
    fn prompts_include_exactly_what_the_console_already_shows_and_nothing_invented() {
        let p = alert_prompt("new_port", 55, "medium", "First use of tcp/22", &["+40 first use".into(), "+15 risky port".into()], "Camera Kitchen (10.0.10.5)");
        assert!(p.contains("new_port") && p.contains("55") && p.contains("Camera Kitchen") && p.contains("+40 first use"));
        let f = finding_prompt("Telnet exposed", "unencrypted remote login", "disable Telnet, use SSH", 3);
        assert!(f.contains("Telnet exposed") && f.contains("3 device"));
    }

    #[test]
    fn a_clean_triage_response_parses_exactly() {
        let r = parse_triage(r#"{"assessment": "suspicious", "confidence": 0.7, "reasoning": "New external destination.", "recommended_action": "Check the device."}"#, 1000).unwrap();
        assert_eq!(r, TriageResult { assessment: Assessment::Suspicious, confidence: 0.7, reasoning: "New external destination.".into(), recommended_action: "Check the device.".into(), generated_at: 1000 });
    }

    #[test]
    fn markdown_fencing_and_surrounding_prose_are_tolerated() {
        let text = "Sure, here is my assessment:\n```json\n{\"assessment\": \"likely_benign\", \"confidence\": 0.9, \"reasoning\": \"r\", \"recommended_action\": \"a\"}\n```\nLet me know if you need more.";
        let r = parse_triage(text, 1000).unwrap();
        assert_eq!(r.assessment, Assessment::LikelyBenign);
    }

    #[test]
    fn an_assessment_outside_the_fixed_set_is_a_hard_error_never_guessed() {
        assert!(parse_triage(r#"{"assessment": "probably fine i guess", "confidence": 0.5, "reasoning": "r", "recommended_action": "a"}"#, 1000).is_err());
        assert!(parse_triage(r#"{"confidence": 0.5, "reasoning": "r", "recommended_action": "a"}"#, 1000).is_err(), "missing assessment entirely");
        assert!(parse_triage("not json at all", 1000).is_err());
    }

    #[test]
    fn confidence_is_clamped_to_zero_one_and_missing_defaults_to_zero() {
        let over = parse_triage(r#"{"assessment": "suspicious", "confidence": 1.4, "reasoning": "r", "recommended_action": "a"}"#, 1000).unwrap();
        assert_eq!(over.confidence, 1.0);
        let under = parse_triage(r#"{"assessment": "suspicious", "confidence": -0.2, "reasoning": "r", "recommended_action": "a"}"#, 1000).unwrap();
        assert_eq!(under.confidence, 0.0);
        let missing = parse_triage(r#"{"assessment": "suspicious", "reasoning": "r", "recommended_action": "a"}"#, 1000).unwrap();
        assert_eq!(missing.confidence, 0.0);
    }

    #[test]
    fn triage_needs_a_key_same_as_explain() {
        let cfg = AiConfig::default();
        assert!(triage(&cfg, "claude", "x", 1000).is_err());
    }
}
