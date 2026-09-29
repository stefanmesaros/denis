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
    /// Recommended actions (`recommend_actions` below): a short advisory list of next steps for
    /// one alert, on click. Independent of the other two — DENIS never acts on this list itself.
    #[serde(default)]
    pub recommended_actions: bool,
    /// The dashboard's AI summary (see `ai_summary.rs`): unlike the three above, this is never
    /// generated on click — a background job regenerates it on its own schedule when recent alert
    /// activity moves on, and the dashboard only ever reads what is already stored (AI.md section
    /// 6 calls this a hard requirement). Off means the background job makes zero API calls, same
    /// as `AiConfig.enabled` off.
    #[serde(default)]
    pub dashboard_summary: bool,
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

/// `http_status_as_error` (ureq's own default) turns a non-2xx response into a bare
/// `Error::StatusCode(code)` with the body already discarded — so a provider's actual reason (bad
/// model name, over quota, malformed request) never reached an administrator, who saw only a
/// generic "answered with an error" and, once that crossed this app's own `BAD_GATEWAY` wrapping,
/// nothing at all. Disabled here so a non-2xx response is read like any other: the status is
/// checked explicitly and the provider's own error body (most of them return `{"error": {...}}` or
/// similar) is surfaced instead of being thrown away.
fn call_ureq_json(url: &str, headers: &[(&str, String)], body: &serde_json::Value) -> Result<serde_json::Value> {
    let agent: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(std::time::Duration::from_secs(30))).http_status_as_error(false).build().into();
    let mut req = agent.post(url).header("Content-Type", "application/json");
    for (k, v) in headers {
        req = req.header(*k, v);
    }
    let mut resp = req.send_json(body.clone()).map_err(|e| anyhow!("the provider could not be reached: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.body_mut().read_to_string().unwrap_or_default();
        return Err(anyhow!("the provider answered with {status}: {}", if text.is_empty() { "(no body)" } else { text.trim() }));
    }
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

/// `token_param`: the request field that caps the reply length — `"max_tokens"` for most
/// OpenAI-compatible APIs (x.ai's included), but OpenAI's own newer reasoning-family models
/// (`gpt-5-mini` among them) reject that name outright ("Unsupported parameter: 'max_tokens' is
/// not supported with this model. Use 'max_completion_tokens' instead.") and require
/// `"max_completion_tokens"` — found live, via a real 400 from OpenAI once `call_ureq_json`
/// started surfacing a non-2xx response's own body instead of discarding it.
fn openai_style(url: &str, key: &str, model: &str, token_param: &str, system: &str, prompt: &str) -> Result<String> {
    let mut body = json!({
        "model": model,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
    });
    body[token_param] = json!(500);
    let v = call_ureq_json(url, &[("Authorization", format!("Bearer {key}"))], &body)?;
    v["choices"][0]["message"]["content"].as_str().map(str::to_string).ok_or_else(|| anyhow!("no answer in the response: {v}"))
}

/// `gemini-2.5-flash` is no longer available to new API keys as of this writing ("This model ...
/// is no longer available to new users" - a real 404 seen live from a fresh key); Google's own
/// error names `gemini-3.8-flash` as its replacement.
fn gemini(key: &str, system: &str, prompt: &str) -> Result<String> {
    let url = format!("https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent?key={key}");
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
        "openai" => openai_style("https://api.openai.com/v1/chat/completions", key, "gpt-5-mini", "max_completion_tokens", system, prompt)?,
        "gemini" => gemini(key, system, prompt)?,
        "grok" => openai_style("https://api.x.ai/v1/chat/completions", key, "grok-4-fast", "max_tokens", system, prompt)?,
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

/// Recommended actions' own system prompt (spec section 15): distinct from triage's single
/// `recommended_action` sentence — a short, concrete list for someone about to actually go
/// investigate, not a one-line hint. Advisory only: nothing in this codebase ever acts on this
/// list itself (spec: "do not automatically execute network changes").
const RECOMMEND_SYSTEM_PROMPT: &str = "You are suggesting concrete next steps for a network administrator \
investigating one security alert from DENIS, a network monitoring tool. You are given the alert's own summary, \
its scored reasons, and the device it concerns — nothing else about their network. Reply with exactly one JSON \
object and nothing else (no markdown fencing, no commentary before or after): {\"actions\": [\"...\", ...]}, \
2 to 5 short, concrete, advisory steps (e.g. \"check the device's DNS history\", \"compare with similar devices\", \
\"consider isolating the device\") - never a command DENIS itself could execute, never a claim that anything was \
already done. Do not invent facts not given to you.";

/// Advisory next steps for one significant alert (spec section 15) — a short list, not DENIS
/// acting on anything itself. Distinct from `TriageResult.recommended_action` (one sentence,
/// bundled with an assessment); this is its own capability, its own toggle, a slightly deeper list
/// for someone about to actually go investigate.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RecommendedActions {
    pub actions: Vec<String>,
    pub generated_at: i64,
}

/// Bounds on `actions`: fewer than 2 is not really "a list", more than a handful stops being
/// concise advice and starts being noise nobody will actually read - both symptoms of a provider
/// not really following the prompt, worth surfacing as a real answer either way rather than
/// silently truncating or padding.
const MIN_ACTIONS: usize = 1;
const MAX_ACTIONS: usize = 8;

/// Ask one provider for recommended actions on `prompt`, returning DENIS's own validated list.
pub fn recommend_actions(cfg: &AiConfig, provider: &str, prompt: &str, now: i64) -> Result<RecommendedActions> {
    let text = ask(cfg, provider, RECOMMEND_SYSTEM_PROMPT, prompt)?;
    parse_recommended_actions(&text, now)
}

/// Extracts and validates a `RecommendedActions` from a provider's raw text — same "find the first
/// `{...}` span" tolerance as `parse_triage`, for the same reason. An empty, missing, or
/// wildly-oversized list fails rather than being silently coerced into something usable, since
/// either is more likely a provider that ignored the prompt than legitimate advice.
fn parse_recommended_actions(text: &str, now: i64) -> Result<RecommendedActions> {
    let start = text.find('{').ok_or_else(|| anyhow!("no JSON object in the response: {text}"))?;
    let end = text.rfind('}').ok_or_else(|| anyhow!("no JSON object in the response: {text}"))?;
    if end < start {
        return Err(anyhow!("no JSON object in the response: {text}"));
    }
    let v: serde_json::Value = serde_json::from_str(&text[start..=end]).map_err(|e| anyhow!("the response was not valid JSON: {e}"))?;
    let actions: Vec<String> = v["actions"]
        .as_array()
        .ok_or_else(|| anyhow!("the response's \"actions\" was missing or not a list: {v}"))?
        .iter()
        .filter_map(|a| a.as_str())
        .map(|a| a.trim().to_string())
        .filter(|a| !a.is_empty())
        .take(MAX_ACTIONS)
        .collect();
    if actions.len() < MIN_ACTIONS {
        return Err(anyhow!("the response gave no usable actions: {v}"));
    }
    Ok(RecommendedActions { actions, generated_at: now })
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

/// The dashboard summary's own system prompt (AI.md section 5): a short overview, not a chat, and
/// never a restatement of the raw counts already visible on the dashboard around it.
const SUMMARY_SYSTEM_PROMPT: &str = "You are writing a short \"AI Security Summary\" card for the dashboard of DENIS, \
a network monitoring tool, summarizing roughly the last 24 hours of alert activity for a network administrator. \
You are given alert counts by severity and a handful of the most significant individual alerts (their type, \
severity, score, device and summary) — nothing else about their network. In 2-5 short sentences: describe the \
overall state (calm, or not), name the most significant change if there is one, and note anything that plausibly \
deserves a look. Do not turn this into a chatbot reply or a bullet-point restatement of the counts already shown \
elsewhere on the dashboard. Do not invent facts not given to you; if nothing significant happened, say so plainly \
and briefly.";

/// Ask one provider to write the dashboard summary for `prompt` (already built by
/// `dashboard_summary_prompt`). Free-form prose, same shape as `explain`.
pub fn summarize(cfg: &AiConfig, provider: &str, prompt: &str) -> Result<String> {
    ask(cfg, provider, SUMMARY_SYSTEM_PROMPT, prompt)
}

/// One alert named individually in the summary prompt, most-significant-first.
pub struct SummaryHighlight {
    pub kind: String,
    pub severity: String,
    pub score: i32,
    pub device_label: String,
    pub summary: String,
}

/// The prompt for the dashboard summary: severity counts over the window plus the highest-scored
/// individual alerts within it — never the raw alert stream, and never more than
/// `highlights.len()` alerts named individually (the caller decides how many; see `ai_summary.rs`).
pub fn dashboard_summary_prompt(window_hours: i64, by_severity: &[(&str, i64)], highlights: &[SummaryHighlight]) -> String {
    let counts = by_severity.iter().filter(|(_, n)| *n > 0).map(|(sev, n)| format!("{n} {sev}")).collect::<Vec<_>>().join(", ");
    let mut out = format!("Alert activity over the last {window_hours} hours: {}.\n", if counts.is_empty() { "none".to_string() } else { counts });
    if highlights.is_empty() {
        out.push_str("No individual alerts stand out enough to name.");
    } else {
        out.push_str("The most significant individual alerts:\n");
        for h in highlights {
            out.push_str(&format!("- [{}, score {}] {} on {}: {}\n", h.severity, h.score, h.kind, h.device_label, h.summary));
        }
    }
    out
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

    #[test]
    fn a_clean_recommended_actions_response_parses_exactly() {
        let r = parse_recommended_actions(r#"{"actions": ["Check the device's DNS history", "Compare with similar devices"]}"#, 1000).unwrap();
        assert_eq!(r, RecommendedActions { actions: vec!["Check the device's DNS history".into(), "Compare with similar devices".into()], generated_at: 1000 });
    }

    #[test]
    fn recommended_actions_fencing_and_prose_are_tolerated() {
        let text = "Here you go:\n```json\n{\"actions\": [\"Investigate the destination\"]}\n```\nHope that helps.";
        let r = parse_recommended_actions(text, 1000).unwrap();
        assert_eq!(r.actions, vec!["Investigate the destination".to_string()]);
    }

    #[test]
    fn an_empty_or_missing_actions_list_is_a_hard_error() {
        assert!(parse_recommended_actions(r#"{"actions": []}"#, 1000).is_err());
        assert!(parse_recommended_actions(r#"{"actions": ["", "  "]}"#, 1000).is_err(), "blank-only entries are not usable actions");
        assert!(parse_recommended_actions(r#"{}"#, 1000).is_err(), "missing actions entirely");
        assert!(parse_recommended_actions("not json at all", 1000).is_err());
    }

    #[test]
    fn an_oversized_actions_list_is_capped_not_rejected() {
        let many: Vec<String> = (0..20).map(|i| format!("\"step {i}\"")).collect();
        let text = format!(r#"{{"actions": [{}]}}"#, many.join(","));
        let r = parse_recommended_actions(&text, 1000).unwrap();
        assert_eq!(r.actions.len(), MAX_ACTIONS);
    }

    #[test]
    fn recommend_actions_needs_a_key_same_as_explain() {
        let cfg = AiConfig::default();
        assert!(recommend_actions(&cfg, "claude", "x", 1000).is_err());
    }

    #[test]
    fn summary_needs_a_key_same_as_explain() {
        let cfg = AiConfig::default();
        assert!(summarize(&cfg, "claude", "x").is_err());
    }

    #[test]
    fn the_summary_prompt_includes_counts_and_only_the_highlights_it_was_given() {
        let h = [SummaryHighlight { kind: "new_destination".into(), severity: "medium".into(), score: 55, device_label: "Camera Kitchen (10.0.10.5)".into(), summary: "First contact with 3.113.81.30".into() }];
        let p = dashboard_summary_prompt(24, &[("high", 0), ("medium", 1), ("low", 4)], &h);
        assert!(p.contains("1 medium") && p.contains("4 low") && !p.contains("0 high"), "{p}");
        assert!(p.contains("Camera Kitchen") && p.contains("First contact with 3.113.81.30"), "{p}");
    }

    #[test]
    fn an_empty_window_says_so_plainly_rather_than_an_empty_list() {
        let p = dashboard_summary_prompt(24, &[("high", 0), ("medium", 0), ("low", 0)], &[]);
        assert!(p.contains("none"), "{p}");
        assert!(p.contains("No individual alerts"), "{p}");
    }
}
