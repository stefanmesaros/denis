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

/// One API key per provider an administrator has set up, and which one the "Explain" button
/// uses by default. Keys are never sent back to the browser once saved (see `web_ai::Redacted`).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct AiConfig {
    #[serde(default)]
    pub keys: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub default_provider: String,
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

pub fn load(store: &dyn SettingsStore) -> Result<AiConfig> {
    Ok(store.get_setting(KEY)?.and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default())
}

pub fn save(store: &dyn SettingsStore, c: &AiConfig, now: i64) -> Result<()> {
    store.set_setting(KEY, &serde_json::to_vec(c)?, now)
}

const SYSTEM_PROMPT: &str = "You are helping a network administrator understand one security alert from DENIS, a \
network monitoring tool. You are given the alert's own summary, its scored reasons, and the device it concerns — \
nothing else about their network. In 3-6 short sentences: explain in plain language why this likely fired, how \
serious it really is in context, and what to check or do next. Do not invent facts not given to you; say plainly \
when you are not sure. Do not repeat the input back verbatim.";

fn call_ureq_json(url: &str, headers: &[(&str, String)], body: &serde_json::Value) -> Result<serde_json::Value> {
    let agent: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(std::time::Duration::from_secs(30))).build().into();
    let mut req = agent.post(url).header("Content-Type", "application/json");
    for (k, v) in headers {
        req = req.header(*k, v);
    }
    let mut resp = req.send_json(body.clone()).map_err(|e| anyhow!("the provider could not be reached, or answered with an error: {e}"))?;
    resp.body_mut().read_json::<serde_json::Value>().map_err(|e| anyhow!("the provider's answer was not valid JSON: {e}"))
}

fn claude(key: &str, prompt: &str) -> Result<String> {
    let body = json!({
        "model": "claude-haiku-4-5-20251001",
        "max_tokens": 500,
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": prompt}],
    });
    let v = call_ureq_json("https://api.anthropic.com/v1/messages", &[("x-api-key", key.to_string()), ("anthropic-version", "2023-06-01".to_string())], &body)?;
    v["content"][0]["text"].as_str().map(str::to_string).ok_or_else(|| anyhow!("no answer in the response: {v}"))
}

fn openai_style(url: &str, key: &str, model: &str, prompt: &str) -> Result<String> {
    let body = json!({
        "model": model,
        "messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt}],
        "max_tokens": 500,
    });
    let v = call_ureq_json(url, &[("Authorization", format!("Bearer {key}"))], &body)?;
    v["choices"][0]["message"]["content"].as_str().map(str::to_string).ok_or_else(|| anyhow!("no answer in the response: {v}"))
}

fn gemini(key: &str, prompt: &str) -> Result<String> {
    let url = format!("https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={key}");
    let body = json!({
        "system_instruction": {"parts": [{"text": SYSTEM_PROMPT}]},
        "contents": [{"parts": [{"text": prompt}]}],
    });
    let v = call_ureq_json(&url, &[], &body)?;
    v["candidates"][0]["content"]["parts"][0]["text"].as_str().map(str::to_string).ok_or_else(|| anyhow!("no answer in the response: {v}"))
}

/// Ask one provider to explain `prompt` (already built from an alert's or finding's own data).
pub fn explain(cfg: &AiConfig, provider: &str, prompt: &str) -> Result<String> {
    let key = cfg.key_for(provider).ok_or_else(|| anyhow!("no API key is set for {}", provider_name(provider)))?;
    let text = match provider {
        "claude" => claude(key, prompt)?,
        "openai" => openai_style("https://api.openai.com/v1/chat/completions", key, "gpt-5-mini", prompt)?,
        "gemini" => gemini(key, prompt)?,
        "grok" => openai_style("https://api.x.ai/v1/chat/completions", key, "grok-4-fast", prompt)?,
        other => return Err(anyhow!("unknown provider {other:?}")),
    };
    Ok(text.trim().to_string())
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
}
