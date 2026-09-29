# AI security assistant: the spec, not yet built

This is the full specification for the "AI security assistant" roadmap item (see ROADMAP.md),
received verbatim from the person directing this project on 2026-09-29. Nothing here is built yet
— it is recorded in full so the detail survives past this conversation, the same reason IPV6.md/
WINDOWS.md/SSO.md/CMDB.md exist as dedicated scoping docs rather than folding everything into
ROADMAP.md's own necessarily-brief entries.

When this item is picked up: read this document first, then follow its own instruction in
section 26 — inspect the existing AI integration, Settings architecture, alert/event persistence,
dashboard architecture, background workers and configuration persistence *before* changing code,
and extend existing DENIS components rather than building parallel infrastructure where one
already fits.

## Status

1. **Settings → AI page** — done (2026-09-29). `AiConfig` gained `enabled: bool` (the global
   switch) and `features: AiFeatures` (one field so far: `alert_explanations`), both enforced
   server-side in `web_ai.rs::explain` (not just hidden client-side) and in `status` (the button's
   own visibility). A real migration question came up building this: an install that already had a
   provider key configured before these fields existed had no separate toggle — alert explanation
   just worked whenever a key was set. `ai::load` now infers `enabled = true` for exactly that case
   (the stored JSON literally predates the `"enabled"` key, and a key is already configured), so
   upgrading never silently turns off something that already worked; a fresh install still defaults
   fully off, and any explicit save from then on is respected as saved, never second-guessed.
2. **Alert explanations** — done, as part of step 1 above (moving its toggle in, not building it
   new; the feature itself is unchanged).
3-11: not started.

## Build order (explicit instruction, 2026-09-29)

Ship this feature-by-feature, not as one large change: **a minor version release after each step**,
so that if work stops partway through, everything already released stays genuinely usable rather
than sitting half-wired. In this order:

1. **Settings → AI page**: move the existing AI provider/API configuration here first (section 3
   below), before adding any new capability — this is the foundation every capability's own toggle
   sits on, per section 4's global on/off control.
2. **Alert explanations** — already exists (`src/ai.rs`/`src/web_ai.rs`); this step is moving its
   toggle into the new Settings → AI page and confirming it still works, not building it new.
3. **Alert triage** (section 12).
4. **Recommended actions** (section 15).
5. **Dashboard AI summary** (sections 5-10: the stale/debounce/versioning/caching machinery is the
   real work here, not just a card on the dashboard — see the hard requirement in section 6).
6. **Ask DENIS** (natural-language investigation, section 16).
7. **Security reports** (weekly summary, section 19).
8. **Incident correlation** (section 13).
9. **Device behavioral analysis** (section 14).
10. **AI threat hunting** (section 17).
11. **AI detection-rule assistant** (section 18) — in the original spec but not named in the
    2026-09-29 reordering message; kept last unless told to drop it.

---

Implement a new AI layer for DENIS that extends the existing AI alert explanation functionality into a configurable, event-driven AI security assistant.
The primary goals are:

1. Add several useful AI capabilities to DENIS.
2. Make all AI capabilities individually configurable by the administrator.
3. Move the existing AI provider/API configuration into a dedicated Settings → AI section.
4. Add an AI Summary to the main dashboard.
5. NEVER call the AI provider simply because an administrator opened or refreshed the dashboard.
6. Generate AI content only when relevant network/security data has changed.
7. Minimize AI API usage and token consumption.
8. Give the administrator complete control over which AI features are enabled.
9. Keep the core detection engine independent from the AI layer.

Do not rewrite working detection functionality unnecessarily. First inspect the existing codebase and understand the current AI implementation, settings architecture, alert system, dashboard data flow, database schema and background/worker architecture.

## 1. AI architecture

Create a clear separation between:

**DENIS Detection Engine**

This remains responsible for:

* network telemetry
* flow analysis
* device discovery
* device profiling
* anomaly detection
* first-seen detection
* new destination detection
* unusual port detection
* behavioral baselines
* DNS/reverse DNS
* IP/ASN/geolocation information
* alert generation
* alert correlation
* historical data

These operations should NOT require an LLM.

**AI Layer**

The AI layer should consume structured, already-processed DENIS security context.
AI should be used for:

* explanation
* classification/triage
* summarization
* correlation interpretation
* investigation assistance
* recommendations
* natural-language interaction

Do not send raw packet captures or unnecessarily large datasets to the LLM.
Create a reusable AI service/module that can receive compact structured context.
For example:

```json
{
  "device": "...",
  "device_type": "...",
  "alert_type": "...",
  "severity": "...",
  "destination": "...",
  "port": "...",
  "asn": "...",
  "country": "...",
  "first_seen": true,
  "historical_behavior": "...",
  "related_alerts": [],
  "baseline_deviation": 0.82
}
```

The exact schema should follow the existing DENIS architecture rather than introducing unnecessary duplication.

## 2. Existing AI alert explanation

Keep the existing AI alert explanation functionality working.
Do not remove or regress it.
Move its configuration into the new Settings → AI section.

## 3. AI Settings

Create a dedicated AI settings page/section.
The existing AI provider/API configuration should be moved here.
The administrator must have complete control over AI functionality.
Create individual enable/disable controls for each AI feature.

Suggested structure:

**AI Provider** — existing configuration:

* provider
* API key / credentials
* model
* endpoint if applicable
* other existing AI configuration

Preserve the currently supported provider architecture. Do not expose secrets unnecessarily in the UI.

**AI Features** — individual checkboxes/toggles:

* **Alert explanations** — explain individual alerts using AI.
* **Alert triage** — use AI to assess an alert and provide additional context such as likely benign / suspicious / requires investigation / reasoning. Do not allow AI triage to override the deterministic DENIS severity. AI should be an additional signal, not the source of truth.
* **Incident correlation** — allow AI to group related alerts into higher-level incidents and summarize them.
* **Device behavioral analysis** — use AI to interpret significant changes in device behavior based on structured DENIS telemetry. Do not invoke AI continuously for every device/event.
* **Recommended actions** — generate investigation/recommended-action suggestions for significant alerts/incidents.
* **Dashboard AI summary** — generate the AI summary shown on the dashboard.
* **Natural-language investigation / Ask DENIS** — allow the administrator to ask questions about the network using natural language.
* **AI threat hunting** — allow AI to help formulate and execute read-only investigations against DENIS data.
* **AI detection-rule assistant** — allow AI to suggest detection rules based on administrator requests. AI-generated rules must be presented for review before activation.
* **Weekly/security reports** — allow AI-generated security summaries/reports.

Each feature must be independently enabled/disabled. Do not assume that enabling the AI provider means all features are enabled. Default new features to OFF unless there is a strong reason to preserve existing behavior. Existing alert explanation behavior should remain enabled if it was already enabled before this change.

## 4. AI usage policy / global control

Add a global AI enable/disable control (e.g. "Enable AI features" ON/OFF).

If globally disabled:

* no AI calls should be made
* dashboard must continue functioning normally
* existing deterministic detection must continue working
* AI UI should indicate that AI is disabled

Individual feature toggles should only be active when global AI is enabled. The administrator must be able to disable every AI feature independently.

## 5. Dashboard AI Summary

Add an AI Summary section/card to the main DENIS dashboard. Example:

> **AI Security Summary**
> Network activity has remained mostly stable over the last 24 hours. Two devices showed unusual outbound behavior. The most significant change involved the Baby Monitor, which contacted a previously unseen external destination.

Potential sections: overall status, important changes, devices requiring attention, significant new destinations, emerging patterns, recommended investigation. Keep the output concise and suitable for a dashboard. Do not turn the dashboard into a chatbot.

## 6. CRITICAL: Dashboard must NOT trigger AI generation on page load

This is a hard requirement. Opening or refreshing the dashboard must NEVER automatically call the AI provider. The AI Summary must be generated asynchronously when relevant underlying data changes. The architecture should work approximately like this:

```text
Network activity
      ↓
DENIS detection engine
      ↓
new/changed security state
      ↓
AI summary marked "stale"
      ↓
background worker / scheduled job
      ↓
AI summary generated
      ↓
stored in database
      ↓
dashboard reads stored summary
```

Dashboard loading should only read the latest stored AI summary. It should not invoke the AI provider.

## 7. Event-driven AI Summary

Implement an explicit concept of an AI summary becoming "stale". For example, create or use an existing state such as:

```text
ai_summary.updated_at
ai_summary.source_state_version
ai_summary.status
```

When meaningful security state changes occur, mark the relevant summary as stale. Examples: new high/medium severity alert, significant alert resolution, new device, significant device behavioral change, new unusual destination, new incident, major change in network activity, other meaningful security events.

Do NOT mark it stale for every packet or flow. The detection engine should determine what constitutes a meaningful state change.

## 8. Deduplication / debounce

Avoid generating multiple AI summaries for a burst of events. Example: five alerts in five minutes should not make five AI calls. Instead:

```text
events
  ↓
summary marked stale
  ↓
debounce / aggregation window
  ↓
one AI generation
```

The exact debounce mechanism should fit the existing worker/background-job architecture. Prefer something like a configurable 5–15 minute aggregation window if appropriate. Do not introduce unnecessary AI calls.

## 9. Summary versioning

The AI summary must be associated with the security state from which it was generated. Example:

```text
security_state_version = 1842
ai_summary_version = 1842
```

If the security state changes (`security_state_version = 1843`, `ai_summary_version` still `1842`), the summary is stale. After regeneration both become `1843`. This makes the behavior deterministic and easy to debug. Use an implementation compatible with the existing DENIS persistence model.

## 10. AI summary caching

Store generated AI results. Do NOT regenerate the same summary repeatedly. The dashboard should read the cached/stored result. Display metadata such as "Generated 8 minutes ago" or "Updated after significant network change". If a summary is stale but regeneration is currently running: "Updating AI summary…" — the dashboard should still display the last valid summary until the new one is ready. Never leave the dashboard blank just because AI generation is in progress.

## 11. AI cost controls

AI usage must be designed to minimize customer API costs. Implement:

* **Event aggregation** — combine multiple events into one AI request.
* **Context compression** — send only relevant structured context.
* **Caching** — never regenerate identical analysis unnecessarily.
* **Debouncing** — avoid repeated calls during alert bursts.
* **Feature-level controls** — disabled features must result in zero API calls.
* **Global AI disable** — must result in zero API calls.
* **Background processing** — never block the dashboard request on AI.
* **Model configuration** — respect the administrator's configured model.

Do not introduce hidden AI calls.

## 12. Alert triage

Implement AI triage as a separate capability from alert explanation. The AI should receive structured context and return structured data, for example:

```json
{
  "assessment": "likely_benign",
  "confidence": 0.82,
  "reasoning": "...",
  "recommended_action": "...",
  "generated_at": "..."
}
```

Use a controlled set of assessment values rather than allowing arbitrary text to drive application logic.

**Important:** AI must NOT modify the original DENIS alert severity. For example, DENIS severity HIGH with AI assessment `likely_benign` — both should remain visible. The administrator makes the final decision.

## 13. Incident correlation

Add an AI-assisted incident correlation layer. The deterministic DENIS engine should identify potentially related alerts using things like: device, destination, time window, alert type, ASN, country, traffic pattern, related entities. AI can then summarize the relationship. Example:

```text
Incident: Baby Monitor unusual outbound communication
Related alerts: new destination, unusual UDP port, new ASN, traffic anomaly
```

AI should produce a concise incident explanation. Avoid sending hundreds of unrelated alerts to the LLM.

## 14. Device behavioral analysis

Create an AI capability that can explain significant behavioral changes. Example:

```text
Device: Baby Monitor Bedroom
Normal: HTTPS to manufacturer cloud, NTP, DNS, 50–150 MB/day
Change: new external destination, unusual UDP port, traffic increased 4x
```

AI should interpret the change. This should only run when DENIS determines there is a meaningful behavioral change. Do not continuously ask the AI to analyze every device.

## 15. Recommended actions

For significant alerts/incidents, allow AI to generate suggested next steps (e.g. investigate destination, check device firmware, compare with similar devices, monitor behavior, inspect DNS history, consider isolation). Recommendations are advisory only. Do not automatically execute network changes.

## 16. Natural-language "Ask DENIS"

Create an AI interface for questions about the network. Examples: "Which devices contacted new external destinations today?", "What changed on my network in the last 24 hours?", "Show me unusual IoT behavior.", "Why is the Baby Monitor generating alerts?", "Has this behavior happened before?"

Architecture:

```text
User question
      ↓
AI interprets request
      ↓
structured DENIS query
      ↓
DENIS database / detection engine
      ↓
results
      ↓
AI summarizes results
```

Do NOT allow the LLM to invent network facts. Network facts must come from DENIS data. Prefer structured tool/function calls or an equivalent internal query mechanism.

## 17. AI Threat Hunting

Add a read-only AI-assisted threat hunting capability. Example: "Find devices that started communicating with rare external destinations this week." The AI should translate the request into structured DENIS queries. The actual query should be executed by DENIS. AI then interprets the returned data.

Initially keep this strictly READ-ONLY. Do not allow AI to: block devices, change firewall rules, modify detection rules automatically, delete data, change network configuration.

## 18. AI Detection Rule Assistant

Allow administrators to describe a desired detection rule in natural language. Example: "Alert me when an IoT device starts communicating with a country it has never contacted before." AI generates a proposed rule, e.g.:

```text
Name: New country for IoT device
Condition: destination.country not in historical_countries
Severity: MEDIUM
```

The administrator must review and explicitly activate the rule. AI must never silently create or enable a security rule.

## 19. Weekly security summary

If enabled, generate a periodic summary using aggregated DENIS data. Do not regenerate it on dashboard access. The scheduled job should generate it once per configured period. Include: number of devices, new devices, significant alerts, incidents, unusual behavior, notable changes, recommended investigations. Keep the prompt/data compact.

## 20. Failure handling

AI must never become a dependency for core DENIS functionality. If the API key is invalid, the provider is unavailable, a request times out, a rate limit is reached, the model returns invalid output, or the AI response cannot be parsed — DENIS should continue operating normally. Show an appropriate non-blocking error/status. Never repeatedly retry aggressively. Use sensible retry/backoff.

## 21. Privacy / data control

Make it clear in the AI settings which data may be sent to the configured AI provider. Where practical, minimize sensitive information. Do not send raw packet contents unless there is an explicit future feature requiring it. Prefer structured metadata, aggregated statistics, device identity, alert context, network behavior over raw telemetry.

## 22. UI requirements

The AI Settings page should clearly show:

```text
AI [ON/OFF]

Provider
  (existing provider configuration)

Features
  ☑ Alert explanations
  ☐ Alert triage
  ☐ Incident correlation
  ☐ Device behavioral analysis
  ☐ Recommended actions
  ☑ Dashboard AI summary
  ☐ Ask DENIS
  ☐ AI threat hunting
  ☐ Detection-rule assistant
  ☐ Security reports
```

The actual default values should respect the existing installation's current AI configuration and avoid unexpectedly changing existing behavior. For every feature provide a short description explaining what it does, when AI is called, and that it may consume API credits/tokens. Example:

> **Dashboard AI summary**
> Generates a concise security summary when significant network changes occur. The dashboard itself never triggers an AI request.

This transparency is important.

## 23. AI usage visibility

Add basic AI usage information to Settings → AI. Example:

```text
AI requests today: 7
AI requests this month: 184
Last AI request: 12 minutes ago
Estimated tokens: ...
```

If exact token/cost information is available from the provider, expose it. Otherwise clearly label estimates. Do not make this dependent on a specific AI provider.

## 24. Audit logging

Record AI activity. Example:

```text
AI feature: Alert triage
Triggered: 2026-09-29 07:31
Reason: New high-priority alert
Model: ...
Result: success
Tokens: ...
```

Do not log API keys or secrets. This should help diagnose unexpected AI usage.

## 25. Tests

Add tests for:

* global AI disabled → zero AI requests
* individual feature disabled → zero requests for that feature
* dashboard refresh → zero AI requests
* unchanged security state → zero new summary generation
* meaningful security change → summary marked stale
* multiple events in short period → one aggregated AI request
* cached summary displayed correctly
* AI failure → dashboard continues working
* invalid AI response → handled safely
* alert severity is never overwritten by AI
* AI-generated rules require explicit administrator activation
* natural-language queries cannot invent data
* AI cannot execute destructive actions

Include tests for existing AI alert explanation functionality.

## 26. Important implementation principle

Before changing code:

1. Inspect the existing AI integration.
2. Inspect existing Settings architecture.
3. Inspect alert/event persistence.
4. Inspect dashboard architecture.
5. Inspect background workers/jobs.
6. Inspect how configuration is persisted.
7. Identify the cleanest integration points.

Do not create parallel infrastructure if existing DENIS components can be extended. Keep the implementation modular so new AI capabilities can be added later without rewriting the AI subsystem.

## 27. Acceptance criteria

The implementation is complete when:

* Existing AI alert explanation still works.
* AI configuration is available under Settings → AI.
* Administrator can globally disable AI.
* Every AI capability has its own enable/disable control.
* Dashboard has an AI Summary.
* Dashboard refresh never triggers an AI request.
* AI Summary is generated only after meaningful state changes.
* AI Summary is cached/persisted.
* Multiple events are aggregated before AI generation.
* AI API usage is minimized.
* AI failures never break DENIS.
* AI does not modify deterministic DENIS detection results.
* AI-generated rules require administrator approval.
* AI network queries use real DENIS data rather than hallucinated data.
* AI activity can be audited.
* Automated tests cover the above behavior.

## 28. Important product principle

The goal is NOT to make DENIS "AI everywhere". The goal is: use AI only where reasoning adds value, while keeping network detection deterministic, local, explainable and efficient. DENIS should remain useful with AI completely disabled. AI should be an optional intelligence layer on top of DENIS, fully controlled by the administrator.
