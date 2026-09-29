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
3. **Alert triage** — done (2026-09-29). On click only, same bar as alert explanations, its own
   independent `features.alert_triage` toggle. Returns a controlled assessment
   (`likely_benign`/`suspicious`/`requires_investigation`), a confidence clamped to `[0,1]`,
   reasoning and a recommended action — `ai::parse_triage` extracts and validates the provider's
   JSON (tolerant of markdown-fenced or prose-wrapped JSON, never tolerant of an assessment outside
   the fixed set, which fails outright rather than guessing). DENIS's own `severity`/`score` are
   returned alongside, unchanged — nothing in this codebase ever writes a triage result back onto
   an `Event`. `web_ai.rs`'s `status` endpoint now reports `alert_explanations`/`alert_triage` as
   separate flags (previously the single `providers` array itself doubled as the explanations
   on/off signal, which stopped scaling once a second feature needed its own independent gate).
4. **Recommended actions** — done (2026-09-29). On click only, its own independent
   `features.recommended_actions` toggle. Deliberately distinct from triage's own single-sentence
   `recommended_action` field (spec section 15 is its own capability): a short advisory list of 1–8
   concrete next steps (`ai::RecommendedActions{actions, generated_at}`), parsed and validated the
   same way as triage (`ai::parse_recommended_actions` finds the first `{...}` span for
   markdown/prose tolerance, requires at least one non-blank action, caps at `MAX_ACTIONS` rather
   than failing on an over-long list). DENIS never acts on anything in the list itself — advisory
   only, matching the spec's explicit "do not automatically execute network changes." New
   `POST /api/ai/recommend` endpoint, alert-only (same reasoning as triage: findings already carry
   their own fixed `fix` text), enforced server-side same as the other two features.
5. **Dashboard AI summary** — done (2026-09-29). The architecturally distinct one of the three
   (sections 5-10): unlike the click-driven features above, this is generated entirely by a
   background job (`src/ai_summary.rs`), never by a request — opening or refreshing the dashboard
   only ever reads what is already stored (`GET /api/ai/summary`), matching section 6's hard
   requirement. The job wakes every 10 minutes (`CHECK_INTERVAL_SECS`), which doubles as the
   debounce/aggregation window section 8 asks for: a burst of alerts inside one tick still produces
   at most one AI call, on the next tick. Staleness is tracked by `SummaryRecord.source_state_version`
   against `Store::latest_alert_id()` — the highest existing alert id, not its timestamp, since an
   agent can report a buffered/backfilled alert whose own timestamp is older than one already
   stored (found and fixed during manual testing: using `timestamp DESC` to find "the latest alert"
   picked the wrong id against demo/replayed data, which is not always inserted in timestamp order).
   The prompt is built from severity counts plus the highest-scored individual alerts in the last
   24h (`ai::dashboard_summary_prompt`, `MAX_HIGHLIGHTS = 8`) — never the raw alert stream. A
   `generating: Arc<AtomicBool>` on `AppState`, set only by the background job, lets the endpoint
   report "Updating…" without needing to persist that as part of the stored record; the dashboard
   always shows the last valid summary regardless (section 10: never blank while regeneration is
   in flight or has failed).
6. **Ask DENIS** — done (2026-09-29). A free-text question box on the dashboard, on click only,
   its own independent `features.ask_denis` toggle. Deliberately two AI calls, never one, matching
   section 16's own architecture diagram: `ai::interpret_question` translates the question into one
   structured `ai::AskQuery` (`{hours, severity?, kind?, device?}`, validated the same rigor as
   triage — `severity` must be one of the three real values, `kind` must pass
   `detect::is_alertable_kind`, either is a hard error if the model invented one); `web_ai::ask`
   then runs that exact search against the store itself (never lets the model touch the database);
   `ai::answer_question` gets only the real rows found (capped at `ASK_MAX_ROWS = 20`) and describes
   them. A question with zero matches still gets a real second call, so the model can say "nothing
   matched" in its own words rather than DENIS synthesizing that message itself. The provider is
   never in a position to answer from anything except what the search actually returned.

Also done, cutting across all of the above (spec section 23, "AI usage visibility") rather than
its own numbered build step: `src/ai_usage.rs` tracks a call count and, when a provider's own
response reported one, a token count, bucketed by day and by calendar month, shown in Settings →
AI → Usage. Every provider function now returns `(text, Option<i64> tokens)`; recording is
always best-effort (mirrors `audit`'s own tolerance) so it can never be the reason an AI feature
that already succeeded appears to fail.

Two real bugs found and fixed live while testing steps 1-6 against real accounts, beyond what
their own CHANGELOG entries cover in full:
* `gpt-5-mini` could spend its entire token budget on invisible internal reasoning before ever
  writing the visible JSON answer, leaving Triage/Recommended actions/Ask DENIS's interpretation
  step failing with an empty response. Fixed with `reasoning_effort: "low"` (OpenAI-only; Grok
  shares the request shape but rejects the field) and a larger token cap.
* Every provider's own request timeout was 30s, too short for a "thinking" model (seen live with
  Gemini). Raised to 60s for all four providers.
7. **Security reports** — done (2026-09-29). Unlike every step above, this extends existing DENIS
   infrastructure (per this document's own section 26 instruction) rather than adding new
   infrastructure of its own: DENIS already generates periodic reports (Settings → Reports, on a
   weekly/monthly schedule or "Generate now" — `reports.rs`/`report.rs`, pre-existing). `reports::
   generate` now also calls `reports::ai_security_summary` right where it already builds
   `compliance_now`, which — only when the feature is on and a provider is configured — writes one
   AI paragraph from the same `ReportData` every other section of the report already shows (device
   count, new devices this period, alert severity counts, the highest-scored alerts, standing
   findings, accepted risks) via `ai::security_report_prompt`/`ai::write_security_report`, and
   `report::html` renders it as its own "AI Security Summary" section. A failed AI call never fails
   the report itself — `ai_security_summary` returns `None` and the report is saved exactly as
   before this feature existed, matching AI.md section 20 ("AI must never become a dependency for
   core DENIS functionality").
Also done, cutting across every feature above rather than its own numbered step: a fifth,
self-hosted "local model" provider (`"local"` in `ai::PROVIDERS`) alongside Claude/ChatGPT/Gemini/
Grok — Ollama, LM Studio, llama.cpp's own server, or anything else speaking the same
OpenAI-compatible `/v1/chat/completions` shape, configured with a URL and a model name rather than
a key (`AiConfig.local_url`/`local_model`; most local servers take no key at all, so `configured()`
now checks per-provider readiness — url+model for `local`, a key for everyone else — instead of
key presence alone). Verified end-to-end against a real local Ollama instance running `qwen2.5:0.5b`
(not just a fake-server unit test): a real "Explain with AI" call round-tripped through DENIS's own
`/api/ai/explain` endpoint in ~3s with a real answer and a real token count recorded. Found live
during that same verification: the settings API's `keys_set` field had been quietly repurposed by
this feature to mean "ready to use" rather than "has a key", which made the local API-key field's
own "(unchanged)" placeholder lie when the provider was ready via url+model alone with no key ever
set — split into `keys_set` (readiness, unchanged meaning) and a new `keys_present` (literal key
presence) so the key field asks the right question again. Requested alongside this: usage
visibility (section 23, shipped earlier) broken down per provider rather than one lumped total —
`ai_usage::UsageRecord` now keys a `by_provider` map instead of one flat set of counters, so an
administrator running a local model alongside cloud ones (or several cloud keys at once) can see
which one is actually being used, not just an aggregate.

9. **Device behavioral analysis** — done (2026-09-29). An "Explain behavior change" button, on
   click only, offered only on the five alert kinds that actually describe a change from a
   device's own established pattern (`detect::BEHAVIORAL_KINDS`/`is_behavioral_kind`:
   `new_destination`, `new_destination_v6`, `new_port`, `unusual_hours`, `volume_anomaly`) — DENIS
   already decided the change was meaningful before this button ever appears, matching the spec's
   own "do not continuously ask the AI to analyze every device". Uses the device's own stored
   `model::Baseline` as "normal" (known destinations/ports, typical volume, active hours) — no new
   tracking, this data already existed and already drives the very alerts the button is offered
   on. Its own independent `features.device_behavior` toggle.

Also found and fixed live, while testing steps 1-9 end-to-end against a real local Ollama
instance rather than only unit tests: the Findings page rebuilt its entire list from scratch on
every 10-second poll, which wiped an in-progress or just-completed "Explain with AI" answer a few
seconds after it appeared — reported as "the explanation disappears". Findings are DENIS's own
computed standing problems, not live data, so their JSON shape is stable poll to poll unless
something genuinely changed; `loadFindings()` now skips the rebuild when the fetched list is
byte-identical to what is already rendered, which fixes the disappearing-answer bug and is a
correctness/performance improvement either way (no pointless reflow when nothing changed).

10. **AI threat hunting** — done (2026-09-29). Folded into Ask DENIS (section 16) as a second
    query shape rather than a separate feature or its own UI: the same interpretation call can
    now come back with a `destination` (an IP or domain the question asks whether/which devices
    have talked to — "has anything talked to 1.2.3.4?", "which devices contacted evil.example?"),
    and when it does, DENIS searches every device's own already-tracked baseline
    (`model::Baseline::typical_destinations` — no new data collection) instead of the event log,
    scoped by the caller's own site access exactly like `/api/baseline/destinations`. The other
    query fields (hours/severity/kind/device) are simply unused for that search; a question that
    is not a destination hunt behaves exactly as before. Still the same two-call shape (structured
    search, then a second call that only ever describes the real rows DENIS found), still on click
    only.

11. **AI detection-rule assistant** — done (2026-09-29). "Suggest a rule with AI" in the network
    watch form (Rules page): a free-text description is translated into one draft watch — the same
    shape (`proto`/`ports_mode`/`ports`/`remotes_mode`/`remotes`/`min_kb`/`score`/
    `cooldown_minutes`) the form's own built-in ready-made presets already fill it with, so it is a
    dynamic, AI-filled preset rather than a separate mechanism. One call, not Ask DENIS's two:
    there is no DENIS-side fact to fetch first, only a shape for the administrator to review, edit
    and submit themselves in the ordinary form — never written or enabled on its own, matching this
    section's own "always needs explicit admin activation, never auto-enabled". Its own independent
    `features.rule_assistant` toggle.

Also done (2026-09-29), as a separate, smaller follow-on to step 11 rather than part of it: the
originally-discussed proactive "this kind of rule would suit your traffic" banner on the Rules
page (`rule_suggest.rs`) — deliberately not an AI feature (no model call, nothing sent anywhere):
a dismissible nudge, computed fresh and cheaply from already-tracked baseline data each time the
page loads, currently covering one case (devices reach the internet, nothing watches it) and
opening into the same pre-filled "New Rule" form the AI assistant above also fills.

This completes the AI feature roadmap's numbered steps 1-11.

Also done (2026-09-29), a cross-cutting UX fix rather than its own step: every on-click "ask AI"
button across the console (Explain, Triage, Recommended actions, Explain behavior change, Suggest
a rule) used to show a provider dropdown sitting next to it for as long as it was visible, whenever
more than one provider was configured. It now opens that dropdown only on click, in place of the
button, closing the same window a Findings-page poll rebuild or an Alerts-page poll rebuild could
otherwise wipe a picked-but-not-yet-submitted value through — the same class of bug the Findings
answer-disappearing fix (step 9's write-up above) and the Acknowledge-reason fix (see CHANGELOG
v2.43.1) both addressed, generalized here to every provider picker at once rather than fixed one
site at a time. New Settings → AI checkbox, "Use default model for all actions" (on by default,
preserving the original one-click behavior); turning it off is what asks per click.

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
