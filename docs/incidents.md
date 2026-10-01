# Incidents

A busy network can raise a dozen alerts for one real event: a device that got compromised might trip a new-destination
alert, then a new-port alert, then a volume anomaly, each a separate row on the Alerts page if nobody groups them.
**Incidents** (Monitor tab, next to Alerts) does that grouping for you: related alerts become one incident with its
own priority, so you work the incident instead of guessing which alerts belong together. Alerts themselves are
unchanged — they still appear on the Alerts page, still drive notifications the same way, and still count toward a
device's risk score; an incident is a second, higher-level view over the same data, not a replacement for it. An
alert that stays on its own just stays on the Alerts page; see **No incidents. DENIS groups related alerts into one
incident when a recognised pattern (or several unrelated signals about the same device) shows up** on an empty
Incidents page for the short version.

This runs entirely on DENIS's own rules — no AI involved in opening, growing or prioritising an incident. An AI
provider can optionally add a second opinion on one you are already looking at (see
[Assess consequences with AI](#assess-consequences-with-ai) below), but DENIS's own verdict is what you see first and
what drives any notification.

## What opens an incident

Three different things can start one, and DENIS tells you which by what the incident contains:

* **A recognised multi-stage pattern.** Certain sequences of alerts, from the same device (or the same site, for
  network-wide trouble) within a matching time window, are specific enough to name:
  * *Someone is trying to become the network's gateway or DNS server* — rogue DHCP/RA activity escalating.
  * *An unauthorised station is talking to, then changing, an industrial controller.*
  * *A device is mapping the network and spraying a worm-signature port outward.*
  * *A device swept the network, then used something new for the first time.*
  * *A device contacted known-bad infrastructure and shows other signs of compromise.*
  * *A device that just joined immediately probed or impersonated the network.*
  * *Several reliably-online devices went quiet together.*

  Each one carries its own priority logic (below); the title on the Incidents page is exactly the plain-language
  description above — nothing to decode.
* **One standalone high-severity alert**, for an alert kind serious enough that it never needs a second alert to
  justify its own incident (contact with a known-bad address, a rogue DHCP server, an ARP conflict on the gateway…).
* **Several unrelated alert kinds about the same device, close together** — even when none of them individually
  matches a named pattern above, two or more genuinely different kinds of alert about one device in a short window is
  itself worth a look, so DENIS opens a plain "related alerts" incident for it.

An incident keeps absorbing matching alerts (and can escalate from a lower-precedence pattern to a higher one) for as
long as they keep arriving; it closes out and stops growing once nothing new has joined for a while. Acknowledging the
alerts inside an incident does not acknowledge the incident itself — **Acknowledge incident** on its detail page does,
in one action, for every alert it contains.

## Priority: what to do first

Every incident gets one of four priorities, shown as a coloured pill, from two things DENIS already knows about it:
**confidence** (how sure the pattern match is — high/medium/low) and **impact** (what is at stake — the whole
network or a physical/industrial process at the top, down through a critical, elevated, normal or low-importance
device). The combination maps to:

| | Priority | Meaning |
|---|---|---|
| 🔴 | **Act now** | high confidence and serious stakes (or either one pushed to the extreme) — look at this before anything else |
| 🟠 | **Investigate today** | still worth same-day attention, but not an emergency |
| 🟡 | **Review** | worth a look when you get to it |
| ⚪ | **Can wait** | low confidence and low stakes — likely noise, but recorded in case it is not |

The incident list sorts by priority first, so *Act now* and *Investigate today* always float to the top regardless of
when they came in; the sidebar badge on **Incidents** only counts those two. Click an incident for the full picture: a
timeline of every member alert in order, which devices are involved, and the same score/confidence/impact factors
spelled out in a sentence.

## Assess consequences with AI

With an AI provider configured and **Settings → AI → Incident consequences** turned on, an incident's detail page
gets an **Assess consequences with AI** button: on click, it sends the incident's own alerts (kinds, scores, reasons,
ages) and the devices involved (type, criticality, Purdue level and zone — never owner, serial number, tags or any
other inventory detail you typed in) to your chosen provider, and shows back what could realistically happen if it is
ignored, innocent explanations that would make it nothing to worry about, and the one fact that would settle it
either way. This is a second, clearly labelled opinion next to DENIS's own rule-based priority — never a replacement
for it, and never what drives a notification. If the AI's read and DENIS's own priority point different ways, the
answer says so explicitly rather than leaving the two sitting side by side. A newer alert joining the incident after
an assessment was written marks it stale, with an offer to ask again.

**Settings → AI → Incident consequences, automatically** (meaningless without the button above also on) writes that
same assessment in the background for open incidents already at *Act now* or *Investigate today* — once an incident
has stopped absorbing new alerts for five minutes, at most once per incident per change, capped at 50 calls a day
across every incident, so you see the AI's read the moment you open a serious incident instead of waiting on a click.

## Turning it off, and sending incidents out

**Settings → Alerting → Incidents → Group related alerts into incidents** (on by default) is the single switch for
all of the above: turning it off stops new correlation immediately — alerts themselves, and their own delivery to
your notification channels, are completely unaffected either way; existing incidents stay as they are.

Each notification channel (Slack, Teams, e-mail, PagerDuty, …) chooses, in its own **Delivery** setting, between
*Every alert, individually* (the default) and *Group related alerts into incidents*: the latter sends one message the
moment an incident opens or escalates, plus any alert that never joined one — never a repeat for every alert already
absorbed into an incident already reported. PagerDuty and ServiceNow update the same incident/ticket on escalation
instead of opening a new one. See [Alerting](alerting.md) for the channels themselves.

SIEM/log export has the same idea: turn on the **Incidents** stream (Settings → Integrations) to send one record per
incident opened, escalated or acknowledged, alongside or instead of the individual-alert stream — see
[Export](export.md).

## API

`GET /api/incidents` lists them (site-filtered like everything else); `GET /api/incidents/{id}` returns one with its
full timeline; `POST /api/incidents/{id}/ack` acknowledges it, with an optional reason. `PUT /api/incidents/settings`
flips the grouping switch above. See the [API reference](api.md).
