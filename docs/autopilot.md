# Autopilot (experimental)

<!-- autopilot-experimental -->
**Autopilot is experimental.** It can miss real threats, and it can interrupt you about things that
turn out to be harmless. It does not replace a security professional. When an AI model is used, its
explanations and suggestions can be wrong. By default Autopilot does not block a device or change your network on
its own: anything that would change something waits for your approval, and a block needs your
password or passkey in the console. The one exception is a separate option, off by default, that
you must switch on yourself and that is highly experimental: [Autopilot may block](#autopilot-may-block-experimental). Autopilot can file away low-importance alerts by itself only if
you allow it, and you can see and undo every one. Before you let Autopilot act, review its shadow-mode
report of what it would have done.
<!-- /autopilot-experimental -->

Autopilot reads the alerts DENIS raises, sorts them into the few that need you now and the many that
can wait, explains each one in plain language, and asks you, one specific question at a time, before
it changes anything. You can answer from the console or, once you have paired a phone, from the phone.

It is a layer on top of the quiet alert stream ([Detection rules](detection-rules.md) and
[Alerting](alerting.md) describe what DENIS already keeps quiet, and why). The quiet stream does most
of the noise reduction by itself. What Autopilot adds is that the few items left arrive explained, with
one proposed answer, and that routine questions ("is this new phone yours?", "is this provider normal
for this camera?") stop needing the console.

## What it is not

* It is **not a firewall, an antivirus or a guarantee**. DENIS sees the traffic that reaches its
  interface and the devices that join the network; it does not see what runs on a device.
* It **does not block anything by default**. Autopilot's proposals contain no block action. When a policy you asked
  DENIS to watch is broken again and again, DENIS can suggest a block (see
  [Zones and policies](segmentation.md)); Autopilot only forwards that suggestion and links to the
  console's own block review, where a block needs your password or passkey. No AI is involved in a
  block suggestion in any way. There is one separate, off-by-default exception that you have to earn and
  switch on yourself: [Autopilot may block (experimental)](#autopilot-may-block-experimental).
* It is **not AI-first**. Everything works without an AI model, on DENIS's own rules. An AI model, if
  you choose one, only helps with ranking, wording and picking among options DENIS built itself.
* It does **not make the network "safe"** and it does not tell you that you are fine. A quiet phone
  means that nothing needed you, not that nothing happened.

## The three modes

You choose the mode in **Settings → Autopilot**. Each control on that page explains itself.

| Mode | What it does | What it does not do |
|---|---|---|
| **Off** (the default on every install) | Nothing. | Decides nothing, proposes nothing, sends nothing. |
| **Shadow** | Watches and records what it *would* have done: which alerts it would have interrupted you about, which it would have put in the briefing, what it would have proposed. Shows you a report. | Changes nothing, files nothing, sends no message, and a shadow proposal cannot be applied. |
| **Active** | Acts within the allowed action classes, below. | Never blocks, unless you also switched on [Autopilot may block](#autopilot-may-block-experimental). Every action has an undo and an audit entry. |

Turning Autopilot on always starts in shadow mode. To go from shadow to active you need all of:

* at least **7 days** in shadow (14 is suggested for a business; the minimum can be raised, not lowered),
* to have **opened the shadow report** during that shadow period,
* a current **acknowledgement of the disclaimer** (it asks again when its wording changes: the wording changed in 4.1.0, so an acknowledgement given earlier must be given again),
* your password (or a passkey).

Switching to Off is always one click, from any mode. A **pause** (1 to 72 hours, from the console or
from any Autopilot message) acts like Off for that long and then returns; resuming early is console-only.

## The shadow week

Leave it in shadow for at least a week. The shadow report compares what Autopilot would have done with
what you actually did:

* the interruptions it would have made each day, each with "you looked at this N hours later",
* how many of the alerts it would have filed you acknowledged yourself as expected behaviour or false
  positive (the **agreement**), and the alerts you acted on that it would have filed or left for the
  weekly report (the **misses**; each is listed),
* the questions it would have asked and whether you later did the same thing by hand,
* what the AI cost, and how often its answers were rejected.

Auto-file (below) cannot be switched on until the agreement is **95 %** or better.

## What it decides: four buckets

Every alert, or group of related alerts about one device, goes to one of:

1. **Interrupt now**: a message to your phone, immediately.
2. **Daily briefing**: one message a day at your briefing time (08:00 by default).
3. **Weekly report**: a section of the weekly report.
4. **Filed**: acknowledged with a reason, visible and undoable (only with auto-file on, see below).

DENIS computes, without any AI, a **floor** (the quietest bucket allowed) and a **ceiling** for each
group, and a default. These always interrupt, whatever the time or the AI says:

* alerts of a kind that is never treated as routine (threat-list matches, rogue DHCP or router
  advertisements, a changed resolver, fan-out to many hosts, sweeps, industrial commands and writes,
  segmentation violations, a gateway address conflict, and so on; the list is the quiet stream's own),
* a very high score (90 or more), an incident that needs attention now, an open block suggestion,
* a new device with a vendor address once the site is past its first day,
* any new provider for a device you marked as sensitive.

An AI model can move other alerts between the floor and the ceiling, never below the floor and never
above the ceiling, and its raising is limited per day. **Quiet hours** (22:00 to 07:00 by default)
hold back everything except what must interrupt.

## What it may do: action classes

Autopilot only ever proposes actions from a closed list, built by DENIS from facts it holds. Each has a
class that sets how much proof it needs from you.

| Class | What | Who decides | From a phone | Undo |
|---|---|---|---|---|
| 1 File | acknowledge `low` alerts you already called expected, on routine kinds of device | Autopilot, **only if** auto-file is on and the agreement gate was met | not applicable | 30 days, listed in the briefing |
| 2 Confirm facts | "Is this device yours?"; mark a device sensitive | you | one tap | edit the device |
| 3a Watch more | turn on passive DNS; pause Autopilot | you | one tap | one click |
| 3b Accept as normal | allow one provider for one device; a quiet exception for one rule on one device; acknowledge a cluster as expected | you | tap **and** your password or passkey on the phone | 30 days; the exception itself lasts 180 days, then you are asked again |
| 3c Tune | an existing rule-settings draft; make a device's noise profile quieter | you | passkey (or your password) on the phone | 30 days |
| 4 Enforce | **none**: Autopilot only links to the console's block review (unless the separate, off-by-default [Autopilot may block](#autopilot-may-block-experimental) is switched on) | an administrator in the console | link only, no approve button | the block review's own unblock |

A **refusal list** is checked when an option is built and again when it is applied. Among other things,
Autopilot never quiets, files or allows: a kind that is never routine, an alert that hit an escape
hatch (a risky port, a large first transfer to a new provider, a threat-list match), an alert that
belongs to an incident that needs attention, the gateway, the DENIS host or an industrial device; never
files anything above `low`; never works on more than one device at a time; never creates an exception
that drops alerts; never disables a rule, sets a weight to zero or raises a minimum score; and takes no
action about a device whose name looks like an instruction to an AI system (except marking it sensitive
or confirming it).

Before an approved action is applied, Autopilot checks again that the alerts still exist and are still
open, that nothing more serious has joined them, that the device still exists and that the action is
the one you were asked about. If anything changed, nothing is applied and you are told to look again.

### Quiet exceptions ("accepted as normal")

When you accept something as normal for one device, DENIS does **not** drop the alerts. It stores them
as quiet entries (`info`, with the reason "you accepted this as normal") and lists them in the daily
digest, so nothing disappears and an undo means something. It never applies to a kind that is never
routine. The rule lasts 180 days and then you are asked again. The **Rules** page lists every one with
its expiry date and the approval it came from, and lets an administrator remove one at any time; the
removal is audited.

## Using an AI model (optional)

Autopilot uses the AI provider you already set up under **Settings → AI** (a cloud provider with your
own key, or a local model such as Ollama). It has its **own on/off switch**, separate from the buttons
on alerts, and it does nothing until both the AI switch and Autopilot's are on. Without a provider
Autopilot works on rules alone, and that is a supported mode, not an error state.

What the model does: ranks and words the alerts that are not must-interrupt, merges clusters about one
device or incident, explains, picks **at most one** of the options DENIS offered (by number), and may
write a short sentence for the briefing. What it cannot do: name an action, go outside the bounds
DENIS set, touch a block suggestion, or change anything. Its answer must fit a fixed format; one
invented value (an unknown alert, a bucket outside the allowed range, an option nobody offered, a
link, an address DENIS did not give it, a claim that something was blocked) throws the whole answer
away and DENIS decides on its own rules. After five rejected answers in a day the provider is left
alone until the next day, and a failing provider is retried after 1, 5, 15 and then 60 minutes.

### What leaves your network

A **local model** sees what it needs, on your own machine. A **cloud model** is **off by default**; when
you turn it on you choose, per kind of data, what may leave:

| Data | Cloud default | Sent as |
|---|---|---|
| device role, noise profile, sensitive flag | on | `camera`, `iot_cloud` ... |
| alert facts (kind, severity, score, counts, ages, reason codes, bytes) | on | numbers and codes |
| provider identity (AS number and organisation) | on | the AS number and its name |
| **device names** | **off** | with it off, a number: "device D3" |
| **network names** (host names, DNS names) | **off** | not sent |
| **provider domains** | **off** | not sent |
| **public addresses** | **off** | not sent (an AS and a country instead) |
| MAC addresses, private addresses, packets, credentials, notes, user names | **never** | never |

Names that are sent are replaced by short references (`D3`, `S1`) and DENIS puts the real names back
only on your own screen, after checking the answer. **Settings → Autopilot** shows exactly what a call
would contain and the real input of the last call (kept 7 days).

A device on your network can choose its own name, so names are treated as hostile text: they are
cleaned (control, bidirectional and zero-width characters removed, only plain characters kept,
shortened), kept in a separate field and never part of an instruction, and a name that looks like an
instruction to an AI ("ignore previous instructions...") is not sent at all, its alerts are decided on
rules alone, and the briefing says that device announces such a name. The model cannot do anything a
name could ask for, because everything it returns is checked against bounds it does not control.

Budgets per day (adjustable): 30 calls and 150,000 tokens. Over budget, Autopilot continues on rules
and says so in the briefing.

## Answering from a phone

A proposal is sent with a **single-use approval token**: one per question and per answer (approve,
deny, snooze, tell me more, pause), valid 12 hours (no longer than the question itself), tied to
exactly that action, so an approve token cannot deny and a token cannot be reused for another
action. Opening the link only shows the question: **a link never acts** (a link scanner or a preview
cannot approve anything); the answer is a separate request. If the question changed after the token
was made, the token no longer works. Revoking a phone invalidates every token that is out.

* Classes 2 and 3a: the token alone (one tap).
* Class 3b: the token **and** your password or passkey on the phone.
* Class 3c: a passkey tied to this one question (or your password if you have no passkey).
* Class 4: never from a phone.

Phones are paired with a one-time code from the console. Paths: ntfy (works behind NAT, no open port
needed), the installed web app with Web Push, and a Telegram bot. Actionable ntfy messages need an
access-controlled topic.

Messages are sent to the paired ntfy topics, Web Push subscriptions and Telegram chats, and to every
channel whose policy is *autopilot*. When one of those channels has not delivered for an hour, an
interruption also goes to the other channels that take important or Autopilot alerts, so one broken
channel never means silence. Delivery is tested against local simulations of ntfy, Web Push and the
Telegram bot API; round trips with real phones are not verified yet (see below).

## Kill switch, pause and limits

* **Off** stops the loop. Outstanding tokens are refused (except deny and pause), and the console
  shows that Autopilot is off.
* **Pause** and **Resume** as above. Every pause is announced in the audit log.
* Limits per day (adjustable within bounds): 10 interrupts (more are batched into one "several things
  need you" message an hour; must-interrupt alerts are never held back), 3 interrupts raised by the
  AI, 5 questions sent (more wait in the console), 200 auto-filed alerts; 10 class-3b answers from the
  phone per week. A question you refused or let expire is not asked again for 7 days unless it changes.

## Privacy and data protection

Autopilot stores its decisions (which alerts, which bucket, why, and who answered) in DENIS's own
database, with the same retention as alerts. Device names, addresses and behaviour patterns are
personal data. For a household the household exemption normally applies. A business or a managed
service provider is the controller of its staff's and guests' device data: sending names or addresses
to a cloud model makes that provider a processor, which needs a data processing agreement, a transfer
basis for providers outside the EU, and a record of processing. DENIS's part is to make minimal data the
default, to show exactly what is sent, and to make a local model a first-class choice. Monitoring
employees' devices can need the works council's agreement in some countries. Check your own situation;
this page is not legal advice, and DENIS does not control a provider's own retention.

## Autopilot may block (experimental)

**Highly experimental. Off by default. It can be wrong, and a wrong block can cut off a device your business needs.**
This is a separate option from everything above, it is not part of any mode, and it can only be switched on in
*Settings → Enforcement → Automation*, under "Let Autopilot block". Read the [enforcement page](enforcement.md#automation)
too: this is level (c) of automation.

**What it does.** When a *rule or detector* reports a `high` severity finding about exactly one ordinary device, and
Autopilot's own rules put it in "Interrupt now", Autopilot may ask DENIS to **quarantine** that device (the default) or
block it, for a limited time. The action goes through the same path as a block you start yourself: the same plan, the
same checks, the kill switch, the hourly limit, the ledger and the audit log.

**What it never does.**

* It never acts on the model's opinion alone: the trigger is a rule or detector severity. The model can only lower: an
  answer of "likely benign" ends it.
* It never acts on OT devices, network or server infrastructure, the gateway, DENIS itself, a device you marked
  sensitive, or anything the guards refuse (uplinks, protected addresses, the address you are signed in from).
* One device per action. It never blocks a flow, never switches off a port and never ends sessions.
* It cannot name a device, a connector, an address, a time or a setting. The model's answer is a closed form: one
  suggestion id and, at most, an action you already allowed. Anything else in it is refused and written to the audit log.
  DENIS itself computes what to do, to which device, through which of the connectors you chose, and for how long.
* It never blocks while Autopilot is in shadow mode, paused or off.
* Every block ends by itself after at most **24 hours** (default 1 hour). It is never permanent.
* At most **2 blocks an hour**, 6 a day, and one per device every 3 days. These also count against the hourly limit of
  all enforcement and the limit of automatic enforcement by rules. A plan with any warning is not carried out.

**What you need before you can switch it on.** All of these, every time, and the server checks each again at the moment of
every block:

1. Automatic enforcement by rules is on (level (b)). Switching that off switches this off in the same moment.
2. Autopilot is on and **active** (not shadow only), and has been through its shadow period.
3. **At least 7 days** of "would have blocked" records. Every time Autopilot would have blocked something, in shadow mode
   or while this option is off, it writes a record and nothing else (one per device and day). To collect them you need
   a connector set up and both lab switches on while Autopilot is in shadow mode.
4. **At least 10** of those records **judged by a person**: you blocked or quarantined the device yourself within a day,
   or acknowledged one of its alerts as *resolved* count as agreeing; you acknowledged one as *false positive* or
   *expected behaviour*, or undid an Autopilot block, count as disagreeing. An alert Autopilot closed itself says nothing,
   and neither does a bulk acknowledgement or an alert closed together with its incident.
5. **At least 95 %** of the judged records agree. The figures are on the Autopilot screen's status line and in
   the automation box.
6. Your account holds the permission to block and to quarantine, both lab switches and the kill switch are on, and you
   type the phrase **LET AUTOPILOT BLOCK** and your password. API tokens, `--insecure-no-auth` and accounts limited to some
   sites cannot switch it on.

**It switches itself off** (it stays off until a person switches it on again) when the administrator who allowed it is
gone, disabled, limited or loses a permission. It stops acting, without switching off, when the agreement falls below 95 %
again, when Autopilot leaves active mode, or when a lab switch or the kill switch goes off.

**Every block is announced** on every notification channel with an **Undo** link. The link only opens the console; the Undo
button there releases the block as you. The audit log has `nac.automation.autopilot.run` for every block (the decision, the
rule or alert behind it, the suggestion id and the agreement figures) and `nac.automation.autopilot.refused` for every
refusal, including every refused suggestion.

## What Autopilot cannot do

* See traffic that does not cross DENIS's interface, encrypted DNS, the content of encrypted traffic, or
  anything on a device itself.
* Stop an attack with certainty. It tells you, can suggest a block, and only if you switch on the experimental option above can it quarantine one device for a limited time.
* Know your intent: a new provider may be a firmware update or a takeover.
* Notice slow, low-volume misuse of a provider a device already uses.
* Work while DENIS, its host or the path to your phone is down.
* Be right every time. AI explanations can be wrong, and the rules have their own residual risks.
* Replace patching, backups, strong passwords or a professional assessment.

## Verified and not verified

Verified by automated tests in this release: the mode rules (shadow first, minimum days, report
viewed, acknowledgement); every line of the refusal list; the closed list of actions (there is no
enforcement variant, and the executor imports no enforcement code); approval tokens (forgery, replay,
wrong verb, changed action, expiry, revocation); the closed AI answer format with hard errors for
anything invented; prompt-injection names in every position, with a model that obeys them; the data
class switches (what is sent is pinned in reviewed files); budgets, backoff and fallbacks; shadow mode
changing nothing; undo for every action; a 14-day synthetic home network with 14 injected attacks, in
which Autopilot missed none, interrupted every must-interrupt attack within one tick, and averaged at
most one interruption a day on quiet days; the database migration on SQLite and PostgreSQL 16.

**Not verified yet**: a shadow week on a real network (the figures above are from a synthetic one);
real phone round trips on Android and iOS; the prompt-injection corpus against each real AI provider
and local model; an external review of the approval protocol and the injection defences; delivery
through the real ntfy, Web Push and Telegram services (it is tested against local simulations only);
[Autopilot may block](#autopilot-may-block-experimental) on real equipment. This is why the label stays
"experimental".

## Measuring it yourself: the replay tool

`denis autopilot-replay export.jsonl` runs the real decision loop over an anonymised export of alerts
with a simulated clock and a simulated owner, and prints the interruptions a day, the seeded attacks
that were missed, the questions asked and the share you would have undone. It is read-only: it uses a
throw-away in-memory database and prints to the screen. Options: `--provider none|fake|obedient|local`
(rules only; a well-behaved fake model; a fake that obeys hostile names; a real local server with
`--local-url` and `--local-model`), `--owner never|approve|deny|approve-undo`, `--mode shadow|active`,
`--auto-file`, `--quiet-hours`, `--json`.

Each line of the export is one alert: `{"ts": 1800000000, "type": "new_destination", "severity": "medium",
"score": 55, "asset": {"id": 3, "type": "camera", "name": "cam-3"}, "site": null, "details": {},
"seed": {"name": "camera exfiltrates", "must": false}}`. A line with a `seed` is an injected attack the
replay must not miss. Never commit a real export; `tools/noise/anonymise.py` makes one that is safe to
share.

## See also

[Alerting](alerting.md) for channels and the "important only" policy, [Security](security.md) for the
approval protocol, [API](api.md) for the `/api/autopilot` routes, [Detection rules](detection-rules.md)
for exceptions and the rules that raise the alerts.
