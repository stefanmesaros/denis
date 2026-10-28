# Alerting: getting alerts to your team

Alerts always appear in the console. **Alerting** (*Settings → Notifications*, administrators) also sends them out, so nobody has to
watch the console. Add as many channels as you like; each one has its own minimum score.

| Channel | What you need | Notes |
|---|---|---|
| **Slack** | an *Incoming Webhook* URL | one message per alert with the device, why it scored what it did, and what to do |
| **Microsoft Teams** | a webhook URL from **Workflows** ("Send webhook alerts to a channel", or a flow triggered by *When a Teams webhook request is received*) | sent as an Adaptive Card. Microsoft retired the old Office 365 Connectors, so use Workflows |
| **Discord** | a channel webhook URL | mentions are disabled, so a device named `@everyone` cannot ping anyone |
| **PagerDuty** | an *Events API v2* integration key | for paging. Default minimum score is 70; repeats about the same device fold into one incident; severity maps to critical / error / warning / info |
| **Pushover** | an application token (pushover.net/apps) and your user or group key | push notifications to phones. *High* alerts go as high priority (they bypass quiet hours), medium as normal, low as low; nothing asks for an acknowledgement |
| **ntfy** | the address of your topic, like `https://ntfy.sh/your-topic` (or a topic on your own ntfy server); an access token if the topic is protected | push notifications without an account. Priority follows severity (urgent for a score of 90 and up). On the public server the topic name is the only secret: make it long and random. A token is never sent over plain `http://` |
| **E-mail** | an SMTP server (STARTTLS or TLS), From and To addresses | plain-text mail with the same content |
| **Jira** | your Jira site address, account e-mail, an API token and a project key | files one real issue per alert via the Cloud REST API. DENIS never updates or closes it afterwards — that happens in Jira like any other ticket |
| **ServiceNow** | your instance address, a username and password | files one real incident per message via the Table API. Severity maps to urgency/impact. DENIS does not look up or update an incident it filed earlier: every message is a new incident, and repeats about the same device or action carry the same `correlation_id` (the same key as PagerDuty's), so a business rule or a filter on that field in ServiceNow can group them |
| **Generic webhook** | any URL that accepts a JSON POST | Mattermost, Zapier, your own code. Optional signing secret |

Press **Test** on a channel to send a test message and see straight away whether it works.

## Individually, or grouped into incidents

Each channel also has its own **Delivery** choice:

* **Every alert, individually** (the default) — one message per alert, as described below.
* **Group related alerts into incidents** — one message the moment an [incident](incidents.md) opens or escalates,
  plus any alert that never joined one. An alert already absorbed into an incident that was already reported never
  sends a second message for it. PagerDuty updates the same incident on escalation instead of opening a new one, the
  same idea as its own repeat-folding below; a ServiceNow incident filed for an escalation carries the same
  `correlation_id` as the first one.

Turning incidents off entirely — **Group related alerts into incidents** at the top of *Settings → Notifications* (on by
default) — does not touch delivery: it just means there is never anything for a channel set to "grouped" to group,
so that channel quietly behaves like "individually" until incidents are back on.

## What gets sent, and when

* Only real alerts (not the low-level `info` events) at or above the channel's **minimum score**.
* **One message per alert**, unless more than five are waiting for a channel; then they go out as **one summary**
  listing the most serious. An alert storm never floods a chat room. (This individual-alert behaviour; a channel set
  to deliver grouped incidents instead follows the rule above.)
* A channel that is down does not lose alerts: it retries with a growing pause (up to 15 minutes) and catches up
  when it returns. Alerts older than 24 hours are dropped rather than sent late.
* A new channel starts from *now*; it does not replay history.
* **Maintenance mode** (*Settings → Notifications*): silence *all* channels for 30 minutes to 7 days during planned work. A
  banner shows on every screen while it is on, and alerts raised meanwhile are **not** sent afterwards.
* **Silence one device**: in a device's edit form, *Silence notifications until* a date (to the end of that day).
  The device's alerts still show in the console.
* Every change to channels and maintenance mode is in the audit log.

## Which alerts a channel gets: every alert, or important only

Each channel has a **Which alerts** setting:

* **Important only** (the default for a new channel) sends what is worth interrupting someone for: a score of 70 or
  more, the kinds that are never kept quiet (threat-list match, rogue DHCP or router advertisement, DHCP-option
  change, DHCP starvation, resolver change, fan-out, address-conflict on the gateway, segmentation violations and the
  like) at medium or above, an address conflict, industrial control and write commands, and a new unknown device
  from a score of 50. The daily digest is sent only when it names a provider that an infrastructure or industrial
  device had never used. Routine events are never sent: they are in the console and in the daily digest.
* **Every alert at or above the minimum score** is what a channel always did. A channel that existed before this
  setting keeps it; upgrading changes nothing a pager receives, until you change it on the channel.

## Autopilot and your channels

[Autopilot](autopilot.md) (experimental, off by default) sorts alerts into "interrupt now", the daily
briefing, the weekly report and "filed", and asks you before it changes anything. It does not change
what your channels do: a channel keeps the policy you gave it (every alert, or important only) exactly
as before, and in shadow mode nothing is sent at all. What Autopilot adds for messages is a
one-line explanation, one proposed answer, and the briefing, and it uses the same "important only"
test that a channel's own policy uses, so the two never disagree about what is important.

An alert you told Autopilot to accept as normal for one device is **not** dropped: it is stored as a
quiet entry and listed in the daily digest (see "What DENIS keeps quiet" below), and the Rules page
lists every such acceptance with its expiry and a button to take it back.

## What DENIS keeps quiet

A routine event (a new address of a provider a device already uses, random peer-to-peer ports, a phone that is away,
a volume well inside what a device usually sends and similar) is not deleted and not hidden: it is **kept quiet**. It is stored as an
`info` event with a record of why (`raw_details.quiet`: the reason code, the device's noise profile, a plain sentence
and what it would have been), it is counted, and it is listed in the **daily digest**. Nothing quiet is ever pushed
to a channel.

* **Show quiet** on the Alerts page lists the quiet events inline, greyed, each with its reason. The line above the
  list says how many alerts need review and how many were kept quiet today.
* **The daily digest** is one stored report per site and local day (the Dashboard shows yesterday's, its dialog
  shows every device: what it raised, what was kept quiet and why, which providers it reached, and which of them
  were new). It is data, not an alert: it is not counted as an open alert and takes no part in incidents.
* **Reasons**, which never change their codes: `known_owner`, `p2p_udp`, `port_coincidence`, `off_scope_private`,
  `smb_fallback`, `within_peak`, `profile_floor`, `same_device`, `known_pair`, `mac_rotation`, `personal_presence`,
  `personal_hours`, `learning_digest`, `watch_quiet`.
* **Never kept quiet:** whatever the profile, the owner or the setting, a threat-list match, a rogue DHCP server or
  router advertisement, a DHCP option change, DHCP starvation, a resolver change, outbound fan-out, a sweep of your
  network, industrial control and write commands, segmentation violations, a new device on a watched port, a
  fingerprint change, a conflict on the gateway's address and a new device with a vendor MAC are always raised. So is
  any event with a risky port, a threat-list address, 10 MB or more to a new provider or 200 MB or more in five minutes
  from a device that is not a server.
* **Noise profiles** (standard, IoT cloud, personal, infrastructure, industrial) decide which routine events are kept
  quiet for a device. DENIS suggests one from the device type; change it on the device panel. The Rules page
  lists each profile, how many devices have it and what it changes.
* **Allow this provider** (in an alert's dialog): records a provider as one this device uses, so what it does next is
  kept quiet. It adds no exception, and it is in the audit log. An administrator can allow it for every device of a
  profile. **Acknowledge all like this** closes every open alert of the same kind about the same provider from the
  last 7 days (never for the kinds above).
* **This is normal** (an alert's dialog; editors and administrators): acknowledges the alert as expected behaviour and
  stores an exception for 90 days (1 to 365). *This rule on this device*, *this rule, this device and this
  destination*, or *everything ordinary on this device*. A later alert it covers is kept quiet (reason
  `owner_exception`, with who made the exception), never dropped: **Show quiet** lists it, the daily digest and the
  counters count it, and `GET /api/rules/normal/suppressed` lists them per exception. Remove an exception on the Rules
  page (administrators) and the rule alerts again; when it expires it does the same. It never covers the kinds above
  that are never kept quiet, address-claim and new-device alerts, an alert with a risky port, a threat-list address or
  a large transfer, your own rules (they have their own exceptions) or an industrial alert of high severity; the
  whole-device choice also never covers any industrial or high-severity alert.
* **How often each rule was acted on**: DENIS keeps, per rule and day, how many alerts were raised, kept quiet,
  acknowledged as resolved, false or expected, closed automatically or put in an incident, and how many nobody
  reviewed after a week. These are counts only (no addresses), kept 400 days whatever the event retention is.
  Your own rules are counted one by one. `GET /api/rules/outcomes` (and `.csv`) reads them.
* **Close low alerts automatically** (*Settings → Notifications → Quiet routine alerts*, off by default): a low alert that
  has not happened again (same device, kind and provider) for 3 to 30 days (7 by default) is acknowledged by the system.
  The alert's history says so, and it can be undone. Medium and high alerts, the kinds above and alerts in an open
  incident are never closed this way.
* **The kill switch**: *Keep routine events quiet* in the same box. Off, every event is raised as an alert, as before.
  It applies within seconds.
* The Alerts list is ordered by **priority** by default: alerts in an incident first, then the kinds that are never
  kept quiet, then the highest score, then the newest.
* `GET /api/quiet/counters`, `GET /api/digest` and `GET/PUT /api/noise` read and change all of this
  (see the API reference); `/metrics` has `denis_alerts_quieted_total{kind,reason}` and `denis_digest_devices`.

Offline, `tools/noise/replay.py` replays this policy layer over an alert CSV export and
`tools/noise/anonymise.py` makes an export safe to share; neither writes inside the repository.

## Messages about enforcement actions

When DENIS blocks, quarantines, releases or extends something, or a block ends on schedule, every enabled channel
gets a message, whatever its minimum score and even in maintenance mode. The title says what happened
(`Blocked: laptop-anna`, `Released: …`, `Block extended: …`, `Block ended on schedule: …`, `Check: …` when the
change could not be confirmed). The lines name:

* the device: its name, the host name DENIS learned on your network, its IP address and MAC address;
* for a flow or an address outside your network: the address, its reverse DNS name, its country (a flag and the
  country code in chat and push messages, the country's name in e-mail and tickets) and the network owner. These
  come from the IP enrichment DENIS already keeps (Settings → Capture → IP enrichment): sending a message never
  waits for a lookup, and an internal address is never looked up. A reverse name that is not known yet is asked for
  in the background (at most 30 addresses a minute, only when reverse DNS is switched on), so it may be missing from
  the first message;
* the firewall or switch, the end time, who did it (a person, an automation policy, Autopilot or the schedule) and
  the reason that person wrote.

Two options per channel (**Edit…**): **Leave out the reason and the person** (for a channel many people read) and
**Shorter messages** (no MAC address, no network owner). With Pushover the message links to the action when DENIS
knows its own address (`--public-url`). PagerDuty folds every message about one action into one incident;
ServiceNow files each message as its own incident with the action's key as `correlation_id`. **Leave out the reason
and the person** also removes them from the details a generic webhook receives (`by`, `reason` and the like), and
the switch-port messages name the person only on their own *By* line.

## The notification centre

The bell in the top bar, between the light/dark switch and your account, lists what you should know: actions DENIS
took or could not confirm, blocks that were released, extended or ended, what automation or Autopilot did, the hourly
limit of actions being reached, a connector DENIS could not reach, changes to the kill switch, the lab switches and
the hands-off list, a site whose agent stopped reporting, a backup that failed, an update that is available or was
installed, the licence, and an MSP opening a remote session. A capture interface that goes down and comes back will
show here too.

* The number on the bell counts what you have not read (red when something needs action). A notice is read when you
  open it or choose **Mark all read**; opening the bell does not mark anything.
* **Show all** opens the full list with filters by category, severity and unread. Under **Show in the bell** you can
  hide categories from your own bell (the channels still send them). An MSP remote session is always shown.
* Everyone sees what their role allows on the sites they may read. Messages about enforcement and automation (what
  was blocked, by whom and why, on which firewall or switch, the hourly limit) are for administrators, like the
  action pages; editors also see capture interfaces and sites that stopped reporting; administrators see everything,
  including connector, licence, backup, update and MSP notices. A notice belongs to the site of the device, switch
  or connector it is about. Each MSP technician has their own read state and bell preferences, and marking read is
  allowed at the MSP's *Read* level.
* The same text goes to the channels. Repeats are folded into one entry with a count and are not sent again. An
  enforcement message is sent to every channel at once; other notices respect a channel's minimum score and
  maintenance mode, and purely informational ones (an update is available) are shown in the bell only. A channel
  gets at most 30 ordinary notices in ten minutes, then one message that more are waiting; enforcement and MSP
  messages (an MSP remote session included) are never held back by that limit and do not count toward it.
* PagerDuty: a notice that is not about an action or a device (a connector DENIS cannot reach, a site offline) uses
  its own key, `denis-notice-<key>`, and the notice that ends the condition (the site is back) resolves the incident.
  A recovery so short that DENIS shows it in the bell only does not resolve it, nor does a connector that answers
  again (its notice is closed without a message): resolve those in PagerDuty.
* A backup that fails is one notice a day. A site that was offline when DENIS restarted is still known to be
  offline; a site that is removed has its notice closed.
* Notices are kept for 90 days (one still in force, such as a site that is offline, until it ends).

## The generic webhook

The body is JSON:

```json
{
  "version": 1, "sent_at": 1789940568, "test": false,
  "event":  { "id": 42, "type": "new_port", "severity": "high", "score": 80, "timestamp": 1789940560,
              "summary": "…", "reasons": ["+40 …"], "details": { } },
  "device": { "id": 7, "name": "Reception printer", "ip": "10.0.0.5", "mac": "00:11:22:33:44:55", "site": null },
  "advice": "What to do about this kind of alert…"
}
```

A message about an enforcement action or another notice (see below) also carries `subject` (`asset_id`, `name`,
`hostname`, `ip`, `mac`, `external`, `action_id`), `title`, `lines` (`label` and `value`) and, when the console's
address is known, `link`. The fields above are unchanged.

If you set a **signing secret** (16+ characters) each request carries `X-Denis-Signature: sha256=<hex>`, the
HMAC-SHA256 of the exact request body. Verify it with a constant-time comparison before trusting the message,
and use `sent_at` to reject old replays.

## Security

* Webhook URLs, integration keys, SMTP passwords and signing secrets are **secrets**. They are stored in the
  database (protect it and its backups), are **never shown again** (the console only says "set"), never appear
  in logs or error messages, and are not written to the audit log. Use a channel's **Edit…** to change one —
  leaving a secret field blank on save keeps the one already stored.
* Slack, Teams and Discord URLs must be `https://`. Plain `http://` is accepted for a generic webhook to your
  own system (and for local testing). A password over SMTP with no encryption is refused.
* Text from the network (device names, hostnames) is escaped for each target so it cannot inject mentions or
  markup.

## Also available

* `--webhook <url>` on the command line: a simple Slack/Discord-compatible text webhook (older; the channels
  above are more capable and can be edited without a restart).
* [SIEM export (CEF/LEEF/JSON) and OpenObserve](export.md) for SIEMs and log platforms — it has its own, separate
  **Incidents** stream, alongside the per-channel grouping above.
* [Incidents](incidents.md): how related alerts get grouped in the first place, and what the priority on a grouped
  message means.

## Details from the console

Explanations that used to be printed on the console screens. The console shows a short version behind the small (i) button after the label it explains; "More in the docs" in it leads here.

* On (recommended): routine things such as a new address of a provider a device already uses are stored as quiet events, counted in the daily digest and never pushed, instead of becoming alerts. Nothing is deleted, and risky events (threat-list matches, rogue DHCP, port scans, industrial writes and the like) are never kept quiet. Off: every event is raised as an alert, as before.
* Off by default. When on, an unacknowledged low alert that has not happened again (same device, same kind, same provider) for the chosen number of days is acknowledged by the system, noted as closed automatically in its history and can be undone. Medium and high alerts, risky kinds and alerts in an open incident are never closed this way.
