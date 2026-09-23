# Alerting: getting alerts to your team

Alerts always appear in the console. **Alerting** (an administrator tab) also sends them out, so nobody has to
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
| **Generic webhook** | any URL that accepts a JSON POST | ServiceNow, Mattermost, Zapier, your own code. Optional signing secret |

Press **Test** on a channel to send a test message and see straight away whether it works.

## What gets sent, and when

* Only real alerts (not the low-level `info` events) at or above the channel's **minimum score**.
* **One message per alert**, unless more than five are waiting for a channel; then they go out as **one summary**
  listing the most serious. An alert storm never floods a chat room.
* A channel that is down does not lose alerts: it retries with a growing pause (up to 15 minutes) and catches up
  when it returns. Alerts older than 24 hours are dropped rather than sent late.
* A new channel starts from *now*; it does not replay history.
* **Maintenance mode** (Alerting tab): silence *all* channels for 30 minutes to 7 days during planned work. A
  banner shows on every screen while it is on, and alerts raised meanwhile are **not** sent afterwards.
* **Silence one device**: in a device's edit form, *Silence notifications until* a date (to the end of that day).
  The device's alerts still show in the console.
* Every change to channels and maintenance mode is in the audit log.

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

If you set a **signing secret** (16+ characters) each request carries `X-Denis-Signature: sha256=<hex>`, the
HMAC-SHA256 of the exact request body. Verify it with a constant-time comparison before trusting the message,
and use `sent_at` to reject old replays.

## Security

* Webhook URLs, integration keys, SMTP passwords and signing secrets are **secrets**. They are stored in the
  database (protect it and its backups), are **never shown again** (the console only says "set"), never appear
  in logs or error messages, and are not written to the audit log. To change a URL, add a new channel and delete
  the old one.
* Slack, Teams and Discord URLs must be `https://`. Plain `http://` is accepted for a generic webhook to your
  own system (and for local testing). A password over SMTP with no encryption is refused.
* Text from the network (device names, hostnames) is escaped for each target so it cannot inject mentions or
  markup.

## Also available

* `--webhook <url>` on the command line: a simple Slack/Discord-compatible text webhook (older; the channels
  above are more capable and can be edited without a restart).
* [SIEM export (CEF/LEEF/JSON) and OpenObserve](export.md) for SIEMs and log platforms.
