# netscope

Network asset discovery, fingerprinting and rule-based anomaly detection in one
Rust binary.

* **Phase 1**: passive + active discovery, OUI/mDNS/DHCP/SSDP/TCP fingerprinting, SQLite, local web UI.
* **Phase 2**: master/agent split, per-device baselines, three scored anomaly rules
  (new device, new destination, volume z-score), alerts with acknowledge, webhook notifications.

```
cargo build --release
./target/release/netscope run                       # standalone: UI on http://127.0.0.1:8080
./target/release/netscope run --flows               # + traffic rules (read "Traffic visibility" first)
./target/release/netscope alerts                    # alerts as a table
./target/release/netscope list                      # inventory as a table
./target/release/netscope interfaces                # what it can monitor (* = default)
./target/release/netscope run --passive-only        # listen only, transmit nothing
```

Linux build needs `libpcap-dev` (`sudo apt install build-essential libpcap-dev`).
macOS has libpcap in the SDK.

## Deployment shapes

```
                      ┌────────────────────────── master (one binary) ───────────────────────────┐
  small network:      │ embedded collector ─► inventory ─► SQLite ◄─ detector ─► alerts ─► webhook │
  just `run`          │                                        ▲                                   │
                      │  UI  127.0.0.1:8080 (no auth)          │ ingest 0.0.0.0:8081 (bearer token)│
                      └────────────────────────────────────────┼───────────────────────────────────┘
                                                               │ HTTP+JSON, agent → master (push)
                          second site / VLAN:  netscope agent ─┘  (collector only, outbound only)
```

* **`netscope run`** is the whole small-network deployment: collector, detector and UI in one process.
* **`netscope run --ingest-listen ADDR --agent-token …`** additionally accepts remote agents on a *separate*
  port. The UI stays on loopback without authentication; only the ingest port is meant to be reachable, and
  every request there needs the bearer token. (This answers Phase 1's "confirm before exposing anything".)
* **`netscope agent --master URL --token …`** is the same collector without the UI or detector. It pushes
  changed assets and 10-second flow summaries every 15 s. Push, so it only needs outbound access (NAT-friendly).

### Agent ↔ master protocol (HTTP + JSON, push)

`POST /api/v1/report` with `Authorization: Bearer <token>`; body = `{agent, run_id, seq, assets[], flows[]}`.

* Assets are **upserted by `(agent_id, mac)`** (the agent's local ids are ignored). The first report is a full
  sync; later ones carry only changes.
* Delivery is **at-least-once**: an unacknowledged batch is re-sent *unchanged*; the master remembers the last
  `(run_id, seq)` per agent (in SQLite, so it survives restarts) and acknowledges replays without re-applying
  them. A malformed batch (400) is dropped so the agent is never wedged; an unreachable master backs off to 5 min
  while up to 200k flow windows are spooled in memory (oldest dropped first).
* Chosen over gRPC because Phase 2 needs summaries every few seconds, not a stream; JSON over HTTP crosses NAT and
  proxies with no extra infrastructure and is trivial to debug.

**No TLS is built in.** The token and data cross the wire in clear text, so across anything but a trusted LAN
put the ingest port behind a tunnel (WireGuard, `ssh -L`) or a TLS-terminating reverse proxy. The agent's HTTP
client has rustls compiled in, so it should accept an `https://` master URL behind such a proxy (**untested**).

## Detection

Rules run at the master over per-device **baselines** (typical destinations, ports, outbound volume
mean/variance, active hours) built from flow summaries. Baselines are per `(agent, device)`; agents forward
summaries and do no judging.

| Rule | Fires when | Score (0-100) |
|---|---|---|
| `new_device` | an asset is first seen after the learning period, scored ~60 s later once fingerprinting had a chance | 50 base; +15 type unknown; +10 vendor not in IEEE registry; −15 private (randomised) MAC |
| `new_destination` | a mature device contacts an address it never has | 35 base; +15 nobody else on the network has; −10 same /24 as one it uses (CDN); +15 unusual port; +10/+20 ≥1 MB/≥50 MB sent; −10/−20 device already talks to ≥100/≥500 hosts; +1 per extra destination in the window (one alert per device per window) |
| `volume_anomaly` | outbound bytes in a bucket exceed the device's own mean by ≥ 3 std-devs (std floored at max(¼·mean, 1 MB)) | 40 + 10 × (z − 3) |

* **Every score carries its reasons** (shown in the UI and in the webhook payload).
* **Tuning without disabling**: `--rule-weight new_destination=0.5` scales a rule; `--min-score 40` sets what
  counts as an alert (below it the event is logged as `info`). Severity: ≥70 high, ≥50 medium, else low.
* **Learning period** (`--learning-minutes`, default 1440): a device, or a newly enrolled agent, is only judged
  after it has been observed this long; until then everything is learned silently. Volume needs ≥12 five-minute
  samples and ≥5 MB in the bucket. An incident is clamped when learned, so a spike doesn't become the new normal,
  and repeats for the same device are suppressed for 1 h.
* **Alerts** are stored, shown in the UI (acknowledge / undo), logged, and optionally POSTed as JSON to
  `--webhook URL` (`NETSCOPE_WEBHOOK`) when the score reaches `--webhook-min-score` (default 60). The payload has
  `text` (Slack) and `content` (Discord) plus the full event; delivery retries 3× and never blocks detection.
  Email/Slack-app integrations are Phase 4.

### Traffic visibility (read this before relying on the traffic rules)

`--flows` accounts traffic between a LAN device and the outside world, attributing outbound bytes by Ethernet
source and inbound by Ethernet destination. It can only count what **crosses the monitored interface**. On a
switched network a machine sees only its own traffic plus broadcast/multicast, so a collector on an ordinary
home server sees **only that server's traffic**. To cover the whole LAN the collector must sit where the traffic
passes: on the gateway/router itself, or on a **mirror/SPAN port**. `new_device` does not depend on this.
Only run one collector per L2 segment: two on the same segment report every device twice (I did this in
testing on purpose).

Destinations are IP addresses; DNS names are not captured yet, so CDN-heavy devices (phones, laptops) produce a
steady drip of low-score `new_destination` alerts. The churn dampener helps; for such devices raise `--min-score`
or lower that rule's weight. The rule is most valuable for quiet devices (NAS, cameras, printers, servers).
`active_hours` is collected but no rule uses it until Phase 3.

## Privileges

| | What is needed | Notes |
|---|---|---|
| **macOS** | Read access to `/dev/bpf*` | Works with *no sudo* when the user is in the `access_bpf` group (Wireshark's ChmodBPF job). A stock Mac needs sudo or an equivalent launchd job. |
| **Linux** | `CAP_NET_RAW` (+ `CAP_NET_ADMIN` for promiscuous mode) | `sudo setcap cap_net_raw,cap_net_admin=eip ./netscope`, or use the systemd units in `packaging/` (ambient capabilities, dedicated user). |

ICMP uses unprivileged datagram sockets where available and falls back to raw sockets.

## Ubuntu home server

```
sudo apt install build-essential libpcap-dev
cargo build --release          # build on the server; cross-compiling isn't set up
```

Then follow the header of `packaging/netscope.service` (master) and, for a second site,
`packaging/netscope-agent.service`. Put secrets in root-owned `0600` env files, not on the command line (visible
in `ps`). The UI binds to loopback; use `ssh -L 8080:localhost:8080 you@server`.

## Discovery (Phase 1)

| Technique | Kind | Yields |
|---|---|---|
| ARP request/reply/sweep | passive + active | MAC ↔ IP (the identity spine) |
| DHCP (67/68) | passive | hostname, vendor class, option list, confirmed lease |
| mDNS (5353) / SSDP (1900) | passive | hostnames, service types, models, server strings |
| TCP SYN / SYN-ACK, ICMP echo | passive + active | TTL, window, option order → OS family |
| TCP connect scan | active | open ports (33 common, not 65535) |

Device type / OS is a weighted rule-vote (`src/fingerprint.rs`); the UI's "Why this guess" lists every rule that
fired. The IEEE OUI database is compiled in. IPv6 is ignored.

## Defaults (chosen, not given)

| Setting | Default | Flag |
|---|---|---|
| Scope | one IPv4 subnet per collector, ≤ 1022 hosts (larger clamped to our /24) | `--iface` |
| ARP sweep / port re-scan | every 300 s (2 passes) / per host at most every 1800 s | `--sweep-interval`, `--rescan-interval` |
| Port scan | 33 ports, 800 ms timeout, 64 concurrent connects (macOS default fd limit is 256) | — |
| Flow windows / agent reports | 10 s windows, report every 15 s (heartbeat ≥ every 60 s) | `--report-interval` |
| Volume bucket / trust | 300 s buckets; ≥12 samples; ≥5 MB; z ≥ 3 | `--bucket-secs`, `--min-samples`, `--min-volume-mb` |
| Learning period | 24 h | `--learning-minutes` |
| Alert threshold / webhook | 30 / 60 | `--min-score`, `--webhook-min-score` |
| Memory bounds | 2000 destinations per device; 50k flow keys per window; 5000 assets and 100k flows per report | — |
| Retention | unbounded (events and baselines are small) | — |
| Web UI | `127.0.0.1:8080`, no auth, Host-header + CSRF-header guards + strict CSP | `--listen` |

## Verified vs. not

Verified (macOS 26, Apple Silicon, Wi-Fi `en0`, a /24 with ~40 devices):
* **92 unit tests** (parsers on hand-built and hostile frames, fingerprint rules, inventory, SQLite incl. an
  in-place Phase 1 → 2 migration, detector rules and scoring, ingest idempotency/auth, reporter state machine,
  web API, webhook delivery). `cargo clippy` clean.
* **Two real processes** (master + agent) over HTTP on this Mac: enrolment, auth (401 without/with a wrong
  token; ingest not reachable on the UI port), incremental sync, alerts tagged with the agent id, live
  `new_destination` alerts for hosts contacted after the learning window, graceful SIGINT shutdown, baselines
  and dedupe state surviving a master restart, ack in the UI, webhook payload received by a local listener.
* **`volume_anomaly` through the real ingest endpoint** with a synthetic site (40 MB vs a 4 MB baseline → 100/high;
  a replay of the same batch ignored, also across a restart).

**Not verified:**
* **Linux at runtime**, and the systemd units (only `net.rs` type-checks for `x86_64-unknown-linux-gnu`).
* **Agent ↔ master across a real network**: only loopback so far. **No TLS, no rate limiting on failed tokens.**
* **Volume rule on real traffic** (synthetic only: producing an outbound spike safely needs a destination I control).
* The **traffic rules on a whole LAN**: the Mac only sees its own traffic (see above).
* DHCP/SSDP on real traffic, wired/promiscuous capture, VLAN tags, IPv6 (ignored).
* **Postgres**: not built (I could not run one here). `Store` is the seam; SQLite serves a single master fine
  at home/SMB scale (a few thousand devices).

## Layout

```
src/parse.rs        frame bytes → Observation / FlowSample (pure, tested)
src/flow.rs         per-window flow aggregation (capture thread)
src/capture.rs      libpcap thread, kernel filter, throttling
src/active.rs       ARP sweep, ICMP, TCP scan
src/inventory.rs    Observation → Asset, revision tracking for agent deltas, guess re-derivation
src/fingerprint.rs  OUI + rule-vote guess, scan port list
src/detect.rs       baselines, the three rules, scoring, learning period
src/notify.rs       persist / log / webhook
src/ingest.rs       master side of the agent protocol (+ token-guarded router)
src/agent.rs        agent reporter (batching, retry, spool) + HTTP client
src/engine.rs       shared collector; `run` (standalone/master) and `run_agent`
src/store/          `Store` trait + SQLite (schema v2, transactional migrations via user_version)
src/web.rs          JSON API + embedded UI (rust-embed, no build step)
```

## Security notes

Hostnames, mDNS names and SSDP strings are attacker-controlled: parsers bounds-check and strip control
characters, and the UI builds DOM nodes with `textContent` (never `innerHTML`) under a strict CSP. The UI has no
authentication, so it validates `Host` on loopback binds (DNS rebinding) and requires an `X-Netscope` header on
POSTs (CSRF). **Do not bind the UI to a non-loopback address.** Agents are trusted once they hold the token
(they choose their `agent_id`); a stolen token lets someone inject devices and flows into the master.
