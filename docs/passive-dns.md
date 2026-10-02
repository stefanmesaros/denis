# Passive DNS

**Off by default.** When you switch it on (Settings → Network interfaces), DENIS reads the DNS
answers devices receive when they look up a name — for example `updates.vendor.example` — and
remembers which names each device looked up, for a retention period you choose (1–90 days, default
30, never longer than the general retention). Names then appear next to addresses in alerts, on
each device's own page, and in [Ask DENIS](tour.md)'s search ("which devices looked up
example.com?").

This is a privacy-sensitive feature. The names a device looks up can reveal what the people using
it do — the websites they visit, the services they use — in a way a bare IP address usually cannot.
Switch it on only where that is acceptable and your users have been told, and keep the retention
short. Names travel wherever alerts travel (notification channels, SIEM export, OpenObserve), since
they are attached directly to alert evidence.

## What DENIS can see: placement decides everything

Passive DNS only reads the responses that cross an interface DENIS actually captures on. An empty
name map on a plain switch-port install is the expected result, not a bug — check the Health card
(below) before assuming something is wrong.

| Where DENIS listens | What passive DNS records |
|---|---|
| A mirror/SPAN of the access switch, or of the router's LAN port | Every client's answers, from the local resolver and from outside resolvers. The full picture. |
| DENIS runs on the resolver itself (a Pi-hole host, a router box) | Every answer it sends — its own frames, deliberately accepted. Full picture. |
| A mirror of the WAN uplink only | Only the router's own upstream lookups. Every name is attributed to the **router** (it is the client on that leg) — accurate, but useless per device. |
| An ordinary switch port, no mirror | Nothing about other devices. The Health card explains why. |
| Any placement, clients using DoH or DoT (browsers' secure DNS, Android Private DNS, Apple encrypted DNS profiles) | Nothing for those lookups: they are HTTPS or TLS, not plain DNS. DoT shows up as a `tcp/853` flow edge but its contents are invisible; DoH not at all. `dns_resolver_changed` (below) is blind to a device that has moved entirely to one of these. |

Needs traffic accounting (`--flows`) or a mirror interface, the same requirement as
[east-west traffic](concepts.md#visibility-what-can-be-seen-from-where). Remote agents are switched
on with `--passive-dns`.

## Where names show up

* **Next to an address**, wherever one already appears with its network context (geolocation,
  reverse DNS): the alert dialog and Events view's *Network context* section, the device panel's
  *Recent destinations* (learned baseline) and *Investigate* section, and `talks-to`/`talked-to-by`/
  `contacted` in the API. Always worded **"looked up as `vendor.example`"**, never "is
  `vendor.example`" — a name row only promises that a device was *told*, at some point, that the
  name lives at that address, never that a later connection to that address *was for* that name.
  Addresses are reused and shared (a CDN, a cloud load balancer), so up to 3 names are shown, most
  recently looked up first.
* **In alert evidence** for `new_destination`, `new_destination_v6`, `new_port`,
  `threat_list_match`, `it_watch` and `segmentation_violation`: a `names` field next to the address,
  filled only when passive DNS looked something up for that exact (device, address) pair recently.
  Omitted entirely otherwise, so an install with the feature off — or an alert from before this
  feature existed — looks exactly as it always did. `dns_resolver_changed` itself (below)
  deliberately never includes names: the rule is about the resolver, and a sample of looked-up
  names in that one alert would export browsing data for no detection value.
* **The device panel's own "Looked up names" section**: every name recorded for that one device,
  most recently seen first, each tagged **contacted** or **looked up only** (see below).
* **Ask DENIS and `GET /api/relationships/contacted?name=`** — the domain hunt, below.

## The domain hunt

Ask DENIS a question naming a domain ("has anything talked to evil.example?", "which devices looked
up vendor.example?") and it runs the same hunt the address search runs for an IP or CIDR, just
keyed on the name instead. It accepts:

* `example.com` — the name and everything under it (subdomains included);
* `*.example.com` — only names *under* it, not the bare name itself;
* `=example.com` or `"example.com"` — only that exact name;
* a pasted URL (`https://evil.example/path`) — its host, the most common way to paste one.

If passive DNS has never been switched on anywhere this console can see, Ask DENIS says so plainly
("DENIS only knows which names devices looked up where passive DNS is switched on … and it has not
been on here. I can search for an IP address instead") rather than quietly searching for nothing.

**Looked up only vs. contacted is the most important distinction in the answer, and it is not
cosmetic.** Browsers prefetch names they never connect to, and a filtering resolver answers
`0.0.0.0` for a blocked name — recorded as "looked up, blocked". For a threat-indicator hunt,
"looked up a known-bad domain but never actually reached it" is still worth knowing: the device (or
something on it) tried. DENIS is told, in its own prompt, never to describe a mere lookup as
contact.

When coverage is partial — passive DNS is a per-collector setting — the answer notes that names are
only recorded on collectors that have it switched on, whenever at least one site you can read has
it off.

## The `dns_resolver_changed` alert

A device gets a DNS answer from a resolver address it has never used before, after its own resolver
set has had time to settle (learned silently for the normal learning period, counted from when
passive DNS first saw the device — not from when the device itself first appeared — so switching
the feature on does not instantly judge every device's pre-existing resolver). It judges only the
*change*, never which resolver a device uses on its own: a device that always asks the same address
never alerts for it.

Scoring, in words — base 40 points for a resolver this device has never used, then:

| the new resolver is… | points |
|---|---|
| a public address no other device on this network uses | +25 |
| a local device that is neither the gateway nor a DNS server your DHCP hands out | +15 |
| a well-known public resolver (Google, Cloudflare, Quad9, OpenDNS, and similar) | −10 |
| the DNS server your own DHCP server currently hands out (probably just a lease renewal) | −30 |
| already used by at least 3 other devices here (an established resolver) | −20 |

One alert per device every six hours; three or more devices switching to the *same* new resolver
within an hour are all recorded, but only the first three raise an alert — the rest get a note that
this looks like a deliberate network-wide change, alongside `dhcp_options_changed`. Firing this rule
suppresses the matching `new_destination` alert on port 53 for ten minutes, so one resolver change
produces one alert, not two plus a spurious combined incident.

*Typical false positive:* you (or the user) changed DNS provider, turned on a VPN client, or
replaced the router. The alert says so plainly in its "safe to ignore if" text, and no action is
needed when that is what happened. Otherwise, this is exactly how malware and DNS-changer attacks
redirect a device, so check its network settings and installed software, and whether the resolver
named in the alert actually belongs to you or your provider. See [Detection rules](detection-rules.md)
for the full entry, and [Incidents](incidents.md) for how it joins the "someone is trying to become
the network's gateway or DNS server" pattern alongside rogue DHCP/RA activity.

## Limits and retention

* At most 1,024 names per device, oldest and least-repeated evicted first — enough for roughly 2
  million rows across 2,000 devices, a manageable size.
* Capture, spool and ingest each have their own bound (visible on the Health page as rows recorded,
  evicted, and dropped at each one), the same shape as east-west traffic's own limits.
* A device that answers DNS for other devices too (a resolver of its own) has its *own* names
  excluded from recording — only the clients it resolves for are recorded, never the resolver's own
  traffic to upstream servers.
* Retention: 1–90 days, your choice, capped at the console's general retention. Pruned hourly like
  everything else.
* **"Delete all recorded names…"** (admin, with a confirmation dialog) erases every recorded name
  immediately. Switching the feature *off* does **not** delete anything already recorded — off
  means "stop recording", the delete button means "forget". They are kept separate so that
  switching off for a moment, by mistake or to pause collection, never destroys an investigation's
  evidence.

## API

See [API](api.md) for the exact shapes: `GET/PUT /api/interfaces/passive-dns` (the switch and
retention), `GET /api/assets/{id}/dns-names` (one device's own rows), `GET
/api/relationships/contacted?name=` (the hunt), `DELETE /api/dns-names` (the purge button), and the
`names` field that `talks-to`/`talked-to-by`/`contacted` and the baseline endpoints all carry.

## A note on personal data

In a home or small office network, which websites and services a device's user visits is personal
data, not just technical metadata — the same reasoning that applies to a web proxy's access log or
a router's DNS log. Passive DNS makes that log available inside DENIS. Before switching it on,
make sure doing so is acceptable where you operate it and that the people whose devices are on the
network have been told, the same as any other monitoring you introduce. Keeping the retention short
and switching it off (or deleting what has been recorded) when it is no longer needed are the two
simplest ways to limit how much of that data sits around.
