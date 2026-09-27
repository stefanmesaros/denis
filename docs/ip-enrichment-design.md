# IP Enrichment System — architecture design (for review, no code yet)

Status: **design only**. Nothing in this document is implemented. It exists so the approach can
be reviewed before any code is written, per the explicit instruction to study DENIS's existing
patterns first and avoid a parallel architecture.

## 1. What this is for

For every **public** IPv4/IPv6 address DENIS shows anywhere (alerts, events, the asset panel's IP
history, top talkers, …), show — *when available, never fabricated*:

IP · reverse-DNS hostname · country · region/state · city · lat/long · ASN · AS organisation ·
ISP/network org · address classification (Public/Private/Loopback/Link-local/Multicast/Reserved) ·
data source. A click opens a detail panel with every field plus the GeoIP database's own version
and last-update date. Geolocation is always labelled "Approximate location", never a precise
physical claim.

Hard constraints from the brief, carried through every section below:
- **No per-event network calls.** Local MMDB lookup for GeoIP; a customer's own IP addresses are
  never sent to a third party per-event.
- **Never blocks ingestion.** Enrichment is best-effort and asynchronous; a slow/broken provider
  never delays or drops an event/alert.
- **Provider-swappable.** DB-IP Lite is the default, not the only option — a customer can point
  DENIS at their own MaxMind database, an internal GeoIP server, or a REST API.

## 2. Where this fits in the existing codebase (reused patterns, not new ones)

| Need | Existing pattern to copy | Reference |
|---|---|---|
| Versioned bundled data + optional refreshed data, "use the newer one" | `vulndata::Intel` — bundled `Data` compiled in, an `Overlay` kept in `SettingsStore`, a `static RwLock<Arc<Intel>>` cache reloaded after a refresh | `src/vulndata.rs:218-273` |
| Config a customer edits in Settings, admin-only, secrets never echoed | `AiConfig` — one `SettingsStore` key, JSON blob, a `Redacted` view for the API | `src/ai.rs`, `src/web_ai.rs` |
| A periodic background job that checks-and-maybe-refreshes | `vulndata::run()` — `tokio::spawn`ed once from `engine.rs`, `interval` tick, `spawn_blocking` for the actual work | `src/vulndata.rs:761` |
| A blocking check kept off the async runtime and neutered in tests | `health::dns_ok()` — a real DNS lookup in `spawn_blocking`, mutex-cached with a TTL, `#[cfg(test)]` returns a fixed value instead of touching the network | `src/health.rs:51-60` |
| Prometheus counters exposed at scrape time | `metrics::Exposition` + the `/metrics` handler building samples from live state | `src/metrics.rs`, `src/web/mod.rs:379+` |
| Where an outside IP already appears in an event's data | `detect.rs` builds `"destinations": [{"ip": ..., "proto": ..., "port": ...}]` inside `raw_details` (see `RULE_THREAT`, port-scan/volume-anomaly reasons) | `src/detect.rs:691,1665` |
| Store trait split by concern (`SettingsStore`, `MetricStore`, …), one `sqlite.rs` impl | `src/store/mod.rs` | — |

**Conclusion:** no new architectural style is needed. This becomes one more `Store`-backed,
`SettingsStore`-configured, `tokio::spawn`-scheduled module, following exactly the `vulndata.rs`
shape (bundled/local-first data, optional live refresh, in-memory cache reloaded after a refresh).

## 3. New module layout

```
src/ipenrich/
  mod.rs        — public API: EnrichedIp, Classification, enrich(ip) / enrich_batch(ips),
                  service handle wiring the pieces below together
  classify.rs   — private/loopback/link-local/multicast/reserved detection (pure, no I/O,
                  RFC1918/RFC4193/RFC3927/etc. ranges; uses the `ipnet` crate already a dependency)
  geoip.rs      — the GeoIP provider(s): local-MMDB (default), custom-MMDB, custom-REST,
                  the update/version-check/download/atomic-swap job
  dns.rs        — reverse-DNS provider: configurable resolver(s), timeout, on/off switch
  cache.rs      — the shared in-memory cache (separate GeoIP and rDNS TTLs), dedup-on-lookup
  provider.rs   — the `IpEnrichmentProvider` trait + `Capabilities`/`Status` types
web_ipenrich.rs — Settings GET/PUT, on-demand "enrich this IP" endpoint, DB update actions
```
`src/web/mod.rs` gains the routes and one `tokio::spawn(crate::ipenrich::geoip::run(store.clone()))`
line next to the other background jobs (`vulndata::run`, `switches::run`, …).

## 4. Provider abstraction

```rust
pub trait IpEnrichmentProvider: Send + Sync {
    fn name(&self) -> &'static str;
    fn capabilities(&self) -> Capabilities;      // { geoip: bool, asn: bool, rdns: bool }
    fn status(&self) -> ProviderStatus;          // ok / degraded / down, + a reason
    fn lookup(&self, ip: IpAddr) -> Option<PartialEnrichment>;      // never blocks > its own timeout
    fn lookup_batch(&self, ips: &[IpAddr]) -> HashMap<IpAddr, PartialEnrichment>; // default: map lookup()
}
```
`IpEnrichmentService` composes up to three independent providers (a GeoIP one, an ASN one — DB-IP
Lite ships country/city/ASN as three separate MMDB files, so one `MmdbProvider` instance per file
covers this rather than three separate trait objects) plus the separate `dns::Resolver`, and the
shared `cache::Cache`. This mirrors the brief's suggested
`IpEnrichmentService ├── DNSProvider ├── GeoIPProvider ├── ASNProvider └── Cache` while keeping
today's actual DB-IP Lite shape (country/city file, asn file) as one provider with two data files,
not two providers — simpler, same external behaviour.

Built-in providers at launch: `MmdbProvider` (local file, default: DB-IP Lite). Structurally ready,
not built yet: `CustomMmdbProvider` (customer's own MaxMind file, same trait), `RestProvider`
(configurable JSON field-path mapping, e.g. `$.country`), `InternalGeoipProvider` (a fixed base
URL). Adding one later is a new file implementing the trait plus a config variant — no change to
the trait, the cache, or any caller.

## 5. Data types

```rust
pub enum Classification { Public, Private, Loopback, LinkLocal, Multicast, Reserved, Unspecified }

pub struct EnrichedIp {
    pub ip: IpAddr,
    pub classification: Classification,
    pub hostname: Option<String>,          // reverse DNS
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub asn: Option<u32>,
    pub as_org: Option<String>,
    pub isp: Option<String>,
    pub connection_type: Option<String>,   // "hosting"/"residential"/"business", if the DB says so
    pub source: &'static str,              // "DB-IP Lite", "Custom MMDB", "Custom API", …
    pub db_version: Option<String>,
    pub updated_at: Option<i64>,
}
```
Every field is `Option`: absent means "Not available" in the UI, never a guess. `classify()` runs
before anything else and short-circuits GeoIP/DNS entirely for non-`Public` addresses (per the
brief: never geolocate a private/loopback/link-local/multicast/reserved address).

## 6. Configuration (`SettingsStore`, one key per concern — mirrors `ai`/`sso`)

```rust
// key "ipenrich.dns"
struct DnsConfig { enabled: bool, primary: String, secondary: Option<String>, timeout_ms: u32 }
// defaults: enabled=true, primary="1.1.1.1", secondary=Some("1.0.0.1"), timeout_ms=2000

// key "ipenrich.geoip"
enum GeoipSource { DbIpLite, CustomMmdb { path: String }, CustomApi { base_url: String, field_map: BTreeMap<String,String> }, InternalServer { base_url: String } }
struct GeoipConfig { source: GeoipSource, auto_update: bool }

// key "ipenrich.cache"
struct CacheConfig { geoip_ttl_secs: i64, dns_ttl_secs: i64 }
// defaults: 30 days, 24 hours — exactly the brief's numbers

// key "ipenrich.custom_api_secret" (separate key, like a channel's webhook secret: never
// round-tripped back to the browser in plaintext, same `Redacted` pattern as ai.rs)
```
Settings UI: a new **Settings → Network → Network Intelligence** box (reusing the existing
`network` category rather than adding a 7th sidebar sub-menu entry — `setup` just moved *out* of
Network this release, so there is room, and the brief's own path is "Settings → Network
Intelligence → DNS", i.e. a heading, not necessarily a new top-level category). Fields: DNS
Resolver, Secondary DNS Resolver, Timeout, Enable Reverse DNS toggle, GeoIP source picker, "Check
for update" / "Update now" buttons, last-updated date, and the DB-IP CC BY 4.0 attribution line
(also duplicated into a public "About" line, unauthenticated, like `branding` already is).

## 7. Cache

In-memory, not a new SQLite table: `DashMap<IpAddr, CacheEntry>`-style (or `Mutex<HashMap>` if a
new dependency is unwanted — `store/mod.rs` already avoids extra crates where std suffices) with
two independent TTLs (GeoIP 30d, rDNS 24h) checked per-field, so a hostname can expire and be
re-resolved without discarding the still-fresh GeoIP data for the same IP. A `dashboard`-style
in-process cache (not persisted) is enough to satisfy "central cache, not per-event" and "same IP
across many events costs one lookup" — it just starts cold after a restart, which is acceptable
(a MMDB lookup is a microsecond-scale local read either way). *Noted as a deliberate simplification
to flag for review* — persisting the cache in SQLite is a small follow-up if restarts turn out to
matter in practice (busy sites would otherwise re-resolve rDNS for up to 24h of traffic once).

## 8. Batch processing / dedup

`enrich_batch(ips: &[IpAddr])`: dedups via `HashSet` first (the brief's own example — 10,000
events, 500 unique IPs, 500 lookups), then for the *uncached* remainder, resolves GeoIP
synchronously (it's a local file read, no reason to defer) and enqueues rDNS lookups (which do
real network I/O) onto a bounded background worker fed by an `mpsc` channel — never awaited by the
caller. A caller that needs a specific answer right now (e.g. "open the IP detail panel") can
instead call a small, single-IP, directly-awaited path with its own short timeout, since a person
who clicked expects to wait a moment for one item, unlike bulk ingestion.

## 9. Non-blocking guarantee, timeouts, retry, circuit breaker

- GeoIP: a local `mmap`ped file read through the `maxminddb` crate (see §12) — no network, so no
  timeout/retry/circuit-breaker is meaningful here; the only failure mode is "database missing or
  corrupt", handled by falling back to "no GeoIP available" (never a panic, never blocking ingestion).
- Reverse DNS: every lookup runs in `spawn_blocking` with the configured timeout (default 2000ms);
  a background worker (not the ingestion path) drains the enrichment queue. After N consecutive
  timeouts/failures (e.g. 5) the resolver trips a circuit breaker — same shape as `health::dns_ok`'s
  cached-check idea, generalised: further lookups are skipped for a cool-down window (e.g. 60s) and
  answer "unavailable" immediately, instead of queueing up slow calls behind a resolver that is
  already down.
- Ingestion itself (`detect.rs`/`engine.rs`) never calls into `ipenrich` synchronously — it only
  ever *reads* whatever is already in the cache when building `raw_details`/API responses, and
  separately *enqueues* the IPs it just saw for the background worker to fill in. This is the
  concrete mechanism behind "must never block event processing".

## 10. GeoIP database lifecycle

- Storage: `<data-dir>/geoip/{country,city,asn}-<version>.mmdb`, a `current` pointer (a small JSON
  file or a `SettingsStore` key naming the active version) — same idea as `update.rs`'s program
  updater (backup kept, atomic switch, rollback on failure), scoped to data files instead of the
  binary.
- Update flow (admin-triggered or the periodic job, same shape as `vulndata::run`): check current
  version → compare against the source's latest → download to a temp path → verify (SHA-256
  checksum, published alongside the DB-IP Lite download, plus "does `maxminddb` parse it and find
  at least one expected field" as a sanity check) → atomic rename into place → record
  version + timestamp in `SettingsStore` → old file kept one generation back as a fallback → all of
  this with **zero DENIS downtime**: the in-memory reader holds an `Arc<Reader>` behind a
  `RwLock`/`ArcSwap`, swapped only after the new file is confirmed good, exactly like
  `vulndata::CURRENT`.
- Never any downtime because lookups always go through the same `Arc` snapshot pattern already
  used for `vulndata::current()`.

## 11. Reverse DNS

A small resolver client (see §12 for the crate choice) configured with the primary/secondary
servers and timeout from `DnsConfig`, supporting both A/PTR (IPv4) and AAAA/PTR (IPv6) — the brief
explicitly requires both address families. `enabled=false` short-circuits before any lookup is
even attempted (not just hidden in the UI). Failure of any kind (timeout, `NXDOMAIN`, resolver
unreachable) yields `hostname: None`, rendered as "Reverse DNS: unavailable" — never an error
surfaced to the person looking at an alert.

## 12. Proposed new dependencies (flagging for approval — everything else reuses what's already in `Cargo.toml`)

| Crate | For | Why not hand-roll it |
|---|---|---|
| `maxminddb` | Reading DB-IP Lite / MaxMind-format `.mmdb` files | Small, no_std-friendly, exact format DB-IP Lite ships; the wire format (a binary search tree + a custom data section) is enough of a spec to get subtly wrong that a maintained parser is worth the dependency, the same judgement call already made for e.g. `x509-parser`/`rcgen` instead of hand-rolled ASN.1/TLS. |
| `hickory-resolver` (client-only feature, no server) | Reverse DNS to a *configurable, arbitrary* resolver (not just the OS's), with a real per-query timeout | `std::net::ToSocketAddrs` only ever asks the OS resolver and cannot do PTR queries or per-query timeouts at all — this is a hard requirement (custom resolver + timeout), not a nice-to-have, so some DNS client crate is unavoidable. `hickory-resolver` is the actively maintained continuation of `trust-dns-resolver`, pure Rust, no C dependency (keeps the "offline build" story intact). |

Both are pure-Rust, no new C/system library dependency, consistent with the project's existing
choices (`rustls` over OpenSSL, etc.), and both are `--offline`-vendorable like everything else.

## 13. Detection-engine field exposure

`detect.rs`'s existing `"destinations": [{"ip": ..., "proto": ..., "port": ...}]` (and the
equivalent single-`"ip"` spots for `source`/`client`/`server`) gain sibling fields read from the
cache at *build* time (`ip.hostname`, `ip.country`, `ip.region`, `ip.city`, `ip.latitude`,
`ip.longitude`, `asn`, `as.organization`, `isp`, `ip.type`) — present only when the cache already
has an answer (best-effort, per §9). This gives rules access to `destination.ip.country` etc.
without a new event schema; it is additive to the JSON already there, so no existing rule or test
that reads `raw_details["destinations"][0]["ip"]` breaks.

## 14. Where this shows up in the UI (concrete pages, concrete components)

The brief's page names translate to DENIS's actual pages like this:

| Brief says | Actual DENIS page/component | What changes |
|---|---|---|
| Network Connections/Flows, Traffic | **Alerts** dialog (`showAlert`, `ui/app.js`) and **Events** table row detail — both already render `raw_details.destinations[].ip` | Each destination IP line gains the inline context (`Cloudflare, Inc. · AS13335 · US`) right under it, and becomes clickable → opens an IP detail panel (new small dialog, same `showMessage()` pattern already used for Software's device list) |
| Asset details | Asset panel's existing **"IP history"** list (`ui/app.js`, the `dl([...row('IP history'...)])` block) | Same inline line under each historical IP, same click-through detail panel |
| Threat detection | The `threat_list_match` alert specifically (already flows through the Alerts case above) | No separate UI — it is an alert like any other, so it is already covered |
| Volume anomaly details | The `volume_anomaly` alert's own dialog content | Same as Alerts, since it is the same `showAlert()` renderer |
| "Alerts, Events" | As above | — |

A shared `ui/ipenrich.js` (new, small) exports one function, `ipContextLine(enriched)` → the inline
DOM snippet, and `ipDetailDialog(enriched)` → the full click-through panel content (`showMessage`),
so every one of the above call sites is a one-line integration (`el('div', {}, ipInfo.ip,
ipContextLine(ipInfo))`), not five separate implementations — consistent with how `aiExplainButton`
and `sevTag` are already small shared helpers reused across pages rather than copy-pasted.

`GET /api/ip-enrichment/{ip}` (on-demand, single-IP, directly awaited per §8) backs the click-through
panel when the cache does not already have a fresh enough answer, so opening the panel can always
show a real answer rather than only whatever happened to be cached already.

## 15. Health/metrics surfacing

- `/metrics`: `ip_enrichment_total`, `ip_enrichment_cache_hits`, `ip_enrichment_cache_misses`,
  `ip_enrichment_errors`, `dns_lookup_total`, `dns_lookup_cache_hits`, `dns_lookup_errors`,
  `geoip_lookup_duration_seconds` (histogram or at least a gauge of the last/avg),
  `dns_lookup_duration_seconds` — all as `Exposition` samples built from a small
  `static ENRICH_METRICS: EnrichCounters` of `AtomicU64`s, the same shape as `frames_matched`.
- Settings/Health page: a small status block — "GeoIP: DB-IP Lite, version 2026-09, updated 3 days
  ago" / "Reverse DNS: 1.1.1.1, ok" or "…, unavailable (5 consecutive timeouts)" — living next to
  the existing Health page's other warning cards (`health.rs`'s pattern), not a new page.

## 16. Tests (mapped to the brief's list, plus where each one naturally lives)

`classify.rs`: valid/private/loopback IPv4+IPv6, invalid input, unspecified. `geoip.rs`: DB-IP
lookup (against a tiny fixture `.mmdb` checked into the repo, not the real multi-MB database — same
idea as `vulndata`'s bundled JSON being small and test-controlled), ASN lookup, provider failure /
missing file → graceful "not available". `dns.rs`: success, timeout, resolver unreachable (fake
resolver address), circuit breaker tripping after N failures, IPv4 and IPv6 PTR. `cache.rs`: hit,
miss, expired entry re-fetched, independent TTLs, concurrent lookups of the same IP coalesce to one
underlying fetch (a `tokio::sync::Notify`/in-flight map, standard dedup-in-flight pattern).
`mod.rs`/integration: duplicate-IP batch dedup (500 unique from 10,000 events), a full "10 events,
1 IP, 1 lookup" style test mirroring `top_talkers_sums_each_devices_destinations`'s style.

## 17. Open questions for you before implementation starts

1. **Settings placement**: reuse the existing "Network" category with a "Network Intelligence"
   sub-heading (§6), or add a 7th top-level sidebar category? (Recommendation: reuse Network —
   smaller change, and the brief's own wording is a heading, not a nav-level demand.)
2. **New dependencies** (`maxminddb`, `hickory-resolver`) — OK to add, or would you rather I hand-roll
   MMDB parsing / raw DNS packets to keep the dependency count at zero? (Recommendation: take the
   dependencies — this is exactly the kind of wire-format code the project already prefers a
   maintained crate for.)
3. **Cache persistence**: in-memory only (cold after a restart) vs. a new SQLite table for
   restart-durability. (Recommendation: in-memory for v1, revisit if it matters in practice.)
4. Anything in §14's page mapping that should instead go somewhere else, or any additional page you
   had in mind that isn't covered?

Once these are confirmed, implementation proceeds bottom-up: `classify.rs` → `cache.rs` → `dns.rs`
→ `geoip.rs` (with a fixture DB) → `provider.rs`/`mod.rs` wiring → Settings UI → the four UI call
sites in §14 → metrics → the full test suite in §16 — each layer built, tested and committed before
the next, same discipline as the rest of this session's work.
