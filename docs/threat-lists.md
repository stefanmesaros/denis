# Threat lists

Threat lists are lists of addresses, networks, domain names and web addresses that you add yourself, next to the sources
under *Settings → Software data → Threat list sources*, read from a file you paste or upload, from a web address, from a TAXII 2.1
server or from a MISP feed. DENIS ships no list and fetches nothing from a list you did not create. Lists you add are your
responsibility. This page describes what exists in this version: the lists, their limits and their settings API, the screen
where you manage them, the formats and the fetching rules, the detection rules that use them, and what it costs. Blocking from a
list comes in a later step; the screen already stores the choice of action.

## Lists, limits and the settings API

**A list** has a name (1 to 60 characters, unique without regard to case), a source, an action and a few settings.

| Setting | Meaning | Default |
|---|---|---|
| Source | `paste`, `file`, `url`, `taxii` or `misp`: where the entries come from | none, you choose |
| Action | `alert`; `prepare_block` (alert and prepare a block that waits for approval); `auto_block` (automatic blocking, **Experimental**) | `alert` |
| Refresh interval | 15 minutes to 30 days, for the sources that are fetched | daily |
| Age limit | days after which an entry that is not seen again, and has no expiry of its own, stops counting; 0 never | 30 |
| Entry types | which of address, domain and url the list may hold | all |
| CSV column | for the `csv` format: the column that holds the entries, a header name or a position from 0 | the first |
| Allow internal address | the address the list is fetched from may be inside your network | off |
| Allow plain http | the address the list is fetched from may be `http` | off |
| An HTTPS address counts as its host | see "What a sensor can see" | off |
| A bare domain also covers below | see "Entries" | off |
| Score | the score of an alert from the list | 80 |

The action is stored and shown. The detection rules create the alert, and for `prepare_block` and `auto_block` queue a prepared block (see "Rules" and "What a block from a list does"). The list's status shows when it was last fetched,
the last error, how many entries of each kind it holds and how much memory the compiled index uses.

The API gives each list one `state` with a `reason` and `next_actions` (4.5): `all_off` (the global switch is off; next action
`enable_lists`), `off` (`enable`), `fetching`, `problem` (`refresh` or `send_entries`, and `edit`), `waiting_first_fetch`
(`refresh`), `no_entries` (`send_entries`), `rule_off`, `stale` and `working`. `rule_off` is said in place of `working` when no
detection rule that uses the list's entry types runs: reason `rule_not_switched_on` for a rule that is new in this release and
nobody switched on yet (on an upgrade the three list rules arrive off), `rule_switched_off` for one switched off; next action
`open_rules`. One rule that runs is enough (a list of names and addresses with the address rule on is not `rule_off`). `stale` is
said in place of `working` for a fetched list whose last successful fetch is older than three intervals and an hour (reason
`no_recent_success`, next action `refresh`); a pasted or uploaded list is never stale.

**Limits** (you can lower the total, you cannot raise any): 100 lists; 500,000 entries in one list; 2,000,000 entries over
all lists; 64 MiB of entry text in one list; a fetch downloads at most 32 MiB. A write that would pass a limit is refused
whole and the old entries stay. About memory and speed see "What it costs".

**Credential.** A list that needs one (a token, an API key or `user:password`) stores only the *name* of a sealed secret,
`threat_list.credential.<id>`. The secret is sealed like every connector secret, left out of a backup by default (the
restore notice asks for it again), never returned by the API, and never written to a log line or an audit entry. It
is set by an administrator in the console, not with an API token, and never over the MSP management channel. The address
a list is fetched from is shown without its query string, because a token is often there, and may not contain a user name
or password; over the MSP management channel a path segment that looks like a token (long, letters mixed with digits) is
shown as `***` as well. **A credential is only sent over https**: a list with a plain `http` address cannot have one
(creating it with one, setting one, or a "Load collections" call with one is refused with a sentence that says so, and a
list that still has one from an earlier version is not fetched until the address is https or the credential is removed).
Before 4.5.0 the credential of a list ticked "allow plain http" was sent over plain http. The address of a TAXII server or
of a MISP feed (not of one exported `.json` event) has no query part, because the requests that follow are built from it
without the query: put a key in the credential field.

**Entries.** Every entry is stored in one canonical form, so the same thing written two ways is one entry:

* *Address and network*: `203.0.113.9`, `198.51.100.0/24`, `2001:db8::/48`. Host bits of a network are cleared, `/32` and
  `/128` are single addresses, an IPv4-mapped address is the IPv4 address, `/0` is refused, a network wider than a `/8`
  (IPv4) or a `/16` (IPv6) is refused as "too wide" (one bad line would cover a large part of the internet), and so are the
  unspecified, loopback, multicast and broadcast addresses.
* *Domain*: lower case, no trailing dot, international names in Punycode (`bücher.de` is `xn--bcher-kva.de`).
  `*.example.com` and `.example.com` mean the name and everything below it; a bare name means the name only, unless the
  list ticks "a bare domain also covers below". A name listed both bare and with `*.` is one entry that covers what is below
  it, whichever comes first, in a refresh and in an incremental pull alike. A single label (`com`) and a public suffix (`co.uk`) are refused, so one
  bad line cannot match every name. The international-name mapping is simplified (no full UTS 46 table): names it does not
  map are refused or kept as written, never matched as another name.
* *Web address*: only `http` and `https`. Host in lower case, default port and fragment dropped, user name and password
  dropped, the path normalised and a trailing slash dropped. Without a query, an entry covers its path and everything
  below it; with a query, only that exact query.

Entries that can be refused are counted by reason, never silently dropped.

**What a sensor can see.** A sensor sees the name in a DNS answer, the server name of a TLS connection when it is not
hidden, and the host and path of a plain-HTTP request. It cannot see the path of an HTTPS request. An `https` web address
therefore matches nothing, and the list shows how many it holds. Ticking "an HTTPS address counts as its host" makes the
host of such an entry an exact name (or an address) instead.

**Matching.** The enabled lists are compiled into one read-only index that is swapped in whole when it is rebuilt, so
a lookup never sees a half-built list. A name matches on label boundaries (`notevil.com` never matches `evil.com`); the most
specific entry wins, and at the same name the list that was created first.

**Settings API.** See [the API page](api.md): `GET/PUT /api/threat-lists` (the switches, the limits and every list),
`POST /api/threat-lists`, `GET/PUT/DELETE /api/threat-lists/{id}` and
`PUT/DELETE /api/threat-lists/{id}/credential`, `POST /api/threat-lists/{id}/test` and `.../refresh` (see "Refreshing and ageing"),
`POST /api/threat-lists/{id}/entries` (see "Pasted and uploaded lists") and `POST /api/threat-lists/collections` (see "Choosing
TAXII collections"). They are the administrator's, reads included; an API token reaches
none of them; creating or changing a list, and every credential, are refused over the MSP management channel.

## Formats

Every format is read the same way: the list is checked against its limits, each entry is kept as the
list gave it (trimmed, defanged, bounded) and handed to the normaliser, and whatever cannot be used is
**counted by reason** and shown after a fetch ("12 lines: not an address, network, name or URL"). One bad
line never fails the list. A list that cannot be read as a whole (not the JSON the format needs, cut off
in the middle, nested too deep, over the size limit) fails, and the previous set stays in use.

Limits that apply to every format (the console can lower them per list, never raise them):

| Limit | Value |
|---|---|
| Download or file size (after decompression) | 32 MiB |
| Entries per list | 500,000 (more are dropped and the list is marked cut off) |
| One value | 4 KiB |
| One text line | 8 KiB (longer lines are skipped without being read) |
| JSON nesting | 16 levels |
| CSV columns looked at | 64 |
| TAXII pages per fetch | 100 |
| MISP events per fetch | 1,000, each at most 5 MiB |

Text must be UTF-8; a line that is not is skipped. A byte order mark and Windows line endings are fine.

### Plain text

One entry per line. Accepted: an IPv4 or IPv6 address, a network in CIDR notation (`203.0.113.0/24`), a DNS
name, a URL with a scheme (`http`, `https`, `ftp`) or without (`bad.example/path`), `address:port` and
`name:port` (the port is dropped), `*.example.com` and `.example.com` (the name and everything below it), and
hosts-file lines (`0.0.0.0 bad.example`, every name after the address is taken; `localhost` and the like are
skipped). Defanged forms are read as the real thing: `hxxp://`, `hxxps://`, `evil[.]example`, `evil(.)example`,
`evil[dot]example`, `[:]`, `[://]`.

Comment lines start with `#`, `;` or `//`; ` # note` or ` ; note` after an entry is cut off. Only the first
token of an ordinary line is used. Skipped and counted: lines that are too long or not UTF-8, single-word
names (`localhost`, hashes), invalid addresses (`999.1.1.1`), other URL schemes (`javascript:`, `file:`).

### CSV and other delimited text

Pick the column that holds the indicator by **header name** (any case) or by **position** (from 0); optionally
a column for a label and one for an expiry time (RFC 3339 such as `2030-01-01T00:00:00Z`, `2030-01-01 10:00:00`,
or Unix seconds). The delimiter (comma, tab, semicolon, pipe) is detected unless you set it. The header row
is detected when you pick by name, or when the first row's cell is not an indicator; you can also say there is
one or is not. A header written as a comment just above the data (`# first_seen,dst_ip,...`, as some public
feeds do) is understood when you pick by name. You may restrict the list to one kind (all values of other
kinds are then skipped).

Fields can be quoted (`"a,b"`, `""` for a quote). A record is one line: a quoted field that runs over a line
break is not supported. Cells are text, never evaluated: a cell that starts with `=` or `@` is just a value that
is not an indicator and is skipped. Rows with too few columns are skipped and counted.

### STIX 2.1

A bundle (`{"type":"bundle","objects":[...]}`), the `objects` of a TAXII answer, or an array of objects. Only
`indicator` objects are used, and only network indicators. The pattern is read by a small reader that knows:

* `[ipv4-addr:value = '198.51.100.1']`, also with a network (`'198.51.100.0/24'`) or `ISSUBSET '...'`,
* `ipv6-addr:value`, `domain-name:value`, `url:value`,
* `IN ('a.example','b.example')`,
* `OR` between comparisons inside one bracket or between bracketed expressions. A branch that is something
  else (a file hash) is counted and the readable branches are kept.

Patterns the reader cannot read are **skipped and counted, never guessed**: `AND` and `FOLLOWEDBY` (a combination
is not an indicator by itself), `NOT`, `!=`, `LIKE`, `MATCHES`, parentheses, time qualifiers (`START ... STOP`),
file hashes, processes, registry keys, and values that do not fit their type. Also skipped and counted:
`revoked` indicators, deprecated ones (`x_mitre_deprecated`, `deprecated` true, or the label `deprecated`), a
`pattern_type` other than `stix` (Snort, YARA, ...), expired ones (`valid_until` in the past), and, if you set a
minimum, those with a lower `confidence` (indicators without one are kept). `valid_from`, `valid_until`,
`modified`, `confidence`, `name` and the object id are carried along.

### TAXII 2.1

Give the discovery address (`https://taxii.example/taxii2/`) or the API root directly, and optionally the
collection (id or title; if the server has exactly one readable collection it is used). DENIS asks with
`Accept: application/taxii+json;version=2.1`, follows `more` / `next` page by page, and sends `added_after`
after the first full fetch so only new objects come down. A collection bigger than one pull (100 pages, 32 MiB or
120 s) is loaded in parts: what one pull read is stored, the answer and the job's log say the list is **only partly
loaded**, and the next pull continues after the last page read (`added_after` of that page), until the collection is
read through. A pull cut that way without a date to continue from changes nothing and says why. It stops as soon as
the entry limit is reached instead of reading the remaining pages. Credentials: basic, bearer token or an API key
header. They are sent only to the host you gave; an API root on another host is asked without them.

### MISP feed

Two layouts. The **feed layout** is `manifest.json` plus one `<uuid>.json` per event (give the address of the
manifest or its folder); events are read newest first, and a later fetch reads only events changed since the
last one. One pull reads at most the 1,000 newest events: a feed that lists more is stored with those, the answer and the
job's log say it is **only partly loaded**, and the later pulls read the events changed since the newest one read (the
older events are not read, as for the entry limit). A **single event or attribute export** is read directly: `{"Event":{...}}`, `{"response":[{"Event":...}]}`,
`{"Attribute":[...]}`, `{"response":{"Attribute":[...]}}` or a plain array of attributes. A single element of the document
(an event wrapper in a plain array, say) may hold at most 200,000 nested attributes, objects and events; a document beyond
that is refused ("a MISP event holds more nested elements than the limit") and, in a feed, that event file counts as one that
could not be read.

Attribute types used: `ip-src`, `ip-dst`, `domain`, `hostname`, `url`, and the composite `ip-src|port`,
`ip-dst|port`, `hostname|port` by their first part, and `domain|ip` by both parts (the name and the address). Attributes inside event objects are included.
Only attributes with `to_ids` set are used unless you switch that off for the list; deleted attributes are
skipped. Other types (hashes, e-mail, ...) are counted as "attribute type not supported". The attribute's
`timestamp` is kept for the age limit. The MISP REST search, OpenIOC, RPZ zone files, Suricata/Snort rules and
hashes are not read in this version.

## Pasted and uploaded lists

A list with the source `paste` or `file` has no address: an administrator sends its entries, as text pasted into the console
or a file chosen on the computer (`POST /api/threat-lists/{id}/entries`, the body of the request is the text or the file;
a `file` list's `path` is only the name the console shows, DENIS reads no file on the machine). The entries go through the
reader of the chosen format (`?format=`, default the list's own: `auto` detects plain text, STIX or MISP; a CSV list uses its
`csv_column`), the normaliser, the list's entry types and age limit, and then the same one-transaction write and index swap
as a refresh. `?mode=replace` (the default) makes the body the whole list, `?mode=add` adds to what the list has, `?column=` names the
CSV column for this call only, `?dry_run=true` reads and counts and changes nothing. The limits are the ones of a fetched list: 32 MiB per body (`413` above), 500,000
entries in a list, 2,000,000 over all lists. A body that cannot be read, has no usable entry or would pass a limit changes
nothing: the old entries stay, the answer says why (`ok: false`) and the list shows the error. At most ten manual calls
(test, refresh, entries, collections) a minute. The audit entry (`threat_list.entries`) holds the list id, the mode, the size,
yes or no and the counts, never a byte of the content. Only a form-less body is accepted (`415` for `multipart`): the console
sends the file itself.

## Choosing TAXII collections

`POST /api/threat-lists/collections` asks a TAXII 2.1 server which collections it has, for the "Load collections" button.
The body is `{"url", "credential"?, "allow_http"?, "allow_internal"?}`; the answer lists `id`, `title`, `description` and
whether the account can read it. Nothing is stored (no list, no setting, no secret), the address and the credential are in no
answer and no audit entry, and the call uses the same fetcher and address rules as a list, with the two ticks given for this
call. The console then adds each ticked collection as a list of its own, with the credential sealed once per list.

## Using the screen

*Settings → Software data → Threat list sources*, under the built-in sources (abuse.ch, Spamhaus, Tor), the group
**Your own lists**. Administrators only; an editor or a viewer sees a short note instead.

**The top.** *Use my own lists* is the switch for all your lists (off: nothing is matched or fetched, the lists and their
entries stay). Under it a line says what the switch costs: the memory in use right now, taken from the matching table
(`index.memory_bytes`), and the measured figures of "What it costs" below. Then *{n} of {max} entries used* against the
ceiling, a bar, the memory for matching, and how many of the 100 lists exist. A note says that a list only does something
when a detection rule uses it, with a button to the Rules page where the rules for lists wait, off, until you switch them on.

**The table.** One row per list: *Name* (with its address without the query, or the collection id), *Source*, *State*
(*Working*, *Off*, *Fetching now*, *Waiting for the first fetch*, *No entries yet*, *Problem at the last fetch* with the
short error, *Not used: the detection rule for this list is off* with a button to the Rules page, or *No successful fetch for a
long time*; the *On* tick next to it switches the list), *Last fetch*, *Entries* (by kind; `https` addresses are counted
because a sensor cannot match their path), *Action* (*Alert only*, *Alert and prepare a block*, *Automatic block* with the
Experimental mark), *Next fetch* and *Memory* (the list's share of the table, an estimate). A narrow screen shows each list as
a card. Buttons per list:

* **Test** fetches and reads the list and shows what it would keep and what it would skip, by kind and by reason, with a few
  samples without query parts. It changes nothing. For a pasted or uploaded list it opens the entries dialog, whose
  *Test (change nothing)* does the same for the text or file you give.
* **Refresh now** fetches at once (web address, TAXII, MISP). **Send entries** (pasted and uploaded lists) replaces or adds
  to the entries.
* **Edit** changes everything but the source kind. The address and the credential are write-only: the dialog shows the address
  without its query and never the credential; *Keep the saved credential* is the default, *Remove* and *User name and
  password* / *Key or token* change it. A credential belongs to one server: when an edit points the list at another server
  (another scheme, host or port in the address) or another kind of source, the saved credential is removed and the list is
  switched off (`credential_cleared: true` in the answer); enter the credential for the new server and switch the list on
  again. A change of the address, the kind, the collection, the format, the CSV column, the entry types or the two reading
  choices makes the list due at once and its next pull a full one, without validators or cursor (`source_changed: true`);
  when the source itself changes (address, kind or collection) the entries of the old source are removed.
* **Delete** asks first and says what goes: the list, its entries and its credential.

**Add list.** Choose where the entries come from:

* *Web address*: the address of a file, optionally with a user name and password or a key; the format (detected, plain text,
  CSV with the column, STIX, MISP).
* *TAXII 2.1 server*: the address of the server, optionally the sign-in, then **Load collections**. The server's collections
  appear with a tick each (*Tick all*; one the account cannot read is greyed out); every ticked collection becomes a list of
  its own, named *server name – collection title*. If the server will not list its collections, a collection id can be typed.
* *MISP feed*: the address of the feed or of one exported event, optionally the key.
* *Pasted text* and *Uploaded file*: the entries; if nothing can be read from them the list is not created.

For every list: the name; which entries it may hold (addresses and networks, domain names, web addresses); **what a match
does** (*Alert only*, the default; *Alert and prepare a block*, which waits for approval; *Automatic block*, Experimental,
with a warning, off unless chosen); how often to fetch (15 minutes to 30 days); the age limit in days; **Allow an address
inside my own network** (off, and the dialog says why: DENIS refuses addresses that lead into your own network so that a list
address cannot be used to make DENIS reach your other devices; turn it on only for a server you run inside it, such as a MISP
server); **Allow plain http** (off, with the warning that a list fetched without encryption can be changed on the way). Under
*More options*: a bare domain also covers everything below it, and an https address counts as its host. Next to every switch a
grey line says what it costs; the figures come from "What it costs" and the live numbers of the API, none is estimated by the
screen. Alerts come from the rules for lists on the Rules page; what a prepared block does is described under "What a block from a
list does".

## What a block from a list does (4.5, Experimental)

A list whose action is *Alert and prepare a block* turns each matched entry into **one prepared block** in *Waiting for your approval*
(Respond; at most 50 waiting; closed after the usual days without approval). It never executes by itself: you open it, read the plan
and give your password.

* A listed **name**: *Block domain* on the firewall or router that can block by name (FortiGate, Palo Alto, MikroTik; UniFi and Omada
  cannot, see [Enforcement](enforcement.md)). It is a **network-wide** block: all devices behind that equipment, not only the device
  that visited the name. When no equipment can block the name, the prepared block is the **addresses** it resolves to, as a connection
  block from the device that asked, labelled **addresses only, may change**, with how many other names passive DNS saw on the same
  addresses; the plan carries the warnings you tick.
* A listed **plain-HTTP address**: a name block with the path, only on equipment with a URL object (PAN-OS), only for HTTP. Nothing is
  prepared when none exists. An HTTPS address with a path matches nothing and blocks nothing: the site can be blocked by its name.
* A listed **address**: the existing connection block from the device to it.
* DENIS never prepares a block of a name it protects (its own endpoints, public resolvers, the connector's own name, your protected
  names).

A list set to *Automatic block* applies a **name** block by itself, **Experimental and off by default**: only while automatic
enforcement is on with both lab switches, on equipment that offers the name block, for a limited time, within the hourly limit of
automatic actions, at most once per name per day, and never when the plan has a warning or a refusal (so never the address
fallback). Each is audited (`nac.automation.lists.run`) and announced with an undo link.

## Fetching safely

Every list fetched over the network goes through one fetcher with fixed rules:

* **https** unless you tick plain http for that list (the console warns: an unauthenticated plain feed can be
  altered on the way). No other scheme; no credentials inside the address.
* The name is resolved once and DENIS connects to the address it checked, so a name cannot be pointed at an
  internal address between the check and the connection. Loopback, link-local (including the cloud metadata
  address), private, multicast, unspecified, reserved, shared (carrier-grade NAT) and unique-local addresses are
  refused, also when written as IPv4-mapped IPv6 or NAT64 / 6to4, **unless you tick "internal address" for that
  list** (a MISP server inside your network is a real case). If a name has several addresses and one is refused,
  the name is refused.
* At most 3 redirects, every target checked again, never from https to http. A credential is sent only to the
  host the list was set up with, not to a redirect target, and only over https.
* A name lookup takes at most the connect timeout and never runs past the total time limit of the fetch.
* One total time limit (120 s) and a size limit that is applied while the answer streams; a compressed answer
  (gzip) is limited after decompression, so a "zip bomb" is stopped at the limit.
* The next fetch asks "has it changed?" (`ETag`, `Last-Modified`) and a 304 answer leaves the list as it is.
* Credentials are never printed, logged, put in an error message or an audit entry; error messages carry a class
  (`refused`, `timed out`, `server answered HTTP 503`) and never the address or its query string.
* No proxy from the environment is used for list fetches, because it would move the connection away from the
  address that was checked.

## Refreshing and ageing

**The schedule.** DENIS looks at the lists once a minute (a local look; the network is touched only for a list that is
due). A list that is fetched from the network is due when its refresh interval has passed since the last attempt; each
list is spread by a fixed offset of up to 5 percent of its interval, so lists with the same interval do not all fetch in
the same minute. After a failed fetch the wait is 15 minutes, doubles with each further failure, and never exceeds the
interval. Only one fetch of a list runs at a time. On a high-availability pair only the leader fetches; the other
node runs nothing, and a node that takes over builds the matching index from the stored entries first and then
continues. A list you switched off, or all lists switched off, is not fetched. The address, the credential and the
allowed internal address or plain http come from the list's own settings only.

**One refresh.** DENIS fetches the list, reads it by its format (`auto` looks at the first bytes: STIX, MISP or plain
text; a TAXII list is read with the TAXII client and a MISP list with the MISP feed reader, or as one export when
the address ends in a `.json` file other than `manifest.json`), normalises every entry, keeps the entry types the list
allows, drops what has aged out, cuts the list at 500,000 entries, and writes the whole set in **one transaction**. The
matching index is rebuilt off the hot path and swapped in whole. It records the time, the size and the validators
(`ETag`, `Last-Modified`). A CSV list is read from its `csv_column` (a header name or a position from 0; empty: the first column). A `user:password` credential is sent as basic authentication, any other as a bearer token; for a MISP list the
key is sent as MISP's `Authorization` header. A list with the source `paste` or `file` is not fetched: its entries are sent (next section).

**When something goes wrong the old set stays.** A failed fetch, an answer that cannot be read, a source that gives no
valid entry, a pull that stops at a page, time or size limit with nothing to continue from (a TAXII server that gives
no date; see "TAXII 2.1" for the one that does), a set that would pass a limit (100 lists, 500,000 in one list,
the total ceiling over all lists, 64 MiB of entry text): nothing is changed, the list keeps being used, and the list
records a short error, for example `fetch: server answered HTTP 503`, `fetch: timed out`, `parse: no valid entries` or
`limit: ...`. The error never holds the address, a query string or the credential. The list shows when it last worked
(`last_ok_at`), the last error and when it is next due (`next_fetch_at`).

**Unchanged sources.** The next fetch of a single file asks "has it changed since this `ETag` / `Last-Modified`?". On
"no" the entries stay, and because they are still listed they count as seen again, so an unchanged feed never ages
out. A TAXII list asks only for what was added after the cursor of its last complete pull; a MISP feed reads only
events changed since its last complete pull. These incremental pulls **add**: an entry the source has since removed leaves
the list through the age limit, not at once. (Set an age limit on such lists.)

**The point to continue from.** The cursor a source sends (the TAXII `X-TAXII-Date-Added-Last` date, the newest MISP event
time) is checked before it is kept: it must be a valid time (for TAXII `YYYY-MM-DDTHH:MM:SS[.fraction]Z`), not more than a day
ahead of the server's clock and not older than the one already kept. Otherwise the previous cursor stays, what was read is
stored as usual, and the list's status says "the source sent a point to continue from that is not usable ... the previous
point was kept": the next pull then reads again from the old point, so a broken or wrong source cannot park later pulls in the future.

**Ageing.** An entry has an expiry from the source (STIX `valid_until`) or counts until its age limit has passed since it was last seen.
"Last seen" is the last fetch that listed it (a 200 answer or a "not modified" one alike); the source's own time (a STIX
`modified`, a MISP attribute's `timestamp`) is kept as when the entry was first seen, so an old indicator a feed still lists
does not age out while it is listed. The default
age limit is 30 days, 0 never. The age limit is for lists that are fetched; the entries of a `paste` or `file` list, which no fetch
sees again, leave it only through their own expiry or when the list is replaced or cleared. Entries that have aged out are not stored by a refresh, are left out of the matching index, and are
deleted by the same job once an hour.

**Test, change nothing.** `POST /api/threat-lists/{id}/test` fetches and reads the list exactly as a refresh does, with a
bounded pull (at most 10 TAXII pages or the 50 newest MISP events), and shows how many entries of each kind it would
keep, how many it skipped and why, and a few sample entries (a web address is shown without its query and user name). It
writes nothing: no entry, no status, no validator, no cursor. `POST /api/threat-lists/{id}/refresh` runs a refresh at
once. Both are the administrator's, at most ten manual fetches a minute together, one fetch of a list at a time, and
bounded by the fetcher's limits (120 s, 32 MiB). Each is written to the audit log (`threat_list.test`,
`threat_list.refresh`) with the list id, yes or no and the counts, never an address, an entry or a credential; when the
answer gives up waiting after 180 s (`424`) the entry says `timed_out: true` (the fetch may still finish in the background
and change the list). On a high-availability pair a refresh and stored entries are refused with `409` on the node that
is not the active one; a test runs on either. A refresh of a list (or of all lists) that is switched off fetches nothing
and says so. For a TAXII server the address is read as the discovery document first and as the API root only when that
step says it is not a discovery document; an error after that step is shown as it is.

## Rules

Three detection rules judge your lists. They are new in 4.5, so on an installation that existed before they arrive **off** and carry
the mark *New in 4.5.0* (none is recommended); they are never quiet and never paused, and they have nothing to do until a list
exists. They are separate from `threat_list_match` and `dns_threat_domain`, which keep judging the lists that come with the product
and the `--threat-list` file, unchanged. Each alert names the list, the matched entry, the device and the evidence. Details, scores
and false positives are in [Detection rules](detection-rules.md).

| Rule | Judges | Evidence an alert carries |
|---|---|---|
| `threat_list_domain` | the name of a DNS lookup and its last CNAME target; later also a TLS server name and the host of a plain-HTTP request | the list, the entry and whether it matched "and below", the name asked for, whether it came through a CNAME, what answered, the resolver, the time |
| `threat_list_url` | a plain-HTTP address: host and path prefix, or a path with its exact query | the list, the listed address (never the visited one), the server |
| `threat_list_address` | the outside address of every flow window | the list, the listed range and whether it is a single address (`match_kind` `exact` or `range`), the connection snapshot (below), the bytes; the hint when there is one |

* **A name matches on label boundaries**, the most specific entry first and, at the same name, the list created first. A CNAME that
  leads to a listed name counts and the alert says so. A name that is merely a longer word (`notevil.com`) never matches.
* **What cannot be seen.** Only plain DNS: DNS over HTTPS or TLS, and a resolver on a link DENIS does not capture, hide the name. An
  `https` web address matches nothing, because the path of an HTTPS request is invisible; its host can be matched as a name.
* **One alert per device and entry per six hours.** Nothing is learned: the rules judge from the first sighting, also during the
  learning period.
* **The action of the list** decides what else happens. `alert`: nothing. `prepare_block` and `auto_block` (Experimental, off by
  default): the rule also queues a prepared block, one per list and entry and at most 50 waiting, so that a poisoned list cannot flood
  the queue. The queue is read by the block step (below), which turns a proposal into a prepared block only once its alert is
  stored as raised: a hit whose alert an exception dropped, that was kept as a trial hit or under the rule's own minimum score, or
  whose insert failed prepares nothing. A proposal waits for its alert for at most two minutes. An exception added after the alert
  also keeps the block from being prepared. The alert says in `response` whether a path exists (`offered`, and `path`:
  `name` or `addresses`). Automatic blocking tries at most three prepared blocks per pass; a name that automation already
  blocked within a day, and the prepared blocks of a pass that has reached the hourly limit, do not use up those tries.
* **Per customer.** The rules read the lists of their own installation (on a server with tenants, of their own tenant) and no others.
* **For the capture of server names and plain-HTTP requests** (a later step) the matcher already has its entry point,
  `Detector::list_names`, which takes a batch of `Sighting` values (`threat_lists::sighting`): the name, how it was seen
  (`lookup`, `tls_name`, `http`), the client, the server address and, for HTTP, the request target. The capture side builds them
  and calls it; no rule changes.

### Using a list in your own rules

Besides the three rules above, a list can be used in a rule you write yourself (Rules, **+ New rule**, **Rule with several conditions**): the condition
**the address talked to is on a list** (for rules about traffic to the internet) or **the name looked up is on a list** (for rules about lookups). You pick
the lists by name from the ones you added; the rule keeps their ids. It combines with the other conditions (a device group, a time of day, a port), so
*cameras may not talk to an address on "Acme ISAC" outside office hours* is one rule. The lookup is the one the rules above use and costs the same: no
allocation per record. A list that you delete or switch off can no longer match, and the rule says so in the editor and on the Rules page (see
[Detection rules](detection-rules.md#custom_rule-your-rules-with-several-conditions)). A rule you write does not prepare a block; only the action of the list
does, through the rules above.

### Lists from your MSP

An MSP can send you the **definition** of a list (where it is fetched from, how it is read, what a match does, how often), never entries and never a
credential. It arrives as a managed list marked *Sent by <MSP>*, **switched off**, only if you allowed your MSP to send (the setting for rules, off by default;
with *Ask me* the list waits as an offer at the top of this page). You can switch it on and off, set the credential it needs (by hand, on this installation
only), refresh it and delete it, but not change its source. The MSP can take it back. Details: [MSP management](msp-management.md#sending-threat-lists-to-customers).

### The flow-to-name hint

A flow carries only addresses, so a flow can never match a name. To help read an alert, DENIS keeps in memory, per device, the
addresses it was answered with by DNS, and for which names, for ten minutes (the answer's own time to live is not recorded by passive
DNS, so five minutes plus five of grace are assumed). It is bounded: at most 128 addresses per device and 50,000 in all (a full map
refuses new entries and counts them), nothing is written to the database, and a restart empties it.

* It only **adds words to an alert** that a name match or a listed address raised, and says it is an **estimate**. It never raises an
  alert and never prepares a block by itself.
* It counts the **other names** the same device got that address for. A content-network address shared by many names is a weak sign:
  the alert shows the count so that you do not block an address that other names use.
* When the device then connects to an answered address of a listed name, that is noted; the alert of `threat_list_address` for that
  address says "this device asked for *name* (list *L*) and then connected to *address*". A stored alert is not amended later, and the
  name alert is raised when the lookup is judged, before its flows, so on a name alert the connection appears only if an earlier
  window already showed it.
* With passive DNS off there is no hint; the alert does not mention a name.

## What a sensor can and cannot see

A list can hold addresses, networks, names and URLs, but a sensor sees only what crosses the interface it
captures on. Addresses and networks are matched against flows. Names are matched where DENIS reads them, in three ways:

| How the sensor sees a name | What it reads | What it does not see |
|---|---|---|
| A DNS lookup (passive DNS, [its own switch](passive-dns.md)) | the name asked for, the last CNAME, the answers, the device and the resolver | DNS over HTTPS and over TLS, answers a device had cached, lookups that never cross the sensor |
| The TLS server name (SNI), switch *Server names and web addresses* | the name a device presents in the first packet of an encrypted connection, in clear | the name under Encrypted Client Hello (only the provider's outer name is in clear), QUIC and HTTP/3, a hello whose server name lies past the first TCP segment (there is no reassembly), connections to an address without a name, anything inside the connection |
| A plain-HTTP request, same switch | the host and the path of the **first** request of a connection, on port 80, 8000, 8008, 8080, 8081 and 8888 | the query string (cut when it is read), cookies, `Authorization` and every other header (never read), the body, later requests of a kept-alive connection, HTTP on other ports |

**A sensor cannot see the path of an HTTPS request.** A URL entry with a path therefore matches plain HTTP only; for HTTPS
only the address and the name (the SNI, and the name of a DNS lookup) are compared. An `https` web address matches nothing; a list can
tick "an HTTPS address counts as its host" to compare its host. IPv6 connections are not read for server names yet
(passive DNS is). Matching a name says a device looked up or contacted it, not that the content was bad.

### Reading server names and web addresses (opt-in)

Off by default, switched on by an administrator **per collector**, like passive DNS: *Settings -> Network interfaces -> Server
names and web addresses* for this console's own capture (takes effect at once, saved), `--capture-names` for a remote agent
(the console's setting is not pushed to an agent; the agent decides for itself). It does something only with the wide flow
capture (`--flows`, a mirror interface), and only while at least one list holds names (otherwise a name is compared with nothing
and dropped).

**What is kept: nothing.** The sensor reads a name, compares it with your lists and forgets it. There is no table of names, no
retention to set and no "delete all" button, because there is nothing to delete (since 4.5.0 with one bounded exception, in
memory only: see [Connection evidence](#connection-evidence-450)); this is a choice, not an omission: names say
what the people behind a device do (see the note on personal data in [Passive DNS](passive-dns.md)), and the lists only need to
know whether a name is on them. What remains of a **match** is the alert: the listed entry, the list, the name (or, for a plain-HTTP
match, the *listed* address and the host, never the visited path and never a query), the device, the server address and the time.
It lives as long as alerts do (the general retention) and is deleted with them. A name that is on no list is never written anywhere:
not to the database, not to a log line, not to the audit trail. While it travels it is held in memory only: on a collector for
the length of one capture window (10 seconds), on a remote agent also while the master cannot be reached (at most 20,000
records, oldest dropped and counted), and on the master for the time it takes to judge the report.

**What is read, exactly.**

* *TLS:* the `server_name` extension of a ClientHello that lies wholly inside the first segment of the hello; only host names
  (other name types are skipped), only letters, digits, `-`, `_` and dots, at most 253 bytes, at least two labels, and never an
  address in disguise. Case, a trailing dot and international names (Punycode, as they are on the wire) are normalised when the
  name is matched, exactly as list entries are.
* *Plain HTTP:* the request line (`GET`, `HEAD`, `POST`, `PUT`, `DELETE`, `OPTIONS`, `PATCH`; HTTP/1.0 or 1.1) and the `Host`
  header within the first 2,048 bytes of the first payload; an absolute target (a client talking to a proxy) names its own host.
  **The query string and the fragment are cut at once**, so a token in a URL is never kept; a console administrator can tick
  *also keep the query string in memory for the match* for list entries that name an exact query, and then it is held in memory only,
  for the match, and is not in the alert. An agent never sends a query, and a master cuts any it receives. A path longer than 512
  bytes is not read. **`Authorization`, `Cookie`, `Set-Cookie` and every other header are never interpreted**: the parser only
  looks for the end of each line and for `Host`.
* A name seen again for the same device within 30 seconds is not reported again; a window holds at most 4,096 distinct names
  (more are counted, not kept); a report holds at most 10,000.

**On the wire.** A new optional list `names` of the agent report (`kind` `tls_name` or `http`, name, path for `http`, client,
server address and port, count, window): absent from reports of agents built before 4.5 and not sent when empty, and a master
built before it ignores the field. The master checks every record (a name that is not a plausible host is dropped, the path is
cut at `?` and `#`, a TLS record has no path, names are lower-cased) and hands it to the same matcher as a lookup.

**What it costs** is in the next section ("Name capture"), measured, and shown next to the switch.

## Connection evidence (4.5.0)

The address alerts of the lists (`threat_list_match` for the shipped lists and the `--threat-list` file, `threat_list_address`
for your own lists) carry a **Connection evidence** section in the alert dialog, built only from what the alert stored
(`raw_details.connection`, see [API](api.md#changes-since-40)), so an old alert reads the same later:

* **Connection**: the device and its address, the remote address, the service port and protocol, bytes sent and received in
  that 10-second window (as the device sees them), the packet total (both directions together), the window, and the agent
  (or this server's own capture) that saw it. Not recorded in this version, and said so: the source port, packets per direction,
  first and last packet inside the window, whether a TCP handshake completed, the capture interface, the DNS TTL and the CNAME
  chain.
* **Domain or service**: every name with its source. *Observed TLS SNI* and *Observed HTTP Host* are names the capture of names
  read in a connection from this device to this address. *DNS correlated (inferred)* is a name this device was given the
  address for by passive DNS: an inference, never "the device visited this site"; when several names point to the address
  (common for content networks) they are all kept and the section says it is ambiguous. *Unknown* when nothing was seen, with
  why that can be (the capture of names or passive DNS is off, Encrypted Client Hello, DNS over HTTPS or TLS). The owner of an
  address is its hosting network, not necessarily the website.
* **Threat list**: the list, the match kind (exact address, a network listed as a whole, or an autonomous system listed as a
  whole, with its AS number) and the entry.
* **Related activity**: what DENIS recorded between the device and the address and which other devices contacted it (the same
  data as *Investigate*). A contact seen in one window only may not be kept there; the snapshot is.
* **Not known from the network alone**: which program made the connection (that needs software on the device) and which website
  was open (one address serves many sites; encrypted names are invisible).

**What is held for it, and when.** While a shipped threat list or one of your lists with addresses is loaded, the master keeps
the server names that arrive from the capture of names in memory for 15 minutes per device and address (at most 3 per pair and
8,192 pairs, about 2 MB; a full table refuses new pairs and counts them). Nothing of it is stored by itself, logged or shown: a
name is copied into an alert only when one of these two rules raises one for that very address, and then lives as long as the
alert. With no such list loaded nothing is held, and with the capture of names off nothing arrives. The DNS names come from
passive DNS's own in-memory label (the last three names per device and address), as `names` did before.

## What it costs

Measured with the benchmark in `src/threat_lists/bench.rs` (`cargo test --release --lib -- --ignored --nocapture
threat_lists::bench`), on one machine and with synthetic names; your numbers will differ.

Release build, Apple M1 Pro, one thread, synthetic names of three labels, half of them "and below" entries; every lookup
was checked to answer as built.

| | 500,000 names | 2,000,000 names |
|---|---|---|
| Adding the entries to the builder | 162 ms | 564 ms |
| Compiling the table | 17 ms | 79 ms |
| Memory that stays (tables) | 12 MiB (25.2 bytes an entry) | 48 MiB (25.2 bytes an entry) |
| Growth of the process while building | 46 MiB | 216 MiB |
| Lookup of a listed name | 103 ns | 140 ns |
| Lookup of a name below a listed name | 130 ns | 219 ns |
| Lookup of a name that is not listed | 143 ns | 172 ns |

500,000 networks: built in 125 ms, a lookup takes about 3 ns on random addresses (3 percent of them listed). 200,000
plain-HTTP addresses: built in 174 ms, a lookup including the normalising of the request takes about 1.2 microseconds.
Building happens off the hot path and the new index is swapped in whole. The cost of reading the entries from the
database and of parsing feeds is not in these numbers; what name capture costs a sensor is in "Name capture" below.

### Name capture (TLS server names and plain-HTTP requests)

Measured with `cargo test --release --test names_seen_hot_path -- --ignored --nocapture` (`tests/names_seen_hot_path.rs`) on the same Apple M1 Pro,
through the real parse path (`parse_frame_into`) with the capture off and on, 400,000 frames of each kind; synthetic frames, so your numbers
will differ. The table is generated from the constants the console shows next to the switch (a test fails when it differs).

<!-- names-cost:begin -->
| What | Cost (Apple M1 Pro, one thread, release build) |
|---|---|
| A packet that carries no name (the parse of a frame is about 50 ns) | about 5 ns more |
| Reading the server name of a TLS hello, the name already seen in the last 30 s | about 55 ns more (the JA3 fingerprint that was already taken costs about 1.7 microseconds) |
| Reading the host and path of a plain-HTTP request, the name already seen in the last 30 s | about 190 ns more |
| Memory while a window is open | at most 4 MB per collector (4,096 records of at most 900 bytes), 16 KB for the filter of recent names |
| Disk | none |
<!-- names-cost:end -->

The raw measurements, nanoseconds per packet with the capture off and on: a packet with no name (TLS application data, an HTTP response,
binary on port 80, capital letters on port 8080) 49.7 and 54.2; an HTTP request whose name was seen in the last 30 s 48.5 and 239.1; a
TLS ClientHello whose name was seen in the last 30 s 1,717 and 1,773 (the JA3 fingerprint is the larger part and was taken before). The
parsers alone: the server name of a 0.7 KB and of a 1.3 KB hello 32 ns; an HTTP request 95 ns, also with 80 padding headers (the header
loop is bounded to 24 lines and the first 2,048 bytes); 1.4 KB of random bytes 1.6 ns (TLS) and 3.8 ns (HTTP), because the first
byte decides. A name that is new allocates once (the owned name, and the path for HTTP) and takes the lock of the recent-names filter;
that is once per device, name and 30 seconds, not per packet.

* **No allocation per packet.** `tests/names_seen_hot_path.rs` counts allocations with a counting allocator: 120,000 frames with no
  name (with the capture off and on, the query option included), 50,000 repeats of one request, and 600 hostile and typical inputs
  (every prefix and mutation of a hello and a request) through both parsers allocate nothing. `fuzz/` has the targets
  `tls_client_hello_sni` and `http_request_line` (no panic, a plausible name inside the input, no `#`, no query unless asked for, and the
  result written back into a fresh request or hello reads as itself).
* **Bounded memory.** A window holds at most 4,096 distinct (device, kind, name, path) keys; more are counted (`dropped` in
  `GET /api/interfaces/capture-names`), never queued. A remote agent spools at most 20,000 records while the master is away (oldest
  dropped and counted) and sends at most 5,000 per report; the master accepts at most 10,000 per report. The filter of recent names is
  1,024 slots of 16 bytes.
* **Capture drops.** There is no live capture in the build environment, so the effect on the drop counters of a loaded interface was not
  measured; what is measured is the added time per packet above (about 5 ns where the parse takes about 50 ns, nothing on the kernel or
  the capture thread's read) and the flood tests of `tests/flood_resilience.rs`, which run the whole frame path with the capture on (all
  bits). Watch `capture_dropped` on the Health page after switching it on a busy link, and switch it off if it moves.

### What the rules cost

Measured with `cargo test --release --lib list_rules_cost -- --ignored --nocapture` (`src/detect/tests/list_rules.rs`) on the same Apple M1 Pro, at the
reference site of 1,000 devices, with a list of 50,000 names and 50,000 networks, worst of 20 windows:

| Rule | Window | Time per window |
|---|---|---|
| `threat_list_domain`, hint on | 5,000 DNS records, two answers each | 1.4 ms |
| `threat_list_address` | 20,000 flows | 0.7 ms |

* **Nothing allocates per record.** `tests/threat_list_hot_path.rs` counts allocations with a counting allocator: 800,000 lookups (listed, below a
  listed name, not listed, IPv4, IPv6, web address) allocate nothing, the allocations of a window do not depend on its number of records, and
  10,000 distinct unlisted names cost a few dozen (the growth of the per-window memo). A window with no list holding names, or with the rule off,
  costs one reference-count read.
* **The hint map** is the only memory the rules add: at most 50,000 answered addresses (128 per device), declared at 160 bytes each, so at most
  about 8 MB, nothing on disk. It is filled only while a list holds names and passive DNS is on; it is the cost next to the passive-DNS switch.
* The rules are Cheap (budget 1 ms a window) and never paused; a window over four times its budget in three of six windows is reported by Health
  like for every rule. The hint map's allowance is added to the ceiling for the state of the new rules (`list_rules::STATE_ALLOWANCE_BYTES`).
