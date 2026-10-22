# Licensing

The Community edition is distributed as pre-built, signed binaries under the DENIS Community License.
The full terms are in `LICENSE`, in the root of the repository; this page is a summary, not a substitute for
reading it.

## Community edition

Free to use for **personal or other non-commercial purposes**, on a single installation
monitoring **up to 100 devices**. This covers a household network, or trying DENIS out.

## Commercial use

Any use by or for a business, non-profit, government body or other organisation — regardless of
device count — and any installation over the 100-device cap, needs a **commercial license**. See
`LICENSE-COMMERCIAL.md`, in the root of the repository, for how to get one.

## What changes without a license

Nothing is crippled. Detection, alerting and everything that keeps you safe keeps working exactly
the same, on every device DENIS finds — a license never turns off protection to make a point.
What is limited is the **browsable list**: past the 100-device cap, the Devices page (and its CSV
and printable report) shows only the first 100 devices, chosen by a stable order so it is always
the same ones, not a different 100 each time. A banner explains why, with a device count, whenever
you are over the cap or a license file cannot be verified (expired, edited, or issued for a
different build).

## Installing a license

A license is a small signed text file, two lines. The easiest way: **Settings → System → License** (an
administrator), paste both lines in and save — it verifies immediately, no restart needed, and
if it does not verify the page says why. This is what most installs should use.

Alternatively, a file on disk works the same way, and takes effect at start-up:

```bash
denis serve --db denis.db --license-file /path/to/license.key
# or, for the full discovery/detection mode:
denis run --license-file /path/to/license.key
```

`DENIS_LICENSE_FILE` works the same way as an environment variable. A license pasted into
Settings → System → License always takes priority over `--license-file` if both are present.

**In an MSP/multi-customer setup**, the license belongs on the top-level installation that has a
console — your own instance if you are a single business, or each customer's master if you are an
MSP running one DENIS per customer. Agents reporting into a master never need their own license;
the cap and terms apply to the install as a whole, not per agent.

A license's validity is counted **from the first time it verifies on that install**, not from the
day it was issued.

**A license is issued for one installation.** Settings → System → License shows this installation's ID (a
random identifier it created once; it never changes and is not a secret). Send it with your order,
and the license you receive works on that installation only — copied to another server it is
refused there, and that server stays on the Community edition. Nothing is sent online for this:
you pass the ID on yourself, so it works fully air-gapped. The ID is kept in DENIS's database, so
restoring a backup onto a replacement server keeps it (and the license with it). Licenses issued
before installation IDs existed are not tied to one and keep working exactly as before.

Expiry is judged against a licensing clock that never runs backwards: setting the system clock back
does not extend a license. Small corrections (NTP and the like, up to 10 minutes) are tolerated.

**Devices are counted across the whole installation**: everything this console holds — its own
devices, every agent's, and every site relayed into it from another DENIS (`denis run
--report-to`). A site that only relays to an MSP's master needs no license of its own for that; the
master's license covers the combined total.

## Expiry, and a 7-day grace period

Nothing changes suddenly. Settings → System → License always shows when the current license expires and,
once it is getting close, how many days are left:

* **30 days before expiry**: everything stays exactly as licensed. A banner appears at the top of
  the console, and a low-severity alert is raised once (not repeated every day), so it does not
  get missed even if nobody happens to open Settings.
* **After it expires**: still nothing is hidden yet. A **7-day grace period** starts, during which
  the license keeps working in full — this is deliberately generous, so a renewal in progress (an
  invoice being processed, a file that has not been re-installed yet) never causes a surprise
  during business hours. A higher-severity alert marks the start of the grace period.
* **After the grace period also passes**, the install falls back to the Community edition (the
  100-device cap and everything described above) until a valid license is installed again.
