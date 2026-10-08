---
name: Integration testing feedback
about: You tried a firewall, switch, cloud, directory, scanner, ticketing or notification integration
labels: integration
---

Integrations were built against vendor documentation and test fixtures and have not been independently
validated against the real products, so every report, including "it worked", is useful.

**Please do not include** passwords, API keys, tokens, SNMP communities, tenant or account identifiers,
public IP addresses or unredacted packet captures. Replace them with `<redacted>`.

**DENIS version** (`denis --version`, or the header of the console)

**Operating system and how you run DENIS**

**Which integration** (for example FortiGate, UniFi, Palo Alto, an SNMP switch, Entra ID, Slack) and the
product's model and firmware or API version

**Network environment** (home / office / industrial; where DENIS sits relative to the device; VLANs)

**Expected behavior** (what you wanted the integration to do)

**Actual behavior** (what happened; the error text shown in DENIS; the step where it stopped)

**What worked** (the parts that did, so we know what is verified)

**Logs or screenshots** (redacted)
