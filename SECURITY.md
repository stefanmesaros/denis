# Security policy

DENIS is security software. Its job is to be trusted on the networks it watches, so vulnerability reports are
welcome and taken seriously.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Use GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a
vulnerability**. Include what you found, how to reproduce it, the version (`denis --version` or the header of the
console) and, if you can, its impact.

You can expect:

* an acknowledgement within **3 working days**;
* an assessment and, for a confirmed problem, a fix or mitigation plan within **30 days** for serious issues;
* coordinated disclosure: we ask for up to **90 days** before publication, less if a fix ships sooner, and we
  will credit you in the advisory unless you prefer otherwise.

## Scope

In scope: the `denis` program and its console/API, the agent protocol, the packet parsers, authentication
(passwords, sessions, API tokens, passkeys), the stored data and the notification/export integrations.

Out of scope: findings that need an already-compromised administrator account or root access to the host, denial
of service by an attacker who can already flood the monitored network, and vulnerabilities in third-party
services DENIS talks to.

Testing your own installation is welcome. Do not test against networks or systems you do not own or have
permission to test.

## Supported versions

Only the latest release and the `main` branch receive security fixes while the project is young.

## Known limitations

They are listed honestly in [docs/security.md](docs/security.md) (what DENIS does *not* protect against) and in the
"Status" section of the [README](README.md). An independent penetration test has not been done yet; if you are able
to do one, please get in touch.
