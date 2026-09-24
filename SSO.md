# Single sign-on (OpenID Connect)

What DENIS supports, what was actually verified, and what still needs a real identity provider
to confirm — written with the same honesty bar as [WINDOWS.md](WINDOWS.md) and
[docs/docker.md](docs/docker.md): if something below isn't marked verified, treat it as
unverified, not as working.

## What it is

An administrator points DENIS at an OpenID Connect identity provider (Entra ID, Okta, Google
Workspace, Keycloak, or anything else that speaks the protocol) from Settings → Single sign-on.
People can then sign in with it instead of a local password. The first successful sign-in for an
email creates a local `viewer` account for it automatically; an administrator raises the role
afterwards, exactly like any other account. Local accounts, including the initial admin password,
keep working unchanged alongside SSO — it is an additional door in, not a replacement for the one
already there.

SAML is deliberately not supported: OIDC covers every provider this project has been asked
about, at a fraction of the implementation size and attack surface of a SAML relying party.

## What was actually built and verified

* `src/sso.rs` implements the OIDC authorization-code flow with PKCE, using the `openidconnect`
  crate (not hand-rolled JWT/crypto verification) over `ureq` — matching this project's existing
  HTTP client rather than pulling in a second one.
* Every piece of logic that does **not** require talking to a real identity provider has a real,
  passing test: `SsoConfig` validation and its "never shows a button when unconfigured" rule, the
  single-use, TTL-expiring pending-login state (the CSRF `state`/`nonce`/PKCE-verifier stash
  between the redirect out and the callback in), account provisioning and reuse in `auth.rs`
  (`sso_login`: creates a `viewer` on first sign-in, reuses an existing account with a matching
  username afterwards without resetting its role, refuses a disabled account, and the account
  never has a usable local password), and the web layer's permissions and secret redaction
  (`GET /api/sso` never returns the stored client secret; only an administrator can change it).
* The full request/response wiring compiles against the real `openidconnect` v4 API (a
  major-version rewrite from most published examples; the exact type-state generic parameters for
  a client built from discovered provider metadata took real trial and error against the compiler
  to get right — this was not assumed from a tutorial).

## What is *not* yet verified

* **The actual exchange with a real identity provider has not been run.** Discovery
  (`.well-known/openid-configuration`), the authorization redirect, the token exchange, and ID
  token signature verification against a real (or even a local mock) provider have not been
  exercised end to end. Everything above this point is verified; this specific, security-critical
  path is not, and should not be treated as working until it is.
* No mock OIDC provider was built for this pass (a correct one — real key generation, JWKS,
  a signed ID token — is itself a non-trivial piece of work, and doing it under time pressure
  risked a mock that "passes" without actually exercising the same code paths a real provider
  would). Recommended before relying on this: configure it against one real provider (a free
  Google Cloud OAuth client or a Keycloak container are both zero-cost ways to do this) and confirm
  the full sign-in works end to end, including that a wrong or expired ID token is correctly
  rejected.
* The redirect URL DENIS derives (`{scheme}://{Host header}/api/auth/sso/callback`) has not been
  checked against every reverse-proxy configuration this project supports (`--allowed-host`,
  loopback + proxy setups). It follows the same trust boundary the rest of the console already
  applies to the `Host` header, but has not specifically been tested through a proxy.

## Configuration

Settings → Single sign-on (admin only): enable/disable, issuer URL, client ID, client secret, and
the sign-in button's own label. The page shows the exact redirect URL to give the identity
provider. Nothing here needs a restart.
