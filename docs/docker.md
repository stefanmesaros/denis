# Docker

Two independent ways to use the image — pick one, do not run both against the same data volume.
Everything below was actually built and run (a real `colima`/Docker Engine locally, not assumed to
work), including finding and fixing three real bugs that only showed up by doing that. What is
still genuinely unverified is called out explicitly, the same way the rest of this project's
documentation does.

## Try it: the built-in demo, no real capture

```bash
docker compose up demo
```

Loads the built-in demo data (a fictional company, 42 devices, 13 alerts) into a named volume on
first start, then serves the console on <http://localhost:8080>. The one-time administrator
password is printed to the container's logs (`docker compose logs demo`) — unlike the bare-metal
`./denis demo && ./denis serve --insecure-no-auth` in the project's README, a real
sign-in is required here: `--insecure-no-auth` only works when the console listens on a loopback
address, and a container reachable through a published port is not one. Restarting the container
does not reload or wipe the data (the entrypoint only loads the demo the first time the volume is
empty) — remove the `denis-demo-data` volume to start over.

This path needs no special network mode or Linux capabilities: ordinary bridge networking, nothing
about a real network is touched.

## Monitor a real network

```bash
DENIS_LISTEN=0.0.0.0:8443 docker compose up -d denis
```

This is the one that needs real trade-offs, spelled out rather than hidden in a flag:

* **`network_mode: host`**: a container's own bridge network is a different network namespace than
  the host's — capture would only ever see the container's own virtual interface, never the LAN a
  real collector needs to watch. Host networking shares the host's network stack instead, so the
  container sees (and can be reached on) the host's real interfaces directly — no port mapping, and
  no network isolation from the host either. This is the standard way network-monitoring tools run
  in Docker; it is still a real reduction in isolation, not a default to take lightly.
* **`cap_add: [NET_RAW, NET_ADMIN]` with `cap_drop: [ALL]`, `user: root`**: the same two
  capabilities `packaging/denis.service` grants a dedicated, unprivileged `denis` user on a
  bare-metal Linux install via `AmbientCapabilities`. A Linux **file** capability (`setcap`) was
  tried first, to keep the container non-root the same way — it does not work: a file capability
  can only grant what the container's own capability *bounding set* already has, and Docker's
  default bounding set excludes both. Confirmed by actually running it: `denis --version` failed
  with "Operation not permitted" inside a container that had the file capability set but neither
  capability added at the Docker level. So the container runs as root, with every other capability
  explicitly dropped — Docker's own capability system enforces the boundary instead.
* With host networking, auto-detection (the interface holding the default route) works the same
  way it does on a bare-metal install — no `--iface` needed by default. To monitor a specific
  interface, or add a `--mirror-iface` for a SPAN/mirror port, override the command in
  `docker-compose.yml`, e.g. `command: ["run", "--iface", "eth0"]`.

**What is verified here, and what is not.** The image builds, starts, binds its port, and serves
the console with real demo data through a real login — all confirmed by actually doing it. **Real
packet capture from inside this container, on a real network, has not been verified** — this
development machine's own network topology is not a stand-in for that, the same honest gap
WINDOWS.md states for the Windows build rather than assuming it away.

## Real bugs found by actually building and running this (not by inspection)

* A `.dockerignore` line meant to exclude runtime artifacts (`data/`) also excluded
  `data/vulndata.json`, a required *source* file (`include_str!`'d into the binary) — the build
  failed outright until this was narrowed.
* `Serve.listen` (used by the `demo` service) had no `env = "DENIS_LISTEN"` binding, unlike
  `Run.listen` — setting the environment variable silently did nothing, and the console kept
  binding to `127.0.0.1` inside the container, unreachable through the published port. Fixed in
  `src/main.rs` to match `Run`'s existing convention.
* `DENIS_NO_TLS=1` is not a valid value — clap parses a plain `bool` env var with Rust's own
  `bool::from_str`, which only accepts the literal strings `true`/`false`. `denis run` refused to
  start at all until the Dockerfile used `true`.

None of these would have been caught by reading the Dockerfile; all three only showed up by
actually building the image and starting a container from it.

## Environment variables

Any `denis run`/`denis serve` flag with an `env = "DENIS_..."` binding works here (see
`docs/deployment.md`'s note on `install.sh`'s environment file for the same convention). Two are
set by the image itself and can be overridden:

| Variable | Image default | Meaning |
|---|---|---|
| `DENIS_NO_TLS` | `true` | Plain HTTP instead of the built-in HTTPS (a container-generated self-signed certificate is usually more friction than it is worth behind a reverse proxy). Unset it (`environment: {DENIS_NO_TLS: ""}`) for the same HTTPS a bare-metal install has. Only affects the `denis` (capture) service — `serve` (the `demo` service) never uses TLS at all. |
| `DENIS_LISTEN` | `0.0.0.0:8080` | The address DENIS binds inside the container. Change the *published* port in `docker-compose.yml` instead of this for the `demo` service; for `denis` (host networking, no port mapping), this is the actual port to reach it on. |
| `DENIS_DB` | `/data/denis.db` | Where the entrypoint script tells DENIS to keep its database — matches the volume mount, no reason to change it. |

## Building it yourself

```bash
docker build -t denis:local .
```

Multi-stage, using [`cargo-chef`](https://github.com/LukeMathWalker/cargo-chef) so a change to
DENIS's own source does not force recompiling its entire dependency tree from scratch every time —
only the first build (or a `Cargo.lock` change) pays that cost.
