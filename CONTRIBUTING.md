# Contributing to DENIS

Thanks for helping. DENIS is security software, so the bar is "works, is tested, and is explained".

## Build and test

```bash
cargo build
cargo test
cargo clippy --all-targets      # must be clean
cargo audit                     # dependencies must have no known vulnerabilities
```

You need a Rust toolchain (stable) and libpcap (`libpcap-dev` on Debian/Ubuntu; included on macOS). Capturing
packets needs privileges; the tests do not.

## What a good change looks like

* **Tests.** Every rule, parser and endpoint has tests, including hostile input. A bug fix starts with a test
  that fails. Parsers must never panic on malformed data.
* **Comments that explain why.** Module headers state the module's purpose and what is trusted and bounded;
  non-obvious decisions say why.
* **Honest scope.** If something does not work well, do not ship it. If something is untested on real
  hardware, say so in the docs (see the README status section).
* **Security first.** Anything read from the network or a user is hostile: bound it, escape it for where it is
  going, never build HTML or commands from it. No secrets in logs, errors or the audit log. Prefer failing
  closed.
* **Docs.** User-visible changes update `docs/` (these pages are compiled into the console) and, for new
  detections, the rule list in `src/rules.rs` and the advice in `src/detect.rs`; tests enforce that they match.
* **Translations.** The console's texts live in `tools/i18n/*.tsv` (English, Deutsch, Français, Español,
  Slovenčina, one line per string). After adding or changing any text the UI shows (`tr('…')` in `ui/*.js`,
  `ui/index.html`, or a sentence the server sends), add its translations and run
  `python3 tools/i18n/build.py --check`; `cargo test` fails if a language lacks a string or a `{placeholder}`.
  A new language is a new column plus an entry in `ui/i18n.js` and `src/branding.rs`.
* **Small pull requests** with a clear description of the problem and what you verified.

## Security issues

Do not file them as public issues: see [SECURITY.md](SECURITY.md).

## License

By contributing you agree that your contribution is licensed under the same terms as the project:
**MIT OR Apache-2.0**, at the user's option.
