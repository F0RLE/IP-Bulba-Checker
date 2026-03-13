# Contributing

Thank you for considering a contribution. This document explains how the project is structured, what kinds of contributions are most useful, and what the review criteria look like.

---

## Before you start

- Check the [roadmap](docs/roadmap.md) — the planned and known-issue sections are the best places to look for impactful work.
- Search existing issues before opening a new one.
- For large changes, open an issue first to discuss the approach.

---

## What to contribute

### High-value areas

| Area | Why it matters |
|---|---|
| **Detection accuracy** | WAF vs GeoBlock confusion (see roadmap) causes real false positives in router configs |
| **Service profiles** | New services in `profiles.toml` require no code changes — easiest contribution |
| **Signature patterns** | More specific body/header signatures reduce noise in `SIGNATURES_BODY` / `SIGNATURES_HEADERS` |
| **Tests** | More annotated domain test cases in `scanner::tests` improve regression coverage |
| **Export formats** | New router targets (Clash, Shadowrocket, NekoBox, Mihomo) |

### Lower priority

- UI/cosmetic changes to output formatting
- Adding dependencies without a strong justification
- Generic "refactoring" PRs without a concrete correctness or performance win

---

## Development setup

```sh
git clone https://github.com/F0RLE/Bulbascan
cd bulbascan

# Run all tests
cargo test

# Run benchmarks (optional)
cargo bench

# Check for warnings
cargo clippy -- -D warnings

# Build release binary
cargo build --release
```

**Requirements:** Rust 1.94+

---

## Adding a service profile

No code changes required. Edit [`profiles.toml`](profiles.toml):

```toml
[[services]]
name = "MyService"
browser_verification = true
expected_roles = ["web", "api"]
critical_roles  = ["web", "api"]

[[services.hosts]]
domain = "myservice.com"
role   = "web"
probe_paths = ["/", "/login"]

[[services.hosts]]
domain = "api.myservice.com"
role   = "api"
probe_paths = ["/"]
```

Guidelines:
- `expected_roles` — every host role you've listed
- `critical_roles` — only the roles whose block should trigger `ProxyRequired`
- `probe_paths` — real URLs that return a representative response (login page, API root, etc.)
- `browser_verification = true` for consumer services with Cloudflare/WAF-protected frontends

---

## Adding a signature pattern

Edit `src/signatures.rs`. Patterns live in three constants:

| Constant | Matches against |
|---|---|
| `SIGNATURES_BODY` | HTTP response body |
| `SIGNATURES_HEADERS` | Response header key + value pairs |
| `SIGNATURES_API` | JSON/API error body |

Rules for a good pattern:
- **Specific** — prefer `"not available in your region"` over `"blocked"`
- **Lowercase** — all patterns are matched case-insensitively; write them lowercase
- **No duplicates** — the engine deduplicates on build, but keeping the source clean is easier to review
- **Correct `BlockType`** — use `Geo` for geographic restriction pages, `Waf` for challenge/bot-check pages, `Captcha` for explicit captcha widgets, `Api` for API error bodies

The specificity scorer already penalises short ambiguous patterns — if your pattern is short, test it doesn't fire on normal pages.

---

## Code style

- Follow the existing module structure — new logic belongs in the appropriate module, not in `main.rs`
- No `unwrap()` in production paths — use `?` or explicit error handling
- No `println!` in library code — use `tracing` events or scanner evidence fields
- Tests belong next to the code they test in `#[cfg(test)]` modules
- Run `cargo clippy -- -D warnings` before submitting — the CI gate enforces zero warnings

---

## Pull request checklist

- [ ] `cargo test` passes with no failures
- [ ] `cargo clippy -- -D warnings` reports zero warnings
- [ ] New functionality has at least one unit test
- [ ] `profiles.toml` changes do not break existing `service_profiles::tests`
- [ ] Signature changes do not regress `signatures::tests`
- [ ] Description explains *why* the change matters, not just what it does

---

## Reporting issues

When reporting a detection bug (wrong verdict for a domain):

1. Specify the domain and the expected verdict
2. Specify whether you used a control proxy and what kind
3. If possible, run with `--verbose` and paste the relevant evidence lines
4. Mention your region / ISP if relevant — the same domain can behave differently by location

---

## License

By contributing, you agree that your contribution is licensed under the [AGPL-3.0 License](LICENSE).
