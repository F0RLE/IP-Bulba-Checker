# Contributing

Thank you for considering a contribution. This document explains how the project is structured, what kinds of contributions are most useful, and what the review criteria look like.

---

## Before you start

- Check the [roadmap](docs/roadmap.md) — the planned and known-issue sections are the best places to look for impactful work.
- Search existing issues before opening a new one.
- For large changes, open an issue first to discuss the approach.
- Project roles and ownership are described in [GOVERNANCE.md](GOVERNANCE.md).

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

### Recommended daily workflow

Use the host system as the default development environment:

- edit code locally in your normal editor
- run `cargo check`, `cargo test`, `cargo clippy -- -D warnings`, and `cargo build --release` natively unless you specifically want an isolated toolchain
- run browser-verification and network-sensitive scans on the host system, not inside a container

This project is sensitive to the real browser environment and the real network path, so native development is usually the least confusing option on Windows.

### Optional: Docker-based development

If you do not want to install Rust and build dependencies directly on your system, use the provided dev container:

```sh
docker build -f dev/Dockerfile.dev -t bulbascan-dev .
docker run --rm -it -v "$PWD:/workspace" -w /workspace bulbascan-dev cargo check
docker run --rm -it -v "$PWD:/workspace" -w /workspace bulbascan-dev cargo test
docker run --rm -it -v "$PWD:/workspace" -w /workspace bulbascan-dev cargo clippy -- -D warnings
```

Or use Docker Compose:

```sh
docker compose -f dev/docker-compose.dev.yml build
docker compose -f dev/docker-compose.dev.yml run --rm bulbascan-dev cargo check
docker compose -f dev/docker-compose.dev.yml run --rm bulbascan-dev cargo test
docker compose -f dev/docker-compose.dev.yml run --rm bulbascan-dev cargo clippy -- -D warnings
```

Included in the dev image:

- `cmake`
- `pkg-config`
- `clang`
- `perl`
- standard build tools

Note:

- this container is optional and intended for build/test/dev workflows
- real browser verification and real network-path debugging are still better tested on the host system

---

## Branch workflow

Bulbascan uses a simple staged branch model:

- `feature/*` — one feature or fix per branch
- `nightly` — integration branch for fresh feature work
- `dev` — stabilized branch promoted from `nightly`
- `main` — stable branch and release source

Expected flow:

1. Branch from `nightly`
2. Implement work in `feature/<name>`
3. Open a PR into `nightly`
4. Periodically promote `nightly` into `dev`
5. Test and stabilize in `dev`
6. Merge `dev` into `main` for release

Guidelines:

- Keep each feature branch focused on a single change
- Prefer PR-based merges for `nightly`, `dev`, and `main`
- Changes to workflow, CI, contributor process, or shared agent instructions should go through a dedicated PR into `nightly`
- Direct commits without PR are only acceptable for local-only changes that do not affect other contributors
- Do not use a dedicated release branch unless the workflow changes again
- If a roadmap item is completed, update `docs/roadmap.md` in the same PR when appropriate

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

- [ ] Branch targets the correct base (`nightly` for feature work unless explicitly coordinated otherwise)
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

By contributing, you agree that your contribution may be used in the project's dual-licensing model.

That means:

- the public repository is distributed under [AGPL-3.0](LICENSE)
- the project may also be offered under separate commercial licensing terms

Unless explicitly agreed otherwise in writing, contributions to this repository are accepted under the same terms as the repository itself and may be included in commercial distributions by the project owner.
