# Bulbascan Shared AI Memory

## Project

Bulbascan is a Rust CLI for high-speed selective-proxy scanning, geo-block detection, and routing list generation.

## Technical Context

- This is a pure Rust CLI/binary project.
- Prioritize network-systems correctness over generic app conventions.
- Core goal: distinguish dead domains, ISP/DPI blocking, geo-blocks, WAF/captcha behavior, and proxy-required routing with minimal false positives.
- Primary areas:
  - `src/scanner/` — core scan engine
  - `src/progress.rs` — live console progress and scan UX
  - `src/geosite.rs` — geosite/rule compilation
  - `src/signatures.rs` — block signature engine
  - `src/router_exports.rs` — router/export outputs

## Engineering Preferences

- Favor performance-aware Rust design in hot paths.
- Use `anyhow` for fallible application flows.
- Avoid `unwrap()` outside tests unless failure is truly unrecoverable.
- Preserve dual-vantage validation logic when touching block-classification behavior.
- Keep docs aligned with actual code state.
- Before implementing a feature, first verify whether the relevant external technical guidance or ecosystem behavior has changed.
- For scanning, anti-bot, DNS, transport, browser, or proxy-related features: check current external sources first, then implement against the verified baseline instead of relying only on older local assumptions.

## Working With This Project

- Start by checking the current branch, local diff, and whether there are unrelated uncommitted changes.
- Treat runtime artifacts and personal local state separately from code changes; do not mix them into feature commits.
- When implementing a feature:
  1. inspect the current local implementation
  2. verify current external guidance when the topic is ecosystem-sensitive
  3. create a dedicated feature branch from `nightly`
  4. implement the smallest coherent slice that is worth reviewing
  5. run `cargo fmt`, `cargo check`, and `cargo test`
  7. open a PR into `nightly`
- Use the `<your-name>/feature/<name>` branch naming pattern.
- Do not bundle unrelated cleanup into a feature PR unless it is truly incidental and low risk.
- If local unrelated changes already exist, review them separately and commit them separately.
- Prefer strict, reviewable increments over large “finish everything at once” branches.

## Git Workflow

Current branch model:

- `feature/*` — one task per branch
- `nightly` — newest integrated feature work, accepts feature PRs
- `dev` — periodic promoted/stabilized branch from `nightly`
- `main` — stable branch and release source

Flow:

1. Start new work from `nightly`.
2. Create a dedicated `feature/<name>` branch.
3. Open PRs from `feature/*` into `nightly`.
4. Promote `nightly` into `dev` weekly or monthly after enough changes accumulate.
5. Test and stabilize in `dev`.
6. Merge `dev` into `main` when ready to release.
7. Create release tags from `main`.

Rules:

- Do not use a dedicated release branch unless the team explicitly restores that workflow.
- Do not merge unrelated features together in one feature branch.
- Prefer PR-based merges into `nightly`, `dev`, and `main`.
- Changes to workflow, contributor process, agent instructions, or CI should go through a dedicated PR into `nightly`, not as part of an unrelated feature PR.
- Direct commits without PR are acceptable only for local-only or personal environment changes that do not affect other contributors.

## Documentation Note

If project workflow or branch strategy changes, update this shared memory so all assistants follow the same process.
