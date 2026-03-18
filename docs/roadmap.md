# Roadmap

---

## v0.1.3 — Active Development

> Primary goal: improve selective-proxy accuracy for country-level blocking detection.
>
> Bulbascan is not trying to become a full browser-bypass platform. The priority is reliable classification:
> `DirectOk` vs `ProxyRequired` vs `ManualReview`, with fewer false positives from WAFs, captchas, DNS poisoning, and transport-level censorship.

## Core Accuracy

- **DNS-level block detection**
  - Usefulness: 9/10
  - Status: completed
  - What it gives: stronger first-class DNS evidence for poisoned answers, resolver failures, and mismatch confirmation.
  - Implemented:
    - system DNS vs DoH comparison
    - resolver failure and health classification
    - DNS mismatch confirmation through failed direct TCP/TLS probes

- **Dual-vantage confidence improvements**
  - Usefulness: 8/10
  - Status: in progress
  - What it gives: cleaner `ConfirmedProxyRequired` vs `CandidateProxyRequired` outcomes and less noise in publication decisions.
  - Implemented:
    - `NeedsReview` already distinguishes control-path ambiguity from transport ambiguity
  - Remaining:
    - tighten promotion rules for `ConfirmedProxyRequired` vs `CandidateProxyRequired`
    - reduce false `ConsistentBlocked` from weak or same-region control proxies
    - improve reasoning when control is direct-ok but local is challenged or blocked
    - suppress remaining technical noise such as `worker error`

- **Browser verification as a confirmation layer**
  - Usefulness: 7/10
  - Status: completed
  - What it gives: a secondary confirmation layer for challenge-heavy and script-dependent targets without turning the browser path into the main detector.
  - Implemented:
    - cleaner challenge-page labeling for captcha and WAF interstitials
    - browser budget for bulk runs
    - challenge-family reuse to avoid repeated browser confirmation
    - more precise handling for headers such as `cf-mitigated: challenge` and `x-amzn-waf-action=captcha|challenge`

- **Service-profile coverage**
  - Usefulness: 8/10
  - Status: completed
  - What it gives: stronger service-level decisions by covering critical login, API, browser, and console surfaces.
  - Implemented:
    - multi-role hosts in `profiles.toml`
    - current official aliases such as `platform.claude.com`
    - richer login and browser probe paths
    - wider API- and auth-adjacent host coverage such as `developers.tiktok.com` and `connect.deezer.com`

## Performance & Scale

- **Concurrent Domain Ingestion**
  - Usefulness: 6/10
  - Status: completed
  - What it gives: lower startup latency on large or multi-file domain lists.
  - Implemented:
    - concurrent loading for plain-text input files
    - deterministic merge in source order
    - streaming line-by-line ingestion for proxy lists

- **Moving Average Speed Smoothing**
  - Usefulness: 5/10
  - Status: completed
  - What it gives: more stable progress speed and ETA during large scans.
  - Implemented:
    - 3-second moving-window throughput smoothing

## Network & Transport Research

- **ECH (Encrypted Client Hello) Support**
  - Usefulness: 4/10
  - Status: in progress
  - What it gives: an additional research signal for targets and CDNs that actually publish usable ECH configuration.
  - Remaining:
    - add optional ECH probing
    - keep it detection-oriented rather than treating it as a universal bypass path

- **XHTTP & HTTP/3 Probing**
  - Usefulness: 4/10
  - Status: in progress
  - What it gives: optional secondary transport evidence for domains that stay ambiguous over the default path.
  - Remaining:
    - evaluate Xray XHTTP as a secondary transport
    - evaluate HTTP/3/QUIC probing
    - keep this only if it materially improves classification quality

## Output & Export Formats

- **Direct `.srs` (sing-box Rule Set v4) Compilation**
  - Usefulness: 7/10
  - Status: completed
  - What it gives: lower-memory sing-box deployments through direct binary rule-set output.
  - Implemented:
    - `.srs` generation through local `sing-box` CLI when available
    - matching binary route snippets
    - JSON source rule sets kept as the portable baseline

- **Mihomo Rule-Set (`.mrs`) Export**
  - Usefulness: 6/10
  - Status: completed
  - What it gives: native output for Mihomo / Clash.Meta consumers.
  - Implemented:
    - Mihomo text rule sets and provider snippets by default
    - optional `.mrs` generation through local `mihomo` / `clash-meta` CLI
    - binary provider snippets when the compiler is available

## Tooling & Operator UX

- **Global Configuration (`bulbascan.toml`)**
  - Usefulness: 7/10
  - Status: completed
  - What it gives: persistent operator defaults without weakening CLI overrides.
  - Implemented:
    - optional `bulbascan.toml` auto-loading from the working directory
    - explicit `--config` override and `--no-config` escape hatch
    - precedence: `CLI/env > config file > built-in defaults`
    - persisted defaults for proxies, timeouts, output profile, browser path, results directory, and comparison settings

- **Enhanced Scan Reports**
  - Usefulness: 8/10
  - Status: completed
  - What it gives: clearer operator-facing outputs for publication and review decisions.
  - Implemented:
    - confidence summaries
    - `ManualReview` hotspot reporting by root cause with operator guidance
    - publication guidance in `validation_report.txt`
    - service publication tiers in `service_geo_report.txt`

- **Incremental Publishing Workflow**
  - Usefulness: 8/10
  - Status: completed
  - What it gives: staged publish artifacts and refresh queues instead of treating every scan as a full reset.
  - Implemented:
    - publication tiers (`publish-strict`, `publish-review`, `publish-direct`)
    - operator-facing `publication_report.txt`
    - hot / warm / cold rescan queue files
    - queue persistence into `--state-dir` for later cycles

- **Cross-platform runtime hardening**
  - Usefulness: 6/10
  - Status: completed
  - What it gives: more predictable behavior across Windows, macOS, and Linux.
  - Implemented:
    - browser auto-detection through env overrides, `PATH`, and common install locations
    - plain-text progress fallback when ANSI / VT support is unavailable
    - more consistent browser-assisted confirmation across supported desktop platforms

## Experimental

- **AI Labyrinth / visibility-safe interaction**
  - Usefulness: 3/10
  - Status: in progress
  - What it gives: safer browser automation if the confirmation layer becomes more interactive.
  - Remaining:
    - avoid hidden honeypot links and decoy elements
    - keep the scope limited to browser confirmation flows

- **Daemon / REST API Mode**
  - Usefulness: 4/10
  - Status: in progress
  - What it gives: service-style integration for other tools once the detection pipeline is stable enough.
  - Remaining:
    - only revisit this after classification accuracy work is largely closed
