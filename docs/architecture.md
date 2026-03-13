# Architecture

> Current module layout.

---

## High-level flow

```
Input files
    │
    ▼
cli.rs ──── parse arguments, normalise domains
    │
    ▼
main.rs ─── orchestrate scan → write outputs
    │
    ├─► scanner.rs ── async worker pool, progress bar
    │       ├── transport.rs   wreq (primary) → reqwest (fallback)
    │       ├── network.rs     DNS / TCP / TLS evidence
    │       ├── analysis.rs    verdict + confidence
    │       ├── browser.rs     Chromium DOM dump + classification
    │       ├── comparison.rs  local vs control-proxy diff
    │       └── reports.rs     text reports
    │
    ├─► progress.rs ── realtime console progress bar logic
    │
    ├─► pipeline.rs ── assemble blocked domain lists, write files
    │
    └─► router_exports.rs ── sing-box / Xray / OpenWRT / geosite.dat
```

---

## Module reference

### `src/`

| Module | Responsibility |
|---|---|
| `main.rs` | Entry point (~770 lines). Orchestrates the scan loop and output stages. |
| `cli.rs` | `Args` struct, enums, domain input parsing, path helpers. |
| `progress.rs` | Realtime dynamic console UI (`LiveBar`), live configuration rendering. |
| `pipeline.rs` | Filtering pending domains, assembling blocked lists, writing output files. |
| `signatures.rs` | Aho-Corasick engine for body/header/API patterns. UA pool. |
| `service_profiles.rs` | OnceLock TOML registry: 27 services → host roles → probe paths. |
| `state.rs` | Incremental scan state (blocked / direct / review buckets). |
| `router_exports.rs` | sing-box, Xray, OpenWRT, strict/known-service/apex exports. |
| `geosite.rs` | Protobuf `geosite.dat` compiler. |
| `radar.rs` | Cloudflare Radar API client. |
| `validation.rs` | Expected-outcome validation reports. |
| `xray.rs` | Local Xray SOCKS bootstrap from `vless://` link. |

### `src/scanner/`

| File | Responsibility |
|---|---|
| `scanner.rs` | Worker pool, browser/runtime coordination, progress bar. |
| `types.rs` | `ScanResult`, `Verdict`, `EvidenceBundle`, `ComparisonResult`. |
| `analysis.rs` | Body/status/redirect classification, infra relaxation, retest stabilisation. |
| `network.rs` | DNS checks, TCP timing, TLS failure classification. |
| `comparison.rs` | Control-proxy comparison decisions, service-level geo aggregation. |
| `reports.rs` | Human-readable scan report generation. |
| `browser.rs` | Chromium discovery, browser-proxy wiring, DOM dump. |
| `transport.rs` | Request retry, fallback client, control-proxy preflight. |

---

## Verdict model

```
Accessible      ─ no block signals, normal HTTP response
GeoBlocked      ─ geo restriction page confirmed (body/redirect/status)
Captcha         ─ challenge / bot-check page (may be geo or WAF)
WAF             ─ WAF actively blocking (not just present)
ProxyRequired   ─ comparison: control-proxy ok, local blocked
NeedsReview     ─ ambiguous, flagged for manual check
Dead            ─ unreachable on all transports
```

---

## Service model

Known services are structured as:

```
ServiceProfile
  ├── name                   ("OpenAI")
  ├── browser_verification   (true/false)
  ├── expected_roles         (["web", "auth", "api", "console", "assets"])
  ├── critical_roles         (["web", "auth", "api"])
  └── hosts[]
        ├── domain           ("api.openai.com")
        ├── role             ("api")
        └── probe_paths      (["/"])
```

Service-level verdict requires:
1. All **critical roles** observed
2. Comparison decisions across critical-role hosts agree

Unknown (non-profiled) domains use conservative apex-level logic.

---

## Signature engine

`BlockMatcher` is built once at startup via `BlockMatcher::new(signatures_file)`:

1. Loads compiled-in header/body/API patterns from `SIGNATURES_*` constants
2. Optionally merges user-supplied patterns from a plain-text file
3. Deduplicates and builds three Aho-Corasick automata (headers / body / API)
4. `find_body()` / `find_header_pairs()` / `find_api()` return the **highest-specificity** match

Specificity scoring avoids false positives from short generic patterns (e.g. `blocked`, `forbidden`).
