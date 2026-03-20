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
    │       ├── transport.rs   reqwest/rustls primary path → fallback reqwest client
    │       ├── network.rs     DNS / TCP / TLS evidence
    │       ├── analysis.rs    verdict + confidence
    │       ├── browser.rs     Chromium DOM dump + classification
    │       ├── comparison.rs  local vs control-proxy diff
    │       └── reports.rs     text reports
    │
    ├─► progress.rs ── realtime console progress bar
    ├─► pipeline.rs ── assemble blocked domain lists, write files
    ├─► router_exports.rs ── sing-box / Xray / OpenWRT exports
    └─► geosite.rs ── protobuf geosite.dat compiler
```

---

## Module reference

### `src/`

| Module | Responsibility |
|---|---|
| `main.rs` | Entry point. Orchestrates scan loop and output stages. |
| `cli.rs` | `Args` struct, enums, domain input parsing, path helpers. |
| `progress.rs` | Realtime dynamic console UI (`LiveBar`), live configuration rendering. |
| `pipeline.rs` | Filtering pending domains, assembling blocked lists, writing output files. |
| `signatures.rs` | Aho-Corasick engine for body/header/API patterns. UA pool. |
| `service_profiles.rs` | OnceLock TOML registry: 38 services → host roles → probe paths. |
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
Accessible        ─ normal HTTP response, no block signals
GeoBlocked        ─ strong geo restriction signal (body/redirect/status/451)
WafBlocked        ─ WAF actively blocking (not just CDN presence)
Captcha           ─ challenge / bot-check page
NetworkBlocked    ─ ISP-level block (Rostelecom, Beltelecom, etc.)
ApiBlocked        ─ JSON API returned geo/access-denied error
RateLimited       ─ HTTP 429 / rate-limit signature matched
UnexpectedStatus  ─ non-2xx without a known block signature
TlsFailure        ─ TLS handshake / certificate error
Unreachable       ─ TCP timeout / DNS failure
```

> **RoutingDecision** (derived from verdict + confidence):
> `ProxyRequired` · `DirectOk` · `ManualReview`
>
> **ComparisonDecision** (dual-vantage output):
> `ConfirmedProxyRequired` · `CandidateProxyRequired` · `ConsistentBlocked` · `ConsistentDirect` · `NeedsReview`

> [!IMPORTANT]
> `ProxyRequired` from a local-only scan is not the same thing as a strict publishable routing decision.
> The most reliable operational outputs come from dual-vantage comparison, especially `ConfirmedProxyRequired`,
> plus the publication tiers built on top of that comparison.

> [!NOTE]
> `ConsistentBlocked` means **both** local and control-proxy paths are blocked. This
> could mean the site is dead globally, OR the control proxy is in the same blocked
> jurisdiction as the local path. An external (EU/US) proxy is required to
> correctly separate geo-blocks from genuinely dead domains.

---

## Dual-vantage accuracy model

The scanner classifies each domain independently on two paths:

```
Local path  (home/residential IP in blocked country)
     │
     ├── Accessible → DirectOk
     ├── GeoBlocked / WAF / Captcha → compare with control
     └── Unreachable (timeout) → compare with control

Control path  (MUST be external EU/US proxy)
     │
     ├── DirectOk  + Local blocked → ConfirmedProxyRequired  ✅
     ├── DirectOk  + Local timeout → ConfirmedProxyRequired  ✅ (strong ISP/DPI suspicion)
     └── Blocked   + Local blocked → ConsistentBlocked       (dead or same region)
```

Key invariant: **the value of the tool scales directly with the geographic distance
between local path and control proxy**. Same-country proxy = useless for detecting
national-level blocks.

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

Service-level `ConfirmedGeoBlocked` requires:
1. All **critical roles** observed
2. Strong enough comparison decisions across critical-role hosts

Service-level `LikelyGeoBlocked` is still useful, but it is weaker than confirmed service-level separation and should stay out of strict publish/export tiers.

Unknown (non-profiled) domains use conservative apex-level logic.

---

## Signature engine

`BlockMatcher` is built once at startup via `BlockMatcher::new(signatures_file)`:

1. Loads compiled-in header/body/API patterns from `SIGNATURES_*` constants
2. Optionally merges user-supplied patterns from a plain-text file
3. Deduplicates and builds three Aho-Corasick automata (headers / body / API)
4. `find_body()` / `find_header_pairs()` / `find_api()` return the **highest-specificity** match

Specificity scoring avoids false positives from short generic patterns (e.g. `blocked`, `forbidden`).
