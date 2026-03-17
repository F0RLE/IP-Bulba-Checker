# Roadmap

---

## v0.1.3 — Active Development

> Primary goal: improve selective-proxy accuracy for country-level blocking detection.
>
> Bulbascan is not trying to become a full browser-bypass platform. The priority is reliable classification:
> `DirectOk` vs `ProxyRequired` vs `ManualReview`, with fewer false positives from WAFs, captchas, DNS poisoning, and transport-level censorship.

### Scan Follow-up Plan

The latest large RU-blocked scan exposed a few concrete bottlenecks:

- `ManualReview` is still too high on bulk runs.
- `ConfirmedProxyRequired` is useful, but the strict list is still much smaller than the ambiguous set.
- Captcha / challenge-heavy hosts dominate `ManualReview`.
- Service-level geo summaries are still thin because critical-role coverage is incomplete.
- A non-trivial number of comparison rows still come from weak or noisy transport outcomes.

Near-term priorities are therefore:

1. Reduce challenge-heavy `ManualReview` pressure without turning browser verification into the primary detector.
2. Tighten comparison quality so weak control-path or worker-noise cases stop polluting dual-vantage output.
3. Expand service-profile critical-role coverage for the small set of services that matter operationally.
4. Keep strict exports as the default publication-grade artifact until the broad local routing list becomes less noisy.

## Core Accuracy

- **DNS-level block detection:** completed
  - Compare system DNS vs DoH answers to detect NXDOMAIN injection, resolver failures, and suspicious poisoned-answer mismatches.
  - Record DNS disagreement as first-class evidence in scan results and comparison reports.
  - Distinguish stronger cases such as "local DNS manipulation suspected", "resolver unhealthy", and "DNS mismatch confirmed by failed direct tcp/tls".

- **Dual-vantage confidence improvements**
  - Tighten `ConfirmedProxyRequired` vs `CandidateProxyRequired` promotion rules.
  - Reduce false `ConsistentBlocked` outcomes caused by weak or same-region control proxies.
  - Surface clearer reasoning when the control path proves direct access but the local path is challenged or blocked.
  - Add a second pass for noisy `NeedsReview` comparison rows:
    - suppress technical noise like `worker error`
    - distinguish control-healthy ambiguity from transport-failure ambiguity
    - emit cleaner top-level buckets for publication decisions
  - Current status: partially implemented; `NeedsReview` now distinguishes control-path ambiguity from transport ambiguity, but broader comparison cleanup is still needed after the latest bulk scan.

- **Browser verification as a confirmation layer**
  - Keep browser verification focused on confirming challenge pages, geo walls, and selective WAF behavior.
  - Avoid promoting the browser path into the primary detector when HTTP/DNS/TLS evidence is already sufficient.
  - Improve challenge-page labeling so captchas and WAF interstitials produce cleaner `ManualReview` vs `ProxyRequired` outcomes.
  - Add a browser budget for bulk runs so large scans do not spend disproportionate time on long-tail challenge pages.
  - Prefer challenge-family clustering over repeated browser confirmation for obviously similar host fleets.
  - Current status: completed for the current scope; bulk runs now cap total browser confirmations and per-domain browser paths, known challenge headers such as `cf-mitigated: challenge` and `x-amzn-waf-action=captcha|challenge` are labeled more precisely, and repeated browser confirmation is skipped for challenge families already confirmed earlier in the same scan.

- **Service-profile coverage**
  - Expand `profiles.toml` so major blocked services expose enough critical-role coverage for reliable service-level decisions.
  - Improve per-service reasoning when only partial host coverage is observed.
  - Current status: partially implemented; service coverage now supports multi-role hosts for products that expose auth/app/playback on the same public domain, but more host-level coverage is still needed for API- and console-heavy services.
  - Immediate targets from the latest scan:
    - OpenAI (`auth`, `api`)
    - Anthropic (`console`, `api`)
    - TikTok (`web`, `app`)
    - Wise (`auth`, `api`)
    - Disney+ (`playback`)
    - Deezer (`player`)

## Performance & Scale

- **Concurrent Domain Ingestion**
  - Parallelize large input file loading to reduce startup latency on community blocklists.

- **Moving Average Speed Smoothing:** completed
  - Progress bar speed now uses a 3-second moving window for more stable throughput and ETA metrics.

## Network & Transport Research

- **ECH (Encrypted Client Hello) Support**
  - Add optional ECH probing for targets and CDNs that publish usable ECH configuration.
  - Treat ECH as an additional research/detection signal, not as a universal bypass path.

- **XHTTP & HTTP/3 Probing**
  - Evaluate Xray XHTTP and HTTP/3/QUIC as secondary transports for domains that are ambiguous over the default path.
  - Only keep this if it materially improves classification quality for selective proxy lists.

## Output & Export Formats

- **Direct `.srs` (sing-box Rule Set v4) Compilation**
  - Generate binary sing-box rule sets directly for lower-memory router deployments.

- **Mihomo Rule-Set (`.mrs`) Export**
  - Add export support for current Mihomo / Clash rule-set consumers.

- **GeoIP `geoip.dat` Generation**
  - Aggregate IP-level evidence into GeoIP-oriented outputs where that signal is stable enough to trust.

## Tooling & Operator UX

- **Global Configuration (`bulbascan.toml`)**
  - Persist defaults for proxies, timeouts, output modes, and comparison settings.

- **Enhanced Scan Reports**
  - Add confidence summaries, better explanation of `ManualReview`, and clearer per-service output for non-expert operators.
  - Current status: completed for the current scope.
  - Reports now include:
    - confidence summaries
    - `ManualReview` hotspot reporting by root cause with operator guidance
    - publication guidance in `validation_report.txt`
    - service publication tiers in `service_geo_report.txt`

- **Incremental Publishing Workflow**
  - Publish strict artifacts from the confirmed comparison set on short intervals.
  - Keep broader local-only proxy candidates in a lower-trust tier until they survive later refresh cycles.
  - Support hot / warm / cold rescan queues for very large domain universes instead of trying to refresh everything every cycle.

- **Cross-platform runtime hardening**
  - Improve browser auto-detection so Windows, macOS, and Linux builds can find Chrome / Chromium / Edge more reliably.
  - Reduce terminal/UI variance by falling back cleanly when ANSI or VT sequences are not supported.
  - Keep browser-assisted confirmation behavior as consistent as practical across supported desktop platforms.
  - Current status: completed for the current scope; browser auto-detection now checks env overrides, `PATH`, and common install locations across Windows, macOS, and Linux, and the progress UI falls back to plain text when ANSI / VT support is unavailable.

## Experimental

- **AI Labyrinth / visibility-safe interaction**
  - If interactive browser automation expands, ensure the scanner never interacts with invisible honeypot links or decoy elements.
  - Keep this scoped to browser confirmation flows only.

- **CapSolver / 2Captcha hooks**
  - Explore only if challenge-solving becomes necessary for materially better classification.
  - Do not make paid captcha-solving a hard dependency of normal scanning.

- **HTTP-level IP spoofing**
  - Experimental only. Keep disabled by default unless it produces measurable classification value without increasing false positives.

- **Daemon / REST API Mode**
  - Lower priority than classification accuracy. Consider only after the detection pipeline stabilizes.
