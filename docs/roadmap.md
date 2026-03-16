# Roadmap

---

## v0.1.3 — Active Development

> Primary goal: improve selective-proxy accuracy for country-level blocking detection.
>
> Bulbascan is not trying to become a full browser-bypass platform. The priority is reliable classification:
> `DirectOk` vs `ProxyRequired` vs `ManualReview`, with fewer false positives from WAFs, captchas, DNS poisoning, and transport-level censorship.

## Core Accuracy

- **DNS-level block detection**
  - Compare system DNS vs DoH answers to detect NXDOMAIN injection and poisoned blockpage IPs.
  - Record DNS disagreement as first-class evidence in scan results and comparison reports.
  - Distinguish "DNS manipulated locally" from "domain genuinely dead globally".

- **Dual-vantage confidence improvements**
  - Tighten `ConfirmedProxyRequired` vs `CandidateProxyRequired` promotion rules.
  - Reduce false `ConsistentBlocked` outcomes caused by weak or same-region control proxies.
  - Surface clearer reasoning when the control path proves direct access but the local path is challenged or blocked.

- **Browser verification as a confirmation layer**
  - Keep browser verification focused on confirming challenge pages, geo walls, and selective WAF behavior.
  - Avoid promoting the browser path into the primary detector when HTTP/DNS/TLS evidence is already sufficient.
  - Improve challenge-page labeling so captchas and WAF interstitials produce cleaner `ManualReview` vs `ProxyRequired` outcomes.

- **Service-profile coverage**
  - Expand `profiles.toml` so major blocked services expose enough critical-role coverage for reliable service-level decisions.
  - Improve per-service reasoning when only partial host coverage is observed.

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
