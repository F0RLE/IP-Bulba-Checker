# Roadmap

---

## v0.1.1 — Detection Accuracy

### Multi-probe consensus (~80 lines)
For ambiguous results (confidence 60–85), run 2–3 probes to different `probe_paths`. Require ≥2/3 agreement before finalising. Disagreement → `NeedsReview`. Reduces single-probe noise on flaky targets.

### Two-phase header classification (~40 lines)
Split `SIGNATURES_HEADERS` into CDN-presence (informational, confidence capped at 35 — already done on 200 OK via status-gating) and CDN-active-block (full confidence 84). Eliminate short generic patterns from the CDN-presence set so they never score on non-error responses. Completes the intent of the existing status-gating logic.

### Domain confidence adjustment (~20 lines)
Known service with `browser_verification = true` → +5 to captcha/geo confidence. Unknown domain without profile → -10 to WAF confidence. Currently all domains get identical confidence scoring regardless of their profile membership.

### Infra domain marker expansion (~15 lines)
`INFRA_DOMAIN_MARKERS` in `analysis.rs` is missing: `fastly`, `edgekey`, `edgesuite`, `azurewebsites`, `azureedge`, `trafficmanager` (already present but check scope). These are causing occasional WAF false-positives on infrastructure apex roots.

---

## v0.1.2 — Signal Quality

### Redirect chain deep scan (~60 lines)
`classify_redirect()` in `analysis.rs` checks only the final URL. Extend to inspect intermediate redirect hops. Some geo-blocks do a two-step redirect through a neutral CDN URL before landing on a blockpage.

### DOM-aware body scoring (~100 lines)
Weight body matches by HTML location: `<title>` = strongest, `<h1>` = strong, body text = weak. Pages with >20 `<a>` links get penalty halved (real pages have navigation; block pages don't). Requires a lightweight HTML tag scanner — no full DOM parser needed.

### `UnexpectedStatus` reclassification via comparison (~30 lines)
`UnexpectedStatus` (non-2xx without a block signature) always routes to `ManualReview`. When control proxy is present: if local = `UnexpectedStatus` and control = `DirectOk` → upgrade to `CandidateProxyRequired`. `comparison.rs` already handles `ConfirmedProxyRequired` and `CandidateProxyRequired` but misses this specific gap. Reduces manual review queue substantially.

### Confidence boost on consistent network evidence (~20 lines)
In `comparison.rs`, when local TCP/TLS fails but control path DNS resolves → already adds a network note. Extend: when network evidence strongly indicates ISP-level block (local tcp/443 fail + local DNS NXDOMAIN + control path DNS ok) → boost `CandidateProxyRequired` → 90+ confidence. `NetworkEvidence` struct already tracks all required fields.

---

## v0.1.3 — Transport Layer

### DNS-level block detection (~150 lines)
Before HTTP probing, compare ISP DNS response (`resolve_host()` in `network.rs` — uses system DNS) with DoH response (`resolve_host_via_path_dns()` — already uses Cloudflare/Google DoH). Detect NXDOMAIN injection, blockpage IP substitution, and DNS poisoning. `NetworkEvidence.dns` and `NetworkEvidence.path_dns` are already populated — just need IP comparison logic in `compare_network_evidence()` to emit a verdict, not just a note.

### SNI-based block detection (~120 lines)
`probe_tls_443()` in `network.rs` already sends a TLS ClientHello with the target SNI. Extend: if TCP 443 succeeds but TLS handshake resets (already captured in `tls_443.status`) → emit `TlsFailure` with SNI-block reason. Also probe the same IP with a benign SNI (e.g. `cloudflare.com`) — if that succeeds → confirmed SNI block. Uses existing `tokio-rustls` setup.

### ECH probing (~100 lines)
When domain publishes ECH keys in DNS HTTPS record (type 65), attempt TLS with ECH enabled. If ECH succeeds where plain SNI was blocked → confirmed SNI censorship. `rustls` 0.23+ supports ECH experimentally. Pairs with the DNS probe to detect ECH-aware DPI.

### IPv6 dual-stack probing (~60 lines)
Extend `collect_network_evidence()` in `network.rs` to probe AAAA records alongside A records. Report when IPv4 is blocked but IPv6 works. `reqwest` and `tokio` support IPv6 natively. Add `ipv6` field to `NetworkEvidence`.

---

## v0.1.4 — Output & Export Formats

### `geoip.dat` generation (~150 lines)
DNS-resolve blocked domains → collect A/AAAA records → aggregate into CIDR subnets → compile into V2Ray `GeoIP` protobuf binary. Same `prost` setup already used in `geosite.rs`. No new dependencies needed.

### Clash / Mihomo rule-set export (~50 lines)
Add a `write_clash_rule_set()` to `router_exports.rs` using the existing `RouterExportSpec` pattern:
```yaml
payload:
  - DOMAIN,blocked.com
  - DOMAIN-SUFFIX,blocked.com
```
`RouterExportSpec` is already factored as a generic over domain lists — adding a new format is mechanical.

### Shadowrocket / NekoBox config export (~40 lines)
```ini
[Rule]
DOMAIN,blocked.com,PROXY
DOMAIN-SUFFIX,blocked.com,PROXY
```
Same pattern as Clash export.

### Import helpers (~80 lines)
Parse existing block lists: Clash `.yaml`, Shadowrocket, NekoBox/Mihomo → extract domain list for scanning. Currently only `geosite.dat` binary and plain `.txt` are supported as input. `normalize_domain()` in `cli.rs` already handles most prefix formats.

### JSON result export (~50 lines)
`--format json` is parsed in `Args` but the JSON branch is likely a stub. `ScanResult` already derives `Serialize` — just needs a writer that emits `Vec<ScanResult>` as JSON to a file instead of only text reports.

---

## v0.1.5 — State & Workflow

### State expiry / TTL (~40 lines)
`LocalState` in `state.rs` stores blocked/direct forever. Add a timestamp per domain (store as `domain\ttimestamp` in the text file). On load, expire entries older than N days (configurable via `--state-ttl-days`). Prevents stale direct-ok entries from masking newly-blocked domains after ISP policy changes.

### Multi-file state merge (~30 lines)
Currently `--state-dir` is a single directory. Add `--merge-state-dir` to ingest another state directory and union the sets before scanning. Useful when combining results from multiple machines or network vantage points.

### Auto-rescan of `manual_review` bucket (~20 lines)
`manual_review.txt` entries are always rescanned, but there is no mechanism to promote them after N failed rescans. Add a counter per domain — after 3 consecutive `ManualReview` results with no resolution, downgrade to `direct.txt` with a note, or flag as permanently inconclusive.

---

## v0.1.6 — Developer & Quality

### `--dry-run` mode (~20 lines)
Parse all inputs, validate proxy, check signatures, print a summary of what would be scanned — without making any network requests. Useful for CI validation of config files.

### Structured JSON logging with `--log-json` (~30 lines)
Emit each scan result as a newline-delimited JSON (`ndjson`) stream to stderr while the scan runs. Enables piping into `jq`, log aggregators, or future UI tools.

### Benchmark / regression test suite
A curated set of domains with known expected outcomes (annotated as `geo domain.com`, `direct domain.com`, etc.) that runs via `cargo test` using mocked HTTP responses. `validation.rs` already has the `ExpectedOutcome` and bucket machinery — just needs a fixture-based test harness.

### Windows starter pack
Release archive: `bulbascan.exe` + `profiles.toml` + `example-domains.txt` + `QUICKSTART.txt` (3 lines). Reduces friction for non-technical users from target audience.
