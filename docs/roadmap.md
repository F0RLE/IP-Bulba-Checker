# Roadmap

---

## v0.1.2 — Signal Quality

### Proxy geo-location validation (~40 lines)
Before running the comparison scan, check the external IP of the control proxy (e.g. via `https://ipinfo.io`) and compare its country/AS against the local external IP. If both are in the same country or same AS, emit a clear warning:
```
[WARN] Control proxy appears to be in the same country (BY/RU) as local path.
       Geo-blocking will NOT be detectable. Use an external EU/US proxy.
```
Prevents the silent case where users get ~0 confirmed results and don’t know why.

### Smart comparison pre-filter (~50 lines)
The comparison scan currently re-runs the ENTIRE pending domain list through the control proxy. Domains classified as `direct_ok` locally do not need comparison. Filter to only re-run: `unreachable`, `manual_review` (WAF/captcha/unexpected), and `proxy_required`. Reduces comparison scan size by ~55% on a typical ru-blocked list (direct\_ok ~41K of 75K) and cuts total dual-vantage time roughly in half.

### CF clearance extraction after browser verify (~60 lines)
When browser verify successfully passes a Cloudflare managed challenge, the browser holds a valid `cf_clearance` cookie that is currently discarded. Extract it from the session, replay the HTTP request via `wreq` with that cookie, and classify the real page content. Lets the scanner correctly resolve Cloudflare-protected geo-blocks instead of leaving them in `captcha`/`manual_review`.

### Warmed browser session pool (~100 lines)
Each `--browser` verify spawns a fresh headless browser per domain — slow and detectable by Cloudflare Bot Management (new fingerprint, no history). Replace with a small persistent pool (1–3 sessions). Sessions accumulate cookies, localStorage, and TLS history, making challenges significantly easier to pass and improving throughput.

### Redirect chain deep scan (~60 lines)
`classify_redirect()` in `analysis.rs` checks only the final URL. Extend to inspect intermediate redirect hops. Some geo-blocks do a two-step redirect through a neutral CDN URL before landing on a blockpage.

### DOM-aware body scoring (~100 lines)
Weight body matches by HTML location: `<title>` = strongest, `<h1>` = strong, body text = weak. Pages with >20 `<a>` links get penalty halved (real pages have navigation; block pages don't). Requires a lightweight HTML tag scanner — no full DOM parser needed.

### `UnexpectedStatus` reclassification via comparison (~30 lines)
`UnexpectedStatus` (non-2xx without a block signature) always routes to `ManualReview`. When control proxy is present: if local = `UnexpectedStatus` and control = `DirectOk` → upgrade to `CandidateProxyRequired`. `comparison.rs` already handles `ConfirmedProxyRequired` and `CandidateProxyRequired` but misses this specific gap. Reduces manual review queue substantially.

### Confidence boost on consistent network evidence (~20 lines)
In `comparison.rs`, when local TCP/TLS fails but control path DNS resolves → already adds a network note. Extend: when network evidence strongly indicates ISP-level block (local tcp/443 fail + local DNS NXDOMAIN + control path DNS ok) → boost `CandidateProxyRequired` → 90+ confidence. `NetworkEvidence` struct already tracks all required fields.

### Compare-Scan UI Polish (~20 lines)
When using `--control-proxy`, the second scan's progress bar overwrites the end-of-scan export messages from the first run, and the dynamic `workers` count (set via up/down arrows) is reset back to the startup default. Need to cleanly separate the two logs and pass the final `workers` value into the comparison `run_scan()`.

### Extract Control-Scan into Dedicated Function (~50 lines)
The control-proxy comparison logic is currently inlined in `main()`, making it >250 lines long and hard to follow. Extract into `run_comparison_scan(domains, control_proxy, concurrency, args, scan_results) -> anyhow::Result<()>` in a new `comparison.rs` (or alongside `pipeline.rs`). `main()` becomes a thin orchestrator: load → scan → compare (if proxy) → export. No behaviour change — pure structural refactor.

### Configurable DOM Geo-markers (~40 lines)
`browser_title_supports_geo` in `analysis.rs` currently hardcodes Russian/Ukrainian keywords (`"недоступ"`, `"регион"`, etc.). Extract these into `profiles.toml` or a dedicated signature file to decouple the core logic from specific locales.

### Adaptive Body Skip Threshold (~10 lines)
Currently, HTTP 200 responses with body size >32KB skip signature scanning. Enhance `skip_body_scan` to dynamically adjust this threshold based on the `Content-Type` (e.g., skip 100% of large binaries, but scan text up to 100KB if the profile specifically expects large WAF pages).

### 429 Exponential Backoff (~30 lines)
`RateLimited` (HTTP 429) responses currently retry with the same flat `retest_backoff_ms` as any other transient result. Add a dedicated 429 path in `scan_domain()`: on 429, extract `Retry-After` header (if present), clamp to 1–30s, and use exponential backoff with jitter for up to 3 attempts before giving up. Prevents hammering services that are actively rate-limiting and improves accuracy on legitimate sites.

### Deduplicate Body Readers (~20 lines)
`read_wreq_body_limited()` and `read_reqwest_body_limited()` in `scanner.rs` are identical byte-for-byte except for the type of `response`. Extract into a single generic `read_body_limited<R: AsyncRead>(...)` or a helper trait. Pure DRY refactor, no behaviour change.

### `send_via_reqwest` ignores proxy / timeout args (~5 lines)
In `transport.rs` `send_via_reqwest()` accepts `proxy`, `timeout_secs`, and `max_redirects` arguments but all three are prefixed with `_` and silently ignored (lines 167–170). The function always uses the pre-built fallback client's settings. Either wire these params in (build client per-call) or remove the dead arguments to avoid false confidence.

### Proxy rotation is global-counter-only (~30 lines)
In `scanner.rs` the proxy is picked as `proxies[idx % proxies.len()]` using a shared `AtomicUsize`. This round-robins all workers across all proxies uniformly, but doesn't account for proxy latency or failure rate. Add a simple sticky failure counter per proxy index: if a proxy fails N consecutive times, skip it and fall back to the next healthy one.

---

## v0.1.3 — Transport Layer

### DNS-level block detection (~150 lines)
Before HTTP probing, compare ISP DNS response (`resolve_host()` in `network.rs` — uses system DNS) with DoH response (`resolve_host_via_path_dns()` — already uses Cloudflare/Google DoH). Detect NXDOMAIN injection, blockpage IP substitution, and DNS poisoning. `NetworkEvidence.dns` and `NetworkEvidence.path_dns` are already populated — just need IP comparison logic in `compare_network_evidence()` to emit a verdict, not just a note.

### SNI-based block detection (~120 lines)
`probe_tls_443()` in `network.rs` already sends a TLS ClientHello with the target SNI. Extend: if TCP 443 succeeds but TLS handshake resets (already captured in `tls_443.status`) → emit `TlsFailure` with SNI-block reason. Also probe the same IP with a benign SNI (e.g. `cloudflare.com`) — if that succeeds → confirmed SNI block. Uses existing `tokio-rustls` setup.

### DNS IP comparison in `compare_network_evidence` (~40 lines)
`compare_network_evidence()` in `comparison.rs` generates text notes when local DNS fails and control path DNS succeeds (lines 92–100), but **never compares the actual IP sets**. If local DNS returns a blockpage IP while control returns the real IP, the difference is invisible. Add `parse_ip_from_detail()` on `ProbeEvidence.detail` and compare local vs control resolved IPs — if they differ, emit a `dns_ip_mismatch` note that boosts `CandidateProxyRequired` confidence.

### TCP-80 probe result unused (~10 lines)
`collect_network_evidence()` in `network.rs` probes `tcp/80` and stores it in `NetworkEvidence.tcp_80`, but `compare_network_evidence()` in `comparison.rs` never reads it. Either use it (local tcp/80 up but local tcp/443 down → likely port-level block) or remove the probe to avoid dead runtime cost.

### IPv6 dual-stack probing (~60 lines)
Extend `collect_network_evidence()` in `network.rs` to probe AAAA records alongside A records. Report when IPv4 is blocked but IPv6 works. `reqwest` and `tokio` support IPv6 natively. Add `ipv6` field to `NetworkEvidence`.

---

## v0.1.4 — Output & Export Formats

### GeoIP — output: `geoip.dat` generation (~150 lines)
DNS-resolve blocked domains → collect A/AAAA records → aggregate into CIDR subnets → compile into V2Ray `GeoIP` protobuf binary. Same `prost` setup already used in `geosite.rs`, no new dependencies. Flag: `--emit-geoip geoip.dat`.

### GeoIP — input: `geoip.dat` import (~100 lines)
Mirror of `--import-geosite`: add `--import-geoip geoip.dat --import-geoip-category RU`. Decode CIDR blocks from the binary V2Ray `GeoIP` protobuf (same `prost` schema), then either reverse-rDNS each range or pass subnets directly as scan targets. Useful when the starting point is an IP blocklist rather than domain names.

### GeoIP — blockpage IP fingerprinting (~50 lines)
In `collect_network_evidence()`: if local DNS resolves to a known blockpage IP (built-in list or user file via `--blockpage-ips blockpage_ips.txt`), immediately emit a `dns_blockpage_ip` verdict with a confidence boost instead of a plain text note. Known examples: `95.213.255.1` (Rostelecom), `188.186.154.90` (MTS), `188.114.97.0/24` (Cloudflare WARP block range). Pairs with the DNS IP comparison item in v0.1.3.

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

### State: no `manual_review` counter / promotion logic (~30 lines)
`LocalState` in `state.rs` stores `manual_review` as a plain `BTreeSet<String>` with no per-domain counter. The roadmap item "auto-rescan" already tracks this — but the data model must change first: replace plain string with `(domain, attempt_count)` tuple stored as `domain\t<n>` in the file. `read_domain_file()` / `write_domain_file()` need updating before the promotion logic can be wired in.

### Periodic state flush (~30 lines)
With `--state-dir`, state is committed to disk only once at the very end of `main()`. If the user kills the process mid-scan or the proxy crashes, progress is lost. Add a periodic flush: every N domains processed (e.g. 1000), call `local_state.save(dir)`. The `save()` method already exists and is async.

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

### User-loadable signatures file (~80 lines)
`signatures.rs` currently compiles all block signatures (body, header, API patterns) into the binary as Rust `const` arrays. Add support for loading an optional `signatures.toml` alongside the executable that extends or overrides the built-in set. The `BlockMatcher::new(file)` path already accepts an `Option<&Path>` — it just needs a TOML parser for the same schema.

### Cancellable retry sleep (~10 lines)
In `scan_domain()`, the `tokio::time::sleep()` between retest attempts (line ~768) is not cancellation-aware. If the user presses `q` during the backoff sleep, the worker does not react until the sleep expires. Wrap with `tokio::select! { () = sleep => {}, () = ct.cancelled() => break }`.
