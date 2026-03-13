# Roadmap

---

## v0.1.2 — Signal Quality

(All planned features for this release have been implemented or moved to future releases)

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
