<p align="center">
  <h1 align="center">🥔 Bulbascan</h1>
  <p align="center">
    <b>High-speed selective-proxy scanner for geo-block detection and geosite routing list generation.</b>
  </p>
  <p align="center">
    <a href="https://www.rust-lang.org"><img src="https://img.shields.io/badge/rust-1.94%2B-orange?logo=rust&logoColor=white" alt="Rust"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-red.svg" alt="License: AGPL-3.0"></a>
    <a href="https://github.com/F0RLE/Bulbascan/actions"><img src="https://img.shields.io/github/actions/workflow/status/F0RLE/Bulbascan/ci.yml?label=CI&logo=github" alt="CI"></a>
    <a href="https://github.com/F0RLE/Bulbascan/releases"><img src="https://img.shields.io/github/v/release/F0RLE/Bulbascan?include_prereleases&label=release" alt="Release"></a>
  </p>
</p>

---

## What it does

Bulbascan scans a list of domains and determines whether each one is:

| Verdict | Meaning |
|---|---|
| ✅ **Accessible** | Reachable directly — no proxy needed |
| 🌍 **GeoBlocked** | Geo-restriction or captcha confirmed |
| 🔀 **ProxyRequired** | Dual-vantage confirmed — must route through proxy |
| 🛡️ **WAF** | CDN/server actively blocking (Cloudflare, AWS WAF, etc.) |
| 🔍 **NeedsReview** | Ambiguous result — flagged for manual check |
| 💀 **Dead** | Unreachable on all transports |

Results are exported as **ready-to-use routing configs** for Xray, sing-box, OpenWRT PBR, and V2Ray `geosite.dat`.

### Live Scanner UI

While scanning, the real-time progress bar shows detailed statistics across two lines. The top line updates your current configuration, and the bottom line tracks progress.

<img width="1102" height="214" alt="Снимок экрана 2026-03-12 203858" src="https://github.com/user-attachments/assets/010c08a2-ef99-4444-970c-6cc05db2cf72" />

| Indicator       | Meaning |
|-----------------|---------|
| `Profile: Balanced` | Current speed tier (derived from worker count) |
| `Workers: 200`   | Active concurrency. Use **→**/**←** (tier jump) or **↑**/**↓** (±1) during the scan to dynamically adjust. |
| `1%`            | Percentage of the domain list processed so far |
| `1254/75018`     | Domains processed / Total domains in queue |
| `✓ 631`         | Domains confirmed **Accessible** (direct HTTP/TCP connection works) |
| `✗ 520`          | Domains confirmed **Blocked** (Geo-block, WAF, Captcha, or ISP redirect) |
| `○ 103`          | Domains confirmed **Dead** (Unreachable, NXDOMAIN, TCP timeout) |
| `41/s`          | Current average processing speed (domains per second) |
| `ETA: 30m`      | Estimated time remaining |

---

## Key Features

| Feature | Details |
|---|---|
| **Dual-transport probing** | Browser-emulating [`wreq`](https://crates.io/crates/wreq) first, plain `reqwest`+`rustls` fallback |
| **Browser verification** | Local Chromium DOM dump to confirm captcha vs. hard block |
| **Smart WAF bypass** | 32-entry randomised UA pool, realistic headers, status-gated header scoring; UA rotation + cookie-aware retry on low-confidence WAF/Captcha |
| **Signature engine** | Aho-Corasick on body/header/API patterns with specificity scoring |
| **RU/BY ISP detection** | Recognises Rostelecom, Beltelecom, BELPAK, MTS, Beeline, Megafon, TTK block pages and Роскомнадзор redirects |
| **27 service profiles** | Mapped to host roles (`web`, `auth`, `api`, `playback`…); editable via `profiles.toml` |
| **Control-proxy comparison** | Dual-vantage: local vs proxy → highest-confidence geo detection |
| **Incremental state** | Resume interrupted scans; skip already-known blocked/direct domains |
| **Cloudflare Radar** | Prefix-level geo data enrichment (optional) |
| **Multi-format export** | `geosite.dat`, sing-box rule-set, Xray rules, OpenWRT PBR + dnsmasq |
| **Multi-file input** | Drag multiple `.dat`/`.txt` files — auto-detected and merged; duplicates deduplicated |
| **Dynamic concurrency** | Press **→** / **←** to jump tiers, **↑** / **↓** for ±1 adjustment; **q** to cancel |
| **Potato Mode** | `--potato` flag for themed ASCII banners, potato progress bars, and starchier error messages |
| **Benchmarked** | Criterion benchmarks for signature matching performance |

---

## Quick Start

```sh
# Scan a list of domains
bulbascan domains.txt

# Scan with a SOCKS5 control proxy for dual-vantage comparison
bulbascan domains.txt --control-proxy socks5://127.0.0.1:1080

# Export all router configs in one pass
bulbascan domains.txt --control-proxy socks5://127.0.0.1:1080 --export-profile full
```

**Windows drag-and-drop:** Drop one or more `.txt` / `.dat` files onto `bulbascan.exe` — all files are merged and scanned together. Results appear in `results_<first-filename>/`.

---

## Input Format

Plain text, one domain per line. Comments and annotations supported:

```
# This is a comment
example.com
chat.openai.com
!blocked.com        # Expected: blocked (validation mode)
?maybe.com          # Expected: needs review
```

Also understands geosite-source formats: `full:domain`, `domain-suffix:domain`, `DOMAIN-SUFFIX,domain`.

> **Public Domain Lists:** You can find community-maintained domain categories (to use as input files) in the [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community/tree/master/data) repository.

---
## Output Files

Depending on your `--export-profile`, Bulbascan generates different sets of files in the `--results-dir`. 

For a complete breakdown of what each file contains (including Xray, sing-box, and OpenWRT exports), see the **[Outputs Documentation](docs/outputs.md)**.

---

## Service Profiles

Service-to-host mappings live in [`profiles.toml`](profiles.toml) next to the binary.  
**Edit this file to add services — no recompilation needed.**

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

If `profiles.toml` is missing, a compiled-in fallback is used automatically.

---

## CLI Reference

Run `bulbascan --help` for the full, up-to-date syntax.

For detailed usage scenarios, including proxy configurations, state management, and Cloudflare Radar fetching, read the **[Full Usage Guide](docs/usage.md)**.

---

## Building from Source

**Requirements:** Rust 1.94+

```sh
git clone https://github.com/F0RLE/Bulbascan
cd Bulbascan

cargo build            # development
cargo build --release  # optimised binary (LTO + strip)
cargo test             # 88 unit tests
cargo bench            # criterion benchmarks
cargo clippy           # lint check
```

---

## Architecture

For a deep dive into how Bulbascan works under the hood (including worker pooling, the signature engine, and `src/progress.rs` live console manipulation), see the **[Architecture Documentation](docs/architecture.md)**.


---

## Environment Variables

| Variable | Purpose |
|---|---|
| `CLOUDFLARE_RADAR_TOKEN` | Cloudflare Radar geo-prefix enrichment (optional) |
| `CI` | Suppresses "Press Enter to exit…" prompt on Windows |

---

## Contributing

Contributions welcome — detection improvements, service profiles, signature patterns, and export formats.

- Read [CONTRIBUTING.md](CONTRIBUTING.md) for dev setup, code style, and PR checklist
- Check [docs/roadmap.md](docs/roadmap.md) for high-impact areas to contribute

**Adding a service or signature requires zero code changes** — just edit `profiles.toml` or `src/signatures.rs`.

---

## Documentation

| Document | Contents |
|---|---|
| [Usage Guide](docs/usage.md) | All scan modes, CLI examples, control-proxy setup |
| [Output Files](docs/outputs.md) | Every output file and export profile explained |
| [Architecture](docs/architecture.md) | Module map, verdict model, signature engine |
| [Limits](docs/limits.md) | Current limitations and how to work around them |
| [Roadmap](docs/roadmap.md) | What's planned: from accuracy fixes to transport-layer probing |

---

---

## 💼 Commercial Licensing

Bulbascan is licensed under **GNU Affero General Public License v3.0 (AGPL-3.0)**. 

### Why AGPL?
The AGPL ensures that the community benefits from any improvements made to the scanner, even when used as a remote service (SaaS). If you use Bulbascan to power a commercial product or service, you are required to share your source code.

### Commercial Exceptions
If your organization cannot comply with the AGPL-3.0 requirements or needs to integrate Bulbascan into a proprietary, closed-source product, we offer **Commercial License Exceptions**.

**Benefits of a Commercial License:**
- Right to use Bulbascan in proprietary (closed-source) products.
- Access to a **Premium Signature Feed** with faster updates for high-value targets (AI services, streaming, etc.).
- Priority technical support and custom feature development.
- Removal of all AGPL-related legal obligations.

**Contact for Licensing:** `lrshka.klim7766@gmail.com`

---

## License

[AGPL-3.0](LICENSE) © 2026
