<p align="center">
  <h1 align="center">🥔 Bulbascan</h1>
  <p align="center">
    <b>High-speed selective-proxy scanner for geo-block detection and geosite routing list generation.</b>
  </p>
  <p align="center">
    <a href="https://www.rust-lang.org"><img src="https://img.shields.io/badge/rust-1.94%2B-orange?logo=rust&logoColor=white" alt="Rust"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License: MIT"></a>
    <a href="https://github.com/F0RLE/Bulbascan/actions"><img src="https://img.shields.io/github/actions/workflow/status/F0RLE/Bulbascan/ci.yml?label=CI&logo=github" alt="CI"></a>
    <a href="https://github.com/F0RLE/Bulbascan/releases"><img src="https://img.shields.io/github/v/release/F0RLE/Bulbascan?include_prereleases&label=release" alt="Release"></a>
  </p>
</p>

---

## Project Status

Bulbascan is temporarily on hold.

The project reached a point where the remaining work is mostly about hard-to-validate blocking accuracy, dual-vantage proxy behavior, and large-scale routing decisions. For a solo developer, the implementation and maintenance cost of getting this close to "almost no mistakes" is currently too high.

The repository is being left online as a working prototype, research codebase, and reference implementation. It may return later, but active development should be considered paused for now.

Bulbascan scans domain lists and classifies which targets are likely safe to keep direct, which likely require proxying, and which still need review. It then exports routing configs for Xray, sing-box, OpenWRT, and V2Ray `geosite.dat`.

It is not a perfect source of truth. Treat it as a verification and triage tool. The useful distinction is between `confirmed`, `review`, and `direct` outputs.

## How It Works

Bulbascan uses a layered detection approach:
1. **HTTP probing:** Uses `reqwest` over `rustls`, with a fallback request path for harder transport cases.
2. **DNS evidence:** Compares system DNS with DoH answers to detect stronger local DNS manipulation and suspicious poisoned-answer mismatches.
3. **Dual-vantage comparison:** Compares the local path with a control proxy to separate local blocking from globally dead or ambiguous domains.
4. **Browser confirmation:** Uses a local browser as a secondary confirmation layer for challenge-heavy and script-dependent services.
5. **Signature engine:** Analyzes headers, bodies, redirects, and API responses with an Aho-Corasick matcher.

| Verdict | Meaning |
|---|---|
| ✅ **Accessible** | Reachable directly |
| 🌍 **GeoBlocked** | Geo-restriction confirmed |
| 🔀 **ProxyRequired** | Local candidate for selective proxy routing; weaker than confirmed dual-vantage output |
| 🛡️ **WAF** | CDN/WAF actively blocking |
| 🔍 **NeedsReview** | Ambiguous — flagged for manual review |
| 💀 **Dead** | Unreachable on all transports |

## Quick Start

```sh
bulbascan domains.txt
bulbascan domains.txt --control-proxy socks5://127.0.0.1:1080
bulbascan domains.txt --control-proxy socks5://127.0.0.1:1080 --export-profile full
```

**Windows:** Drop `.txt` / `.dat` files onto `bulbascan.exe`. Results appear in `results_<filename>/`.

## Advanced Usage

**Export for routers (Xray/sing-box/OpenWRT) with state management:**
```sh
bulbascan domains.txt -x http://user:pass@proxy:port --export-profile router --state-dir ./state
```

**Import domains directly from an existing geosite file:**
```sh
bulbascan geosite.dat --import-geosite-category ru-blocked
```

**Re-scan an existing public feed and build your own confirmed routing set:**
```sh
bulbascan geosite.dat \
  --import-geosite-category ru-blocked \
  --control-proxy socks5://127.0.0.1:1080 \
  --state-dir ./state \
  --export-profile full
```

**Load defaults from `bulbascan.toml`:**
```sh
bulbascan --config ./bulbascan.toml domains.txt
```

## Use Cases
- **Smart Routing (Selective Proxy):** Generate routing inputs that proxy likely blocked services while keeping likely direct traffic local.
- **Home Routers:** Export directly to OpenWRT / dnsmasq formats for network-wide bypass.
- **Censorship Analysis:** Discover exactly which layer (DNS, SNI, HTTP) your ISP or a specific service is blocking.

## Why Use Bulbascan If Public Geosite Lists Already Exist?

Public feeds such as country-specific `geosite.dat` lists are useful seed inputs, but they answer a different question: "what does this external project currently publish?" Bulbascan is for checking what should be proxied from the current network path.

Use Bulbascan when you want to:
- re-scan a public geosite/domain feed from your own country or ISP
- separate `ConfirmedProxyRequired` from weaker `CandidateProxyRequired` and `ManualReview`
- compare the local path against a control proxy instead of trusting a third-party list blindly
- keep your own `direct`, `blocked`, and `review` state over time
- generate router outputs from your own confirmed results, not from a raw imported feed

Typical workflow:
1. take a public domain feed as seed input
2. run Bulbascan locally, ideally with `--control-proxy`
3. review `publish-strict`, `publish-review`, and `direct` outputs
4. export your own routing lists and `geosite.dat`

Bulbascan currently imports these domain-oriented inputs directly:
- plain text domain lists
- annotated text lists such as `geo example.com`, `direct example.com`, `waf example.com`
- geosite-source style text such as `full:example.com`, `domain:example.com`, `domain-suffix:example.com`, `DOMAIN-SUFFIX,example.com`, `DOMAIN,example.com`, `HOST,example.com`
- URL-like lines where only the host should be re-scanned, such as `https://user:pass@example.com:8443/path`
- Clash/Mihomo-style payload lists such as `- '+.example.com'`
- dnsmasq/OpenWrt-style domain rules such as `ipset=/example.com/set`, `server=/example.com/1.1.1.1`, `address=/example.com/...`
- JSON rule-sets and route snippets when domains are stored in fields such as `domain`, `domains`, `domain_suffix`, `domain_full`, `domain_keyword`, `payload`, `rules`, `route`, or `routing`
- binary `geosite.dat` categories via `--import-geosite-category`

Bulbascan does **not** currently import IP-oriented or compiled rule inputs such as `geoip.dat`, `.mmdb`, CIDR/IP lists, `.srs`, or `.mrs`. It is a domain scanner first: those formats belong to IP routing or compiled router rule pipelines, not to direct domain verification.

## What Bulbascan Is And Is Not

Bulbascan is best used as:
- a local verification tool for country- or ISP-specific blocking
- a rescan pipeline for public feeds and third-party domain lists
- a way to separate stronger `confirmed` results from weaker `review` and `candidate` observations
- a helper for building your own selective-proxy routing lists from your own network path

Bulbascan should not be treated as:
- a perfect, always-correct censorship oracle
- a replacement for human review on ambiguous domains
- a reason to publish every non-direct result straight into production proxy rules

The most trustworthy outputs are usually:
- `txt/publish-strict.txt`
- `txt/publish-direct.txt`
- `txt/comparison.txt`
- `txt/service-geo.txt`

The least trustworthy outputs are local-only weak signals that have not been confirmed with dual-vantage comparison. In practice, `review` exists because real websites mix geo blocks, WAF challenges, transient failures, resolver issues, and anti-bot behavior in ways that no scanner can separate perfectly every time.

## Supported Platforms
- **Windows** (x86_64, ARM64)
- **macOS** (Apple Silicon, Intel)
- **Linux** (Debian/Ubuntu, Arch, Alpine, etc.)

**Prerequisites:** 
- For standard scanning: None (standalone binary).
- For **Browser Verification** (WAF/Captcha bypass): A Chromium-based browser (Chrome, Edge, or Chromium) must be installed on the system.

## Key Features

| Feature | Details |
|---|---|
| Dual-transport probing | `reqwest`/`rustls` primary path with fallback transport handling |
| DNS-level block detection | System DNS vs DoH comparison, resolver failure classification, and mismatch confirmation via direct TCP/TLS probes |
| Browser verification | Local browser confirmation for challenge-heavy and script-dependent targets, with optional browser-all mode and configurable parallel tabs |
| Signature engine | Aho-Corasick on body/header/API patterns with specificity scoring |
| RU/BY ISP detection | Rostelecom, Beltelecom, MTS, Beeline, Megafon, TTK block pages |
| 38 service profiles | Editable via `profiles.toml` — no recompilation |
| Control-proxy comparison | Dual-vantage comparison between local and control paths |
| Incremental state | Resume interrupted scans |
| Multi-format export | `geosite.dat`, sing-box, Xray, OpenWRT PBR + dnsmasq |
| Global configuration | Optional `bulbascan.toml` with `CLI > config > built-in defaults` precedence |
| Dynamic concurrency | `→`/`←` tier jump, `↑`/`↓` ±1 workers, `q` cancel |
| Stable throughput metrics | 3-second moving average speed smoothing for less jumpy `/s` and ETA |

## Custom Service Profiles
You can easily add custom API checks or service behaviors without recompiling by editing `profiles.toml`:

```toml
[[services]]
name = "MyService"
browser_verification = true
expected_roles = ["web", "api"]
critical_roles = ["web", "api"]

[[services.hosts]]
domain = "myservice.com"
role = "web"
probe_paths = ["/", "/login"]

[[services.hosts]]
domain = "api.myservice.com"
role = "api"
probe_paths = ["/"]
```

## Building

```sh
git clone https://github.com/F0RLE/Bulbascan
cd Bulbascan
cargo build --release
cargo test
```

**Requirements:** Rust 1.94+

## Development Notes

- If you just want to use Bulbascan, prefer GitHub Releases or CI artifacts instead of building from source.
- If you want to contribute, use [docs/project/CONTRIBUTING.md](docs/project/CONTRIBUTING.md) for workflow, development setup, and branch rules.
- Project roles and ownership are described in [docs/project/GOVERNANCE.md](docs/project/GOVERNANCE.md).
- Optional dev-container files live in [`docker/`](docker).

## Documentation

| Document | Contents |
|---|---|
| [Usage Guide](docs/usage.md) | All scan modes, CLI examples, proxy setup |
| [Output Files](docs/outputs.md) | Every output file and export profile |
| [Architecture](docs/architecture.md) | Module map, verdict model, signature engine |
| [Limits](docs/limits.md) | Known limitations |
| [Governance](docs/project/GOVERNANCE.md) | Project status and maintenance pause |

## License

Bulbascan is available under the [MIT License](LICENSE).
- Project roles and owner-led governance: [docs/project/GOVERNANCE.md](docs/project/GOVERNANCE.md)
