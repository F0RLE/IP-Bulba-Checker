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

Bulbascan scans a list of domains and determines whether each one is geo-blocked, WAF-protected, or freely accessible — then exports ready-to-use routing configs for Xray, sing-box, OpenWRT, and V2Ray `geosite.dat`.

| Verdict | Meaning |
|---|---|
| ✅ **Accessible** | Reachable directly |
| 🌍 **GeoBlocked** | Geo-restriction confirmed |
| 🔀 **ProxyRequired** | Dual-vantage confirmed — must proxy |
| 🛡️ **WAF** | CDN/WAF actively blocking |
| 🔍 **NeedsReview** | Ambiguous — flagged for manual check |
| 💀 **Dead** | Unreachable on all transports |

## Quick Start

```sh
bulbascan domains.txt
bulbascan domains.txt --control-proxy socks5://127.0.0.1:1080
bulbascan domains.txt --control-proxy socks5://127.0.0.1:1080 --export-profile full
```

**Windows:** Drop `.txt` / `.dat` files onto `bulbascan.exe`. Results appear in `results_<filename>/`.

## Key Features

| Feature | Details |
|---|---|
| Dual-transport probing | `wreq` (browser-emulating) first, `reqwest`+`rustls` fallback |
| Browser verification | Local Chromium DOM dump to confirm captcha vs. hard block |
| Signature engine | Aho-Corasick on body/header/API patterns with specificity scoring |
| RU/BY ISP detection | Rostelecom, Beltelecom, MTS, Beeline, Megafon, TTK block pages |
| 27 service profiles | Editable via `profiles.toml` — no recompilation |
| Control-proxy comparison | Dual-vantage: local vs proxy → highest-confidence geo detection |
| Incremental state | Resume interrupted scans |
| Multi-format export | `geosite.dat`, sing-box, Xray, OpenWRT PBR + dnsmasq |
| Dynamic concurrency | `→`/`←` tier jump, `↑`/`↓` ±1 workers, `q` cancel |

## Building

```sh
git clone https://github.com/F0RLE/Bulbascan
cd Bulbascan
cargo build --release
cargo test
```

**Requirements:** Rust 1.94+

## Documentation

| Document | Contents |
|---|---|
| [Usage Guide](docs/usage.md) | All scan modes, CLI examples, proxy setup |
| [Output Files](docs/outputs.md) | Every output file and export profile |
| [Architecture](docs/architecture.md) | Module map, verdict model, signature engine |
| [Roadmap](docs/roadmap.md) | Planned improvements |
| [Limits](docs/limits.md) | Known limitations |

## Development

Built with AI-assisted tooling (Antigravity, Claude, and similar agentic coding tools). Architectural decisions, detection logic, signatures, and export formats are designed and directed by the author. AI accelerates implementation; engineering judgment is human.

## License

[AGPL-3.0](LICENSE) © 2026 — Commercial licensing available: `lrshka.klim7766@gmail.com`
