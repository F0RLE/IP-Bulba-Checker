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

Bulbascan scans domain lists and classifies which targets are likely safe to keep direct, which likely require proxying, and which still need review. It then exports routing configs for Xray, sing-box, OpenWRT, and V2Ray `geosite.dat`.

## How It Works

Bulbascan uses a layered detection approach:
1. **HTTP probing:** Uses `rquest` as the primary client with a fallback request path for harder transport cases.
2. **DNS evidence:** Compares system DNS with DoH answers to detect stronger local DNS manipulation and suspicious poisoned-answer mismatches.
3. **Dual-vantage comparison:** Compares the local path with a control proxy to separate local blocking from globally dead or ambiguous domains.
4. **Browser confirmation:** Uses a local browser as a secondary confirmation layer for challenge-heavy and script-dependent services.
5. **Signature engine:** Analyzes headers, bodies, redirects, and API responses with an Aho-Corasick matcher.

| Verdict | Meaning |
|---|---|
| ✅ **Accessible** | Reachable directly |
| 🌍 **GeoBlocked** | Geo-restriction confirmed |
| 🔀 **ProxyRequired** | Strong candidate for selective proxy routing |
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

## Use Cases
- **Smart Routing (Selective Proxy):** Generate routing inputs that proxy likely blocked services while keeping likely direct traffic local.
- **Home Routers:** Export directly to OpenWRT / dnsmasq formats for network-wide bypass.
- **Censorship Analysis:** Discover exactly which layer (DNS, SNI, HTTP) your ISP or a specific service is blocking.

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
| Dual-transport probing | `rquest` primary path with fallback transport handling |
| DNS-level block detection | System DNS vs DoH comparison, resolver failure classification, and mismatch confirmation via direct TCP/TLS probes |
| Browser verification | Local browser confirmation for challenge-heavy and script-dependent targets |
| Signature engine | Aho-Corasick on body/header/API patterns with specificity scoring |
| RU/BY ISP detection | Rostelecom, Beltelecom, MTS, Beeline, Megafon, TTK block pages |
| 27 service profiles | Editable via `profiles.toml` — no recompilation |
| Control-proxy comparison | Dual-vantage: local vs proxy → highest-confidence geo detection |
| Incremental state | Resume interrupted scans |
| Multi-format export | `geosite.dat`, sing-box, Xray, OpenWRT PBR + dnsmasq |
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

## Usage vs Development

### If you just want to use Bulbascan

Use GitHub Releases or CI artifacts instead of building from source. That is the intended path for normal scanning and avoids installing Rust and build dependencies locally.

### If you want to develop Bulbascan

Recommended daily workflow:

- edit code on the host system
- run `cargo check`, `cargo test`, and `cargo clippy` either natively or through the optional dev container
- run real browser-verification and real network-path checks on the host system

You can choose either:

- install Rust and build dependencies locally
- use the provided dev container in [`dev/Dockerfile.dev`](dev/Dockerfile.dev)

For Windows contributors, native development is the recommended default. Bulbascan's browser-confirmation and selective-proxy behavior are easier to validate on the host network stack than inside a container.

Example Docker-based development flow:

```sh
docker build -f dev/Dockerfile.dev -t bulbascan-dev .
docker run --rm -it -v "$PWD:/workspace" -w /workspace bulbascan-dev cargo check
docker run --rm -it -v "$PWD:/workspace" -w /workspace bulbascan-dev cargo test
```

Or with Docker Compose:

```sh
docker compose -f dev/docker-compose.dev.yml build
docker compose -f dev/docker-compose.dev.yml run --rm bulbascan-dev cargo check
```

Note:

- the dev container is optional and mainly useful for build/test workflows
- real browser verification and real network-path debugging are still better tested on the host system

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
