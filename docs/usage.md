# Usage Guide

> Covers all scan modes, control-proxy setup, state management, and Radar fetch.

---

## Quickest start (Windows)

1. Put your domains in a `.txt` file (one per line)
2. Drag the file onto `bulbascan.exe`
3. Open the `results_<filename>` folder that appears next to it

That default run uses the `safe` scan profile and `simple` export profile and writes:

- `blocked-domains.txt` — plain list of proxy-required domains
- `blocked.log` — per-domain evidence log
- `geosite.dat` — ready-to-use V2Ray/Xray routing file

## Input format

Plain text, one domain per line. Comments and annotations are supported:

```
# This line is a comment
example.com
!blocked.com        # Expected to be blocked (used in validation mode)
?maybe.com          # Expected to need review
chat.openai.com
api.openai.com
```

Geosite-source lines are also understood:

```
full:example.com
domain-suffix:example.com
DOMAIN-SUFFIX,example.com
DOMAIN,example.com
HOST,example.com
```

---

## Common commands

```sh
# Default scan (safe profile, simple exports)
bulbascan -i domains.txt

# With a HTTP control proxy for dual-vantage comparison
bulbascan -i domains.txt -x http://user:pass@host:port

# Import domains from geosite.dat, specific category
bulbascan --import-geosite geosite.dat --import-geosite-category ru-blocked

# Router-oriented exports (sing-box, Xray, OpenWRT)
bulbascan -i domains.txt --export-profile router

# Full run: router exports + state management
bulbascan -i domains.txt -x http://... --state-dir state-ru --export-profile router

# Aggressive scan profile
bulbascan -i domains.txt --scan-profile aggressive -x socks5://127.0.0.1:1080
```

---

## CLI Reference

| Short | Long | Default | Description |
|-------|------|---------|-------------|
| (pos.) | `<FILES>` | `targets.txt` | One or more input files |
| `-c` | `--concurrency` | `50` | Initial workers (adjustable live 1–1000 with arrow keys) |
| `-t` | `--timeout` | `12` | Per-request timeout (seconds) |
| `-g` | `--global-timeout` | `0` (∞) | Global scan timeout |
| `-r` | `--max-redirects` | `10` | Max redirects to follow |
| `-b` | `--max-body-size` | `131072` | Max response body size (bytes) |
| `-v` | `--verbose` | off | Print detailed real-time info |
| `-q` | `--profile` | `safe` | Scan profile: `safe` / `aggressive` |
| `-e` | `--export-profile` | `simple` | Export: `simple` / `router` / `full` |
| `-f` | `--format` | `text` | Output format: `text` / `json` |
| **Proxies** | | | |
| `-p` | `--proxy` | — | Proxy for main scan |
| `-P` | `--proxies` | — | Proxy list file for rotation |
| `-x` | `--control-proxy` | — | Control proxy (dual-vantage comparison) |
| `-L` | `--control-link` | — | VLESS link for Xray bootstrap |
| `-E` | `--emit-xray-socks-config` | — | Write Xray SOCKS config and exit |
| | `--xray-socks-listen` | `127.0.0.1:1080` | Local listen address for Xray inbound |
| **Output** | | | |
| `-k` | `--out-ok` | `ok.log` | Accessible domains log |
| `-l` | `--out-blocked` | `blocked.log` | Blocked domains log |
| `-B` | `--blocked-list` | `blocked-domains.txt` | Blocked domains filename |
| `-F` | `--blocked-list-format` | `plain` | Format: `plain` / `geosite-source` |
| `-m` | `--merge-into-list` | — | Merge results into existing list |
| `-d` | `--geosite` | `geosite.dat` | Geosite output filename |
| `-C` | `--geosite-category` | `blocked` | Category inside geosite.dat |
| `-D` | `--results-dir` | `results` | Results output directory |
| **Geosite input** | | | |
| `-I` | `--import-geosite` | — | Import domains from a geosite.dat file |
| | `--import-geosite-category` | `blocked` | Category to extract (requires `-I`) |
| `-G` | `--list-geosite-categories` | — | List all categories in a .dat file and exit |
| **State** | | | |
| `-W` | `--state-dir` | — | Incremental state directory |
| `-K` | `--refresh-known` | off | Rescan already-known domains |
| **Advanced** | | | |
| `-s` | `--signatures` | — | Custom signature patterns file |
| `-n` | `--browser` | — | Path to Chromium/Chrome binary |
| `-S` | `--sni-fragment` | — | SNI fragmentation (max TLS record size) |
| `-R` | `--fetch-radar` | `0` | Fetch top-N from Cloudflare Radar |
| `-X` | `--radar-token` | env | Cloudflare Radar API token |
| **UI** | | | |
| `-A` | `--ascii-only` | off | ASCII-only output (no emoji, plain spinner) |
| | `--potato` | off | Potato mode 🥔 |

---

## Live controls (during scan)

While the scan is running you can adjust concurrency without restarting:

| Key | Action |
|-----|--------|
| `→` | Jump to **next** worker tier (e.g. Safe → Standard → Balanced…) |
| `←` | Jump to **previous** worker tier |
| `↑` | Increase workers by 1 (fine-tune) |
| `↓` | Decrease workers by 1 (fine-tune) |
| `q` / `Esc` | Cancel scan |

The profile header above the bar updates live to reflect the current tier and worker count.

> **Persistence:** The last worker count set during a scan is automatically saved to `.bulbascan_workers` and will be reused on the next start unless overridden by the `--concurrency` flag.

---

## Worker tiers

Workers can be set from 1 to **1000** (hard cap). The profile name and tier shown in the header are derived from the live worker count:

| Tier | Workers |
|------|---------|
| Safe | 1 – 50 |
| Standard | 51 – 100 |
| Balanced | 101 – 200 |
| Active | 201 – 300 |
| Fast | 301 – 400 |
| Turbo | 401 – 500 |
| Heavy | 501 – 600 |
| Intense | 601 – 700 |
| Brute | 701 – 800 |
| Rush | 801 – 900 |
| Aggressive | 901 – 1000 |

> **Tip:** On a typical home internet connection, 50–150 workers gives the best throughput. Higher counts hit network/server rate limits and yield diminishing returns. Reduce `--timeout` (e.g. `-t 5`) to speed up dead-domain detection.

---

## Scan profiles

| Profile | Default workers | Secondary probes | Browser probes | Control browser |
|---|---|---|---|---|
| `safe` | 50 | 1 | 1 | no |
| `aggressive` | 200 | 4 | 4 | yes |

Use `aggressive` only when you need the deepest possible confirmation and accept a noisier request pattern toward target servers.

---

## Control-proxy comparison

Running with `--control-proxy` (short: `-x`) enables dual-vantage mode — each domain is scanned both locally and through the proxy, and verdicts are compared. This is the strongest path to geo-confirmation.

Supported proxy formats:
- `http://user:pass@host:port`
- `socks5://user:pass@host:port`
- `socks5h://host:port` (DNS through proxy)

**Recommended setup with Xray:**

```sh
# 1. Generate a local Xray SOCKS config from a vless:// link
bulbascan --control-link "vless://UUID@HOST:443?type=xhttp&security=reality&pbk=...&sni=..." \
                 --emit-xray-socks-config xray-control.json

# 2. Start local Xray
xray run -c xray-control.json

# 3. Scan with the control proxy
bulbascan -i domains.txt -x socks5h://127.0.0.1:1080
```

---

## Incremental state

Use `--state-dir` (short: `-W`) to build a persistent local block list over time:

```sh
bulbascan --import-geosite geosite.dat --import-geosite-category ru-blocked \
          --state-dir state-ru --export-profile router
```

The state directory keeps three files:

- `blocked.txt` — confirmed proxy-required
- `direct.txt` — confirmed direct-ok
- `manual_review.txt` — uncertain, revisited on the next run

On later runs, `blocked` and `direct` domains are skipped. Only new and `manual_review` domains are rescanned. Add `--refresh-known` to force a full rescan.

---

## Merging into an existing list

```sh
# Merge scan results into an existing blocked list
bulbascan -i russia-blocked.txt --merge-into-list my-list.txt

# Merge in geosite-source format
bulbascan -i russia-blocked.txt --merge-into-list my-geosite.txt --blocked-list-format geosite-source
```

---

## Cloudflare Radar fetch

```sh
# Fetch top-N domains from Cloudflare Radar and scan them
bulbascan --fetch-radar 500 --results-dir results_radar_top500
```

Requires `CLOUDFLARE_RADAR_TOKEN` environment variable or `--radar-token`.

---

## Browser verification

Pass `--browser` with the path to a Chromium or Chrome binary to enable browser-backed verification:

```sh
bulbascan -i domains.txt --browser "C:\Program Files\Google\Chrome\Application\chrome.exe"
```

Browser verification is triggered automatically for services with `browser_verification = true` in `profiles.toml` when the HTTP scan result is ambiguous (captcha or low-confidence geo).

---

## Environment variables

| Variable | Purpose |
|---|---|
| `CLOUDFLARE_RADAR_TOKEN` | Enables Cloudflare Radar geo-prefix fetch |
| `CI` | Suppresses the "Press Enter to exit…" prompt on Windows |
