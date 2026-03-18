# Usage Guide

> Covers the actual CLI, control-proxy setup, state management, browser verification, and Radar fetch.

---

## Quick Start

### Windows drag-and-drop

1. Put domains into a `.txt` file, one per line.
2. Drag the file onto `bulbascan.exe`.
3. Open the generated `results_<filename>` directory.

Default drag-and-drop behavior:

- scan profile: `safe`
- export profile: `simple`
- results directory: `results_<input-file>`

### Basic command line

```sh
bulbascan domains.txt
```

This writes the default simple outputs:

- `txt/blocked.txt`
- `txt/blocked.log`
- `bin/geosite.dat`

---

## Input Format

Bulbascan accepts one or more positional input files.

- text files: plain domain lists
- `.dat` files: binary `geosite.dat`
- mixed input: text files and `.dat` files together

Plain text input supports:

```text
# comment
example.com
chat.openai.com
api.openai.com
```

Annotated validation-style lines also work:

```text
geo claude.ai
waf challenges.cloudflare.com
direct example.com
```

Accepted expected-outcome keywords:

- `geo`, `geo_blocked`, `blocked`
- `waf`, `challenge`, `captcha`
- `direct`, `ok`, `accessible`, `control`

Common list prefixes are normalized automatically:

```text
full:example.com
domain:example.com
domain-suffix:example.com
DOMAIN-SUFFIX,example.com
DOMAIN,example.com
HOST,example.com
https://example.com/path
```

---

## Common Commands

```sh
# Default scan
bulbascan domains.txt

# Dual-vantage comparison with a control proxy
bulbascan domains.txt --control-proxy socks5h://127.0.0.1:1080

# Router-oriented exports
bulbascan domains.txt --export-profile router

# Full run with validation report and state
bulbascan domains.txt --control-proxy socks5h://127.0.0.1:1080 --state-dir state --export-profile full

# Import domains from a geosite.dat category
bulbascan geosite.dat --import-geosite-category ru-blocked

# Fetch top domains from Cloudflare Radar
bulbascan --fetch-radar 500
```

---

## Global Configuration

Bulbascan can load defaults from `bulbascan.toml`.

Config precedence is:

1. CLI flags and environment-backed CLI values
2. `bulbascan.toml`
3. built-in defaults

Config loading behavior:

- auto-loads `./bulbascan.toml` if it exists
- `--config FILE` loads an explicit file
- `--no-config` disables config loading entirely

Use config for persistent defaults like:

- proxies
- control proxy
- timeouts
- export profile
- results directory
- state directory

Keep one-shot inputs on the CLI:

- positional domain files
- `--fetch-radar`
- `--import-geosite`
- `--emit-xray-socks-config`

Example:

```toml
[scan]
concurrency = 80
timeout = 8
profile = "safe"

[comparison]
control_proxy = "http://user:pass@proxy:port"
state_dir = "state"

[output]
export_profile = "full"
results_dir = "results"
```

Example run:

```sh
bulbascan domains.txt
bulbascan --config ./bulbascan.toml domains.txt
bulbascan --no-config domains.txt --timeout 5
```

---

## Recommended Run Modes

These presets are the practical starting points for selective-proxy work.

### Maximum accuracy

Use this when you want the cleanest geo-block separation and are willing to pay for deeper probing, slower runtime, and more browser activity.

```sh
bulbascan geosite.dat --import-geosite-category ru-blocked --control-proxy http://user:pass@proxy:port --state-dir state-ru --export-profile full --timeout 8 --profile aggressive
```

Use this mode when:

- you are validating a new control proxy
- you want `txt/comparison.txt` and `txt/service-geo.txt`
- you are building a high-confidence routing list

Tradeoffs:

- more requests
- more browser confirmation attempts
- slower on very large lists

Important:

- on large lists, `aggressive` can create noticeable browser churn
- use this mode for validation and high-confidence routing work, not as the default bulk-refresh mode

### Balanced

Use this as the default mode for day-to-day geo filtering. It keeps dual-vantage comparison and full reporting, but avoids the heavier aggressive browser path.

```sh
bulbascan geosite.dat --import-geosite-category ru-blocked --control-proxy http://user:pass@proxy:port --state-dir state-ru --export-profile full --timeout 8 --profile safe
```

Use this mode when:

- you want good geo accuracy without excessive browser checks
- you are iterating on the same list over time with `--state-dir`
- you want reports, not just router exports

Tradeoffs:

- less aggressive challenge confirmation than `aggressive`
- slightly more `ManualReview` leftovers than the deepest mode

### Fast

Use this when you want to refresh router outputs quickly and are willing to accept weaker diagnostics.

```sh
bulbascan geosite.dat --import-geosite-category ru-blocked --control-proxy http://user:pass@proxy:port --state-dir state-ru --export-profile router --timeout 6 --profile safe
```

`router` keeps the output bundle smaller.
Use `full` when you specifically need validation and advanced `bundle` / `apex` exports.

Use this mode when:

- you mainly care about router exports
- you want a quicker refresh pass over an already-known list
- you do not need validation-heavy reports on every run

Tradeoffs:

- fewer diagnostics than `full`
- weaker audit trail for why a domain ended up proxy-routed

Practical note:

- if your control proxy is slow or unstable, increase `--timeout` to `8-10`
- if you see too many browser windows or too much browser churn, prefer `--profile safe`

---

## CLI Reference

| Short | Long | Default | Description |
|---|---|---|---|
| pos. | `<FILES>` | `targets.txt` | One or more input files |
| `-c` | `--concurrency` | saved / `50` | Initial workers; live-adjustable during scan |
| `-t` | `--timeout` | `12` | Per-request timeout in seconds |
| `-g` | `--global-timeout` | `0` | Whole-scan timeout in seconds (`0` = infinite) |
| `-r` | `--max-redirects` | `10` | Maximum redirects to follow |
| `-b` | `--max-body-size` | `131072` | Maximum response body bytes inspected for signatures |
| `-v` | `--verbose` | off | Print more real-time debug information |
| `-q` | `--profile` | `safe` | Scan profile: `safe` / `aggressive` |
| `-e` | `--export-profile` | `simple` | Export profile: `simple` / `router` / `full` |
| `-f` | `--format` | `text` | Output format: `text` / `json` |
| `-p` | `--proxy` | — | Proxy for the main scan |
| `-P` | `--proxies` | — | File containing rotating proxies |
| `-x` | `--control-proxy` | — | Control proxy for dual-vantage comparison |
| `-L` | `--control-link` | — | VLESS link used to generate a local Xray SOCKS config |
| `-E` | `--emit-xray-socks-config` | — | Write the generated Xray config and exit |
|  | `--xray-socks-listen` | `127.0.0.1:1080` | Listen address for generated Xray SOCKS inbound |
| `-k` | `--out-ok` | `ok.log` | Accessible-domain log file name |
| `-l` | `--out-blocked` | `blocked.log` | Blocked-domain log file name |
| `-B` | `--blocked-list` | `blocked.txt` | Blocked-domain list file name |
| `-F` | `--blocked-list-format` | `plain` | `plain` / `geosite-source` |
| `-m` | `--merge-into-list` | — | Merge detected blocked domains into an existing list |
| `-d` | `--geosite` | `geosite.dat` | Output geosite filename |
| `-C` | `--geosite-category` | `blocked` | Category name inside generated geosite |
| `-D` | `--results-dir` | `results` | Results directory |
| `-I` | `--import-geosite` | — | Import domains from a geosite.dat file |
|  | `--import-geosite-category` | `blocked` | Category to extract from imported geosite |
| `-G` | `--list-geosite-categories` | — | List categories in a geosite.dat file and exit |
| `-W` | `--state-dir` | — | Persistent state directory |
| `-K` | `--refresh-known` | off | Recheck already-known `blocked` and `direct` domains |
| `-s` | `--signatures` | — | Extra custom signatures file |
| `-n` | `--browser` | auto-detect | Path to Chrome / Chromium / Edge for browser verification |
| `-S` | `--sni-fragment` | — | Maximum TLS record size for fragmented SNI experiments |
| `-R` | `--fetch-radar` | `0` | Fetch top-N domains from Cloudflare Radar |
| `-X` | `--radar-token` | env | Cloudflare Radar API token |
| `-A` | `--ascii-only` | off | ASCII-only UI |
|  | `--potato` | off | Potato UI mode |

---

## Live Controls

While a scan is running:

| Key | Action |
|---|---|
| `→` | Jump to the next worker tier |
| `←` | Jump to the previous worker tier |
| `↑` | Increase workers by 1 |
| `↓` | Decrease workers by 1 |
| `q` / `Esc` | Cancel scan |

The last live worker count is saved in the user config area (`APPDATA/Bulbascan/workers.txt` on Windows) and reused on the next run unless `--concurrency` is explicitly set.

---

## Scan Profiles

| Profile | Secondary probes | Browser probe paths | Retest attempts | Control-browser verify |
|---|---:|---:|---:|---|
| `safe` | `1` | `1` | `1` | no |
| `aggressive` | more | more | `2` | yes |

Use `aggressive` only when you want deeper confirmation and accept more requests toward targets.

---

## Control Proxy

`--control-proxy` enables dual-vantage comparison.

This is the strongest path to a high-confidence `ProxyRequired` decision:

- local path blocked, control path direct -> strong evidence the domain should be proxied
- local path timeout, control path direct -> often ISP/DPI blocking rather than a dead domain
- both blocked -> still ambiguous; may be globally dead or blocked on both paths

Important:

- the control proxy must be outside the blocked jurisdiction
- same-country or same-region control proxies reduce the value of comparison sharply

Supported proxy formats:

- `http://host:port`
- `http://user:pass@host:port`
- `socks5://host:port`
- `socks5://user:pass@host:port`
- `socks5h://host:port`

Browser verification on proxied paths is only attempted when the proxy can be represented as a browser-compatible proxy server argument. `socks5://` or `socks5h://` is the safest choice for full comparison coverage. Authenticated `http://user:pass@...` control proxies are valid for normal comparison, but they are not the best option for browser-assisted control verification.

### Xray bootstrap

```sh
# 1. Generate a local Xray SOCKS config from a VLESS link
bulbascan --control-link "vless://UUID@HOST:443?type=xhttp&security=reality&pbk=...&sni=..." \
  --emit-xray-socks-config xray-control.json

# 2. Start Xray separately
xray run -c xray-control.json

# 3. Use the local SOCKS proxy as the control path
bulbascan domains.txt --control-proxy socks5h://127.0.0.1:1080
```

---

## Browser Verification

Browser verification is a confirmation layer, not the primary detector.

Bulbascan uses it when:

- the service profile for a domain enables browser verification
- the initial HTTP/TLS result is ambiguous enough to justify it
- a usable browser binary is available
- proxy/browser constraints allow it

Automatic browser detection is attempted if `--browser` is not supplied.

Explicit example:

```sh
bulbascan domains.txt --browser "C:\Program Files\Google\Chrome\Application\chrome.exe"
```

What browser verification is for:

- confirming challenge pages
- confirming geo walls visible only after script execution
- reducing false `ManualReview` outcomes on WAF/captcha-heavy services

What it is not for:

- guaranteed captcha bypass
- solving interactive challenges by default

Operational note:

- for very large lists, browser verification is the most expensive confirmation layer
- `aggressive` now uses a capped browser budget for each scan and limits browser confirmation to at most two paths per domain
- once a challenge family has already been browser-confirmed in the same run, later domains with the same family can reuse that signal instead of spending more browser budget
- if you are doing a bulk pass and only need strong routing candidates, prefer `--profile safe`
- use `--profile aggressive` when you are explicitly trading speed for deeper confirmation

---

## Understanding Results

### Routing decisions

- `ProxyRequired` — safe candidate for router/proxy routing
- `DirectOk` — looks accessible directly
- `ManualReview` — signal is ambiguous; not safe to auto-route blindly

### Comparison decisions

- `ConfirmedProxyRequired` — local path blocked or broken, control path direct
- `CandidateProxyRequired` — local path differs from control and likely needs proxying, but evidence is weaker
- `ConsistentDirect` — both paths direct
- `ConsistentBlocked` — both paths non-direct; still ambiguous
- `NeedsReview` — comparison exists but does not cleanly separate the cause

### Why `Unreachable` is dangerous without a control proxy

Without dual-vantage comparison, `Unreachable` can mean either:

- the domain is really dead
- the local network is suppressing or breaking access

With a control proxy:

- local timeout + control direct -> often proxy-worthy
- local timeout + control timeout -> more likely globally dead or still inconclusive

---

## Incremental State

Use `--state-dir` to build a persistent local base:

```sh
bulbascan domains.txt --state-dir state
```

The state directory maintains:

- `blocked.txt`
- `direct.txt`
- `txt/review.txt`
- `rescan-hot.txt`
- `rescan-warm.txt`
- `rescan-cold.txt`

On later runs:

- known `blocked` and `direct` domains are skipped
- `manual_review` domains are revisited
- `--refresh-known` forces a recheck of already-known domains

For incremental publication:

- `txt/publish-strict.txt` is the publication-grade tier
- `publish-review-domains.txt` is the holdback tier for later refresh cycles
- `txt/publication.txt` explains what is safe to publish now and what still belongs in review

---

## Merging Into Existing Lists

```sh
bulbascan domains.txt --merge-into-list my-list.txt

bulbascan domains.txt \
  --merge-into-list my-geosite.txt \
  --blocked-list-format geosite-source
```

---

## Cloudflare Radar

```sh
bulbascan --fetch-radar 500 --results-dir results_radar_top500
```

Token sources:

- `--radar-token`
- `CLOUDFLARE_RADAR_TOKEN`

---

## Environment Variables

| Variable | Purpose |
|---|---|
| `CLOUDFLARE_RADAR_TOKEN` | Radar API token |
| `CI` | Suppresses the Windows exit prompt |
