# Output Files and Export Profiles

> All output files are written to `--results-dir` (defaults to `results_<input-filename>` next to the input file).

---

## Export Profiles

### 1. `simple` (default)
Essential outputs for basic blocklist creation and drag-and-drop usage.

| File | Contents |
|---|---|
| `blocked-domains.txt` | Plain list of proxy-required domains (format controlled by `--blocked-list-format`) |
| `geosite.dat` | V2Ray/Xray geosite binary |
| `blocked.log` | Detailed audit log of all blocked/geo-blocked domains |
| `ok.log` | Log of all accessible (direct) domains |

### 2. `router`
Adds firmware-native routing rules and advanced comparison reports.

Everything in **Simple**, plus:

| File | Contents |
|---|---|
| `report.txt` | Human-readable scan summary with distribution stats |
| `services_report.txt` | Service-level grouping and verdict confidence |
| `proxy_required.txt` | All proxy-required domains as a newline-delimited list |
| `direct_ok.txt` | All confirmed direct domains as a newline-delimited list |
| `manual_review.txt` | Ambiguous domains flagged for manual check |
| `sing-box-rule-set.json` | sing-box domain rule-set (Version 4) |
| `sing-box-route-snippet.json` | sing-box route rule snippet connecting the rule-set |
| `xray-routing-rule.json` | Xray routing rule (`full:domain` format) |
| `openwrt-pbr-domains.txt` | Domain policies for OpenWrt PBR |
| `openwrt-dnsmasq-ipset.conf` | `ipset=` configuration snippet for `dnsmasq-full` |
| `strict-*` | **Dual-vantage confirmed** variants of all the above (requires `--control-proxy`) |
| `known-service-bundle-*` | Minimal per-service host sets covering all critical roles |
| `generic-apex-bypass-*` | Apex-level fallback rules for non-profiled domains |
| `comparison_report.txt` | Local vs Control-vantage comparison analysis |
| `confirmed_proxy_required.txt` | Domains confirmed proxy-required by dual-vantage |
| `control_proxy_health.txt` | Health preflight result for the control proxy |
| `service_geo_report.txt` | High-confidence service-level geo conclusions |

### 3. `full`
Includes detailed diagnostic reports for accuracy validation.

Everything in **Router**, plus:

| File | Contents |
|---|---|
| `validation_report.txt` | Accuracy report comparing results against expected annotations |

---

## Export strategy

Router exports are intentionally conservative:

- **`sing-box`** uses exact `domain` matches — no wildcards
- **`Xray`** uses exact `full:` matches
- **`OpenWRT`** gets both a PBR domain list and `dnsmasq-full` `ipset=` snippets
- **`strict-*`** variants include only dual-vantage **confirmed** domains (strongest signal)
- **`known-service-bundle-*`** — smallest host set per service that still covers all critical roles
- **`generic-apex-bypass-*`** — apex-level fallback for the non-profiled long tail

---

## Blocked list formats

Controlled by `--blocked-list-format`:

| Format | Output example | Use case |
|---|---|---|
| `plain` | `example.com` | Simple blocklists, most routers |
| `geosite-source` | `full:example.com` | Merging into V2Ray geosite source files |

---

## Local state directory

When `--state-dir` is set, the scanner also maintains:

| File | Contents |
|---|---|
| `blocked.txt` | Confirmed proxy-required (persistent) |
| `direct.txt` | Confirmed direct-ok (persistent) |
| `manual_review.txt` | Uncertain — rescanned on the next run |

Domains already in `blocked.txt` or `direct.txt` are skipped on subsequent runs unless `--refresh-known` is passed.
