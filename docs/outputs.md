# Output Files and Export Profiles

> All outputs are written into `--results-dir`.
>
> If `--results-dir` is left at the default and an input file is provided, Bulbascan automatically derives `results_<input-stem>`.

---

## Export Profiles

### `simple` (default)

Minimal outputs for basic selective-proxy usage.

| File | Contents |
|---|---|
| `blocked-domains.txt` | Blocked-domain list in the format selected by `--blocked-list-format` |
| `blocked.log` | Detailed log for non-direct results |
| `geosite.dat` | Generated geosite binary |
| `ok.log` | Detailed log for direct results |

Note:

- if `simple` is used, `ok.log` is created during the scan and then removed at the end
- the primary intended outputs in `simple` mode are the blocked-domain list and `geosite.dat`

### `router`

Adds router-oriented lists, native exports, and comparison reports.

Everything in `simple`, plus:

| File | Contents |
|---|---|
| `report.txt` | Human-readable report with routing, verdict, service, and confidence summaries |
| `services_report.txt` | Service-grouped report with per-host details |
| `proxy_required.txt` | Domains classified as `ProxyRequired` |
| `direct_ok.txt` | Domains classified as `DirectOk` |
| `manual_review.txt` | Domains classified as `ManualReview` |
| `sing-box-rule-set.json` | sing-box source-format rule set |
| `sing-box-route-snippet.json` | sing-box route snippet |
| `xray-routing-rule.json` | Xray routing snippet using exact `full:` matches |
| `openwrt-pbr-domains.txt` | OpenWrt PBR domain list |
| `openwrt-dnsmasq-ipset.conf` | `dnsmasq-full` `ipset=` snippet |
| `comparison_report.txt` | Local-vs-control comparison report, when `--control-proxy` is used |
| `confirmed_proxy_required.txt` | Domains confirmed by dual-vantage comparison |
| `control_proxy_health.txt` | Control-proxy preflight report |
| `service_geo_report.txt` | Service-level geo summary from comparison results |
| `strict-*` files | Strict exports based only on confirmed dual-vantage results |
| `known-service-bundle-*` files | Minimal host bundles for known services |
| `generic-apex-bypass-*` files | Apex-level exports for unmapped proxy-required domains |

### `full`

Adds validation output on top of `router`.

| File | Contents |
|---|---|
| `validation_report.txt` | Validation report against annotated expected outcomes |

---

## Export Strategy

Bulbascan exports are intentionally conservative.

- `proxy_required.txt` is the direct routing list from the local decision model
- `confirmed_proxy_required.txt` is stricter and only exists when dual-vantage comparison runs
- `strict-*` exports are built from confirmed comparison outcomes
- `known-service-bundle-*` exports try to keep enough hosts to cover critical service roles
- `generic-apex-bypass-*` exports cover the long tail of unmapped domains

This means:

- `proxy_required.txt` is broader
- `strict-*` is safer
- `known-service-bundle-*` is smaller and service-aware

---

## Blocked List Formats

Controlled by `--blocked-list-format`.

| Format | Example | Use case |
|---|---|---|
| `plain` | `example.com` | Plain lists and generic router usage |
| `geosite-source` | `full:example.com` | Geosite source lists and merge workflows |

---

## State Directory

When `--state-dir` is used, Bulbascan also maintains persistent state files:

| File | Contents |
|---|---|
| `blocked.txt` | Persisted blocked/proxy-required set |
| `direct.txt` | Persisted direct-ok set |
| `manual_review.txt` | Persisted uncertain set |

These files are used to skip already-known domains on later runs unless `--refresh-known` is enabled.
