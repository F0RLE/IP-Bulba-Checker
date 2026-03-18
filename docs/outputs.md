# Output Files

> All outputs are written into `--results-dir`.
>
> Bulbascan now groups outputs by format:
> - `txt/`
> - `json/`
> - `yaml/`
> - `bin/`

---

## Main Idea

The results directory is split by file type so the top level stays clean.

Use these first:

- `txt/publication.txt`
- `txt/publish-strict.txt`
- `txt/publish-review.txt`
- `txt/publish-direct.txt`

Use these for diagnostics:

- `txt/comparison.txt`
- `txt/service-geo.txt`
- `txt/validation.txt`
- `txt/hotspots.txt`

Router and client exports live in:

- `json/`
- `yaml/`
- `bin/`

---

## Export Profiles

### `simple` (default)

Minimal outputs for basic usage.

| Path | Contents |
|---|---|
| `txt/blocked.txt` | Blocked-domain list in the format selected by `--blocked-list-format` |
| `txt/blocked.log` | Detailed log for non-direct results |
| `bin/geosite.dat` | Generated geosite binary |
| `txt/ok.log` | Detailed log for direct results during the run |

Note:

- in `simple`, `txt/ok.log` is created during the scan and then removed at the end
- the main outputs are `txt/blocked.txt` and `bin/geosite.dat`

### `router`

Adds routing lists, reports, and router/client exports.

Everything in `simple`, plus:

| Path | Contents |
|---|---|
| `txt/report.txt` | Human-readable summary |
| `txt/services.txt` | Service-grouped summary |
| `txt/proxy.txt` | Domains classified as `ProxyRequired` |
| `txt/direct.txt` | Domains classified as `DirectOk` |
| `txt/review.txt` | Domains classified as `ManualReview` |
| `txt/comparison.txt` | Local-vs-control comparison report |
| `txt/confirmed.txt` | Domains confirmed by dual-vantage comparison |
| `txt/control-health.txt` | Control-proxy preflight report |
| `txt/service-geo.txt` | Service-level geo summary |
| `txt/publication.txt` | Publication-tier and rescan guidance |
| `txt/publish-*.txt` | Publication lists: strict, review, direct |
| `txt/rescan-*.txt` | Hot/warm/cold refresh queues |
| `json/` | sing-box and Xray JSON exports |
| `yaml/` | Mihomo provider snippets |
| `bin/` | `geosite.dat`, `.srs`, `.mrs` when local compilers are available |

### `full`

Adds validation output on top of `router`.

| Path | Contents |
|---|---|
| `txt/validation.txt` | Validation report against annotated expected outcomes |

---

## Folder Layout

### `txt/`

Human-facing reports, flat lists, logs, and text-based router files.

Common files:

- `blocked.txt`
- `proxy.txt`
- `direct.txt`
- `review.txt`
- `confirmed.txt`
- `report.txt`
- `services.txt`
- `comparison.txt`
- `control-health.txt`
- `service-geo.txt`
- `hotspots.txt`
- `validation.txt`
- `publication.txt`
- `publish-strict.txt`
- `publish-review.txt`
- `publish-direct.txt`
- `rescan-hot.txt`
- `rescan-warm.txt`
- `rescan-cold.txt`

OpenWrt / dnsmasq text exports also live here:

- `openwrt.txt`
- `dnsmasq.conf`
- `strict-openwrt.txt`
- `strict-dnsmasq.conf`
- `bundle-openwrt.txt`
- `bundle-dnsmasq.conf`
- `apex-openwrt.txt`
- `apex-dnsmasq.conf`

### `json/`

JSON exports for sing-box and Xray.

Main set:

- `sing-box.json`
- `sing-box-route.json`
- `sing-box-binary-route.json`
- `xray.json`

Other scopes:

- `strict*.json`
- `bundle*.json`
- `apex*.json`

### `yaml/`

Mihomo provider snippets.

Main set:

- `mihomo.yaml`
- `mihomo-binary.yaml`

Other scopes:

- `strict*.yaml`
- `bundle*.yaml`
- `apex*.yaml`

### `bin/`

Binary artifacts.

Main set:

- `geosite.dat`
- `sing-box.srs`
- `mihomo.mrs`

Other scopes:

- `strict.*`
- `bundle.*`
- `apex.*`

---

## Output Strategy

Use these tiers:

- `txt/publish-strict.txt`
  Best publication-grade list.
- `txt/publish-review.txt`
  Keep for later refresh cycles and human review.
- `txt/publish-direct.txt`
  Stable direct-ok set.

Use these diagnostics when something looks off:

- `txt/comparison.txt`
- `txt/service-geo.txt`
- `txt/validation.txt`
- `txt/hotspots.txt`

Treat specialized `bundle*` and `apex*` exports as advanced compatibility outputs, not as the first files to open.

---

## State Directory

When `--state-dir` is used, Bulbascan maintains persistent state files:

| File | Contents |
|---|---|
| `blocked.txt` | Persisted blocked/proxy-required set |
| `direct.txt` | Persisted direct-ok set |
| `manual_review.txt` | Persisted uncertain set |
| `rescan-hot.txt` | Short-interval refresh queue |
| `rescan-warm.txt` | Medium-interval refresh queue |
| `rescan-cold.txt` | Long-interval refresh queue |

These state files stay flat because they are machine-maintained cache/state, not user-facing result bundles.
