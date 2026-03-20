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

These outputs are not all equally trustworthy. Bulbascan is a verification and triage tool, not a perfect censorship oracle. For operational routing decisions, prefer `publish-strict`, `publish-direct`, and the dual-vantage diagnostics over raw local-only blocked outputs.

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
- the main quick-start outputs are `txt/blocked.txt` and `bin/geosite.dat`
- for higher-confidence routing work, prefer `router` or `full` and use `txt/publish-strict.txt` plus `txt/comparison.txt`

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

`router` keeps the output surface focused on the main operator and deployment files.

### `full`

Adds validation output on top of `router`.

| Path | Contents |
|---|---|
| `txt/validation.txt` | Validation report against annotated expected outcomes |
| `bundle*` outputs | Confirmed known-service minimal bundles |
| `apex*` outputs | Confirmed generic apex bypass exports for unmapped domains |

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
  Strictest publication list.
- `txt/publish-review.txt`
  Keep for later refresh cycles and human review.
- `txt/publish-direct.txt`
  Stable direct-ok set.

Interpretation:

- `publish-strict` is the safest publication tier because it is driven by stronger dual-vantage confirmation.
- `publish-review` is intentionally mixed and should not be treated as a production-ready proxy list.
- local-only `blocked.txt` and `proxy.txt` are useful diagnostics, but they are weaker than confirmed comparison outputs.

Use these diagnostics when something looks off:

- `txt/comparison.txt`
- `txt/service-geo.txt`
- `txt/validation.txt`
- `txt/hotspots.txt`

Treat specialized `bundle*` and `apex*` exports as advanced compatibility outputs. They are generated only in `full`.

- `bundle*` is reserved for service summaries that reach `ConfirmedGeoBlocked`.
- `apex*` is reserved for unmapped domains that reach `ConfirmedProxyRequired`.
- weaker `likely`, `candidate`, and `review` outcomes belong in `publish-review`, not in these compatibility exports.

---

## State Directory

Bulbascan keeps persistent state in `results_dir/state` by default.
If `--results-dir` is not set, the default `results_dir` is created under the per-user Bulbascan runtime directory rather than in the repository root.

If `--state-dir` is provided, that explicit location is used instead.

The state directory maintains:

| File | Contents |
|---|---|
| `blocked.txt` | Persisted strictly confirmed blocked/proxy-required set |
| `direct.txt` | Persisted direct-ok set |
| `manual_review.txt` | Persisted uncertain set |
| `rescan-hot.txt` | Short-interval refresh queue |
| `rescan-warm.txt` | Medium-interval refresh queue |
| `rescan-cold.txt` | Long-interval refresh queue |

These state files stay flat because they are machine-maintained cache/state, not user-facing result bundles.

User-facing review outputs are separate and live under `results_dir/txt/`:

| File | Contents |
|---|---|
| `txt/proxy.txt` | Current run's local proxy-required domains |
| `txt/direct.txt` | Current run's local direct-ok domains |
| `txt/review.txt` | Current run's local review set |
