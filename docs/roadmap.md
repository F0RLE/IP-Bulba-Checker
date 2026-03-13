# Roadmap

> Only realistic, implementable improvements. No speculative features.

---

## v1.2 — WAF Bypass & Detection Accuracy

### Multi-probe consensus (~80 lines)
For ambiguous results (confidence 60–85), run 2–3 probes to different `probe_paths`. Require ≥2/3 agreement before finalising. Disagreement → `NeedsReview`.

### Two-phase header classification (~40 lines)
Split `SIGNATURES_HEADERS` into CDN-presence (informational, never blocks) and CDN-active-block (scored normally). Eliminates "accessible Cloudflare page → WAF" false positives.

---

## v1.3 — Signal Quality

### Redirect chain geo-detection (~60 lines)
Detect geo-redirects by checking if final URL contains region-specific segments (`/en-us/`, `/region/block`, `/geo/`). Catches soft geo-blocks on 200 OK pages.

### DOM-aware body scoring (~100 lines)
Weight body matches by location in HTML: `<title>` = strongest, `<h1>` = strong, general body text = weak. Pages with >20 `<a>` links get penalty halved (real pages have navigation, block pages don't). Needs a lightweight HTML tag parser — no full DOM.

### Domain confidence adjustment (~20 lines)
Known service with `browser_verification = true` → +5 to captcha/geo confidence. Unknown domain without profile → -10 to WAF confidence.

---

## v1.4 — Transport Layer

### DNS-level block detection (~150 lines)
Before HTTP, compare ISP DNS response with public resolver (8.8.8.8). Detect NXDOMAIN injection, blockpage IP substitution, and DNS poisoning. Highest-confidence censorship signal. Requires async DNS resolver (`hickory-dns` or raw UDP).

### SNI-based block detection (~120 lines)
Send TLS ClientHello with target SNI. If reset at handshake but plain TCP works → SNI block. If same IP with different SNI succeeds → confirmed. Uses `tokio-rustls` directly.

### ECH probing (~100 lines)
When domain publishes ECH keys in DNS HTTPS record (type 65), attempt TLS with ECH. If ECH succeeds where plain-SNI was blocked → confirmed SNI censorship. `rustls` 0.23+ supports ECH.

### IPv6 dual-stack probing (~60 lines)
Optional: probe both IPv4 and IPv6. Report when IPv4 is blocked but IPv6 works. `reqwest` supports IPv6 natively.

---

## v1.5 — Output Formats

### `geoip.dat` generation (~150 lines)
DNS-resolve blocked domains → collect A/AAAA records → aggregate into CIDR subnets → compile into V2Ray `GeoIP` protobuf. Same `prost` setup as `geosite.dat`.

### Clash / Mihomo rule-set export (~50 lines)
```yaml
payload:
  - DOMAIN,blocked.com
  - DOMAIN-SUFFIX,blocked.com
```

### Shadowrocket config export (~40 lines)
```ini
[Rule]
DOMAIN,blocked.com,PROXY
DOMAIN-SUFFIX,blocked.com,PROXY
```

### Import helpers (~80 lines)
Parse existing block lists: Clash `.yaml`, Shadowrocket, NekoBox/Mihomo, V2Ray `geosite.dat` → domain list.

### Windows starter pack
Release archive: exe + profiles.toml + example domains + 3-line README.txt.
