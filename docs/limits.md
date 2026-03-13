# Limits and Safety Defaults

> What the scanner does well, where it can still be wrong, and how to get the most out of it.

---

## Where the scanner is strong

- **Known services with a control proxy** — dual-vantage comparison gives the strongest geo signal.
  When local scan returns `GeoBlocked` and the control proxy returns `Accessible`, confidence is high.
- **Curated service profiles** — services in `profiles.toml` get role-aware aggregation.
  "Auth is blocked even though web looks ok" is surfaced correctly.
- **WAF detection** — the Aho-Corasick signature engine handles 60+ CDN/WAF patterns.
  Specificity scoring filters out noisy short patterns.

---

## Current limitations

| Area | Detail |
|---|---|
| **WAF vs GeoBlock** | CDN presence headers (Cloudflare, Akamai, Fastly) can score as WAF even on accessible pages. Header scoring needs a two-phase check (see roadmap). |
| **Captcha → GeoBlocked** | A 403 + Turnstile challenge sometimes scores as `GeoBlocked` before browser verification. Browser verify usually corrects this. |
| **Inconclusive services** | Gemini, Meta, TikTok, Strava are often `Inconclusive` in partial-block regions. Critical-role coverage is incomplete without all expected hosts returning clear verdicts. |
| **Large mass scans** | Best treated as triage. Not every domain in a 50,000-item list will be classified perfectly. Use the control-proxy path + manual review for important domains. |
| **No IPv6** | The scanner probes IPv4 only. Services accessible via IPv6 but not IPv4 will appear blocked. |
| **No HTTP/3** | QUIC/HTTP3 is not probed. Some CDNs serve HTTP/3 when HTTP/2 is rate-limited or blocked. |
| **Authenticated HTTP proxies** | Browser verification is not available on the control path when using HTTP proxies with credentials. Use SOCKS5 for full comparison coverage. |

---

## Safety defaults (`safe` profile)

| Setting | Value | Rationale |
|---|---|---|
| Concurrency | 50 | Avoids hammering targets or triggering rate limits |
| Secondary probes | 1 | One additional path per host beyond the root |
| Browser probes | 1 | One browser verify attempt per ambiguous host |
| Control browser | off | Not available unless `aggressive` |
| Retry limit | 2 | Retries transient errors (internal constant) |

Use `--scan-profile aggressive` only when you need deeper confirmation and are aware of the higher request volume toward target servers.

---

## Getting the most accurate results

**Best setup:**

1. Supply a control proxy via SOCKS5 (ideally through local Xray with a `vless://` link)
2. Use `--scan-profile default` or `aggressive`
3. Enable browser verification with `--browser`
4. Focus on curated service sets, not huge raw lists
5. Use `--state-dir` to accumulate a confirmed local base over multiple runs

**Interpret results as:**

- `ConfirmedProxyRequired` — high confidence, safe to add to router config
- `CandidateProxyRequired` — likely blocked, worth adding with monitoring
- `NeedsReview` — ambiguous; run again with a control proxy before routing
- `Inconclusive` — not enough role coverage to decide; add missing hosts to input list
