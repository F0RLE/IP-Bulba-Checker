# Limits and Safety Defaults

> What Bulbascan does well, where ambiguity still exists, and how to get the most reliable selective-proxy results.

---

## Where the Scanner Is Strong

- **Dual-vantage comparison with a real external control proxy**
  - This is the strongest source of `ProxyRequired` confidence.
  - It is especially valuable for separating local censorship from globally dead domains.

- **Known services with curated profiles**
  - `profiles.toml` gives Bulbascan role-aware service grouping.
  - This improves decisions like “auth blocked, web direct” or “one critical role still ambiguous”.

- **Layered evidence**
  - HTTP status, headers, redirects, body signatures, network probes, and optional browser DOM evidence are combined instead of relying on one signal.

- **Conservative routing output**
  - Bulbascan already distinguishes `ProxyRequired`, `DirectOk`, and `ManualReview`.
  - That is safer than forcing every ambiguous domain into a proxy list.

---

## Current Limitations

| Area | Detail |
|---|---|
| **Weak control proxy** | If the control proxy is in the same country or a similarly filtered network, comparison quality drops sharply. |
| **ConsistentBlocked ambiguity** | When both local and control paths are blocked, Bulbascan cannot always separate “globally dead” from “blocked on both paths”. |
| **DNS manipulation visibility** | The scanner already records network evidence, but dedicated system-DNS vs DoH disagreement reporting is still missing. |
| **Challenge-heavy services** | Captcha / WAF interstitials can still leave some domains in `ManualReview`, especially when browser confirmation is unavailable. |
| **Incomplete service coverage** | If a service profile lacks enough critical-role hosts, service-level conclusions stay weaker than they could be. |
| **IPv6** | The scanner is still primarily IPv4-oriented. IPv6-only accessibility can be missed. |
| **HTTP/3 / QUIC** | QUIC is not a primary detection path yet. Some CDN behavior may differ from the HTTP/1.1 / HTTP/2 results Bulbascan sees today. |
| **Browser proxy constraints** | Browser-backed verification depends on proxy compatibility and a usable local browser. |

---

## Safety Defaults

The default `safe` profile is intentionally conservative.

| Setting | Safe profile behavior | Why |
|---|---|---|
| Concurrency | lower default worker count | reduces accidental rate-limit noise |
| Secondary probes | limited | avoids probing too many paths on uncertain hosts |
| Browser verification | limited | keeps browser confirmation as a secondary layer |
| Retests | limited | reduces unstable retry storms |
| Control-browser verification | disabled in safe mode | avoids extra browser noise on comparison runs |

Use `aggressive` only when deeper confirmation is more important than a quieter scan footprint.

---

## How To Get The Most Accurate Results

Recommended setup:

1. Use a control proxy outside the blocked jurisdiction.
2. Prefer `socks5` or `socks5h` for comparison work.
3. Supply a browser binary when scanning challenge-heavy services.
4. Use `--state-dir` on repeat runs to accumulate confirmed outcomes.
5. Treat `ManualReview` as an intended output, not as a failure.

Interpret outputs like this:

- `ConfirmedProxyRequired` — high-confidence selective-proxy candidate
- `CandidateProxyRequired` — likely useful, but weaker than confirmed comparison
- `DirectOk` — safe to keep direct
- `ManualReview` / `NeedsReview` — not enough signal to auto-route confidently
- `ConsistentBlocked` — still unresolved without better comparison context
