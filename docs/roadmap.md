# Roadmap

---

## v0.1.3 — Active Development (The "2026" Upgrade)

> Focused on high-fidelity browser emulation, next-gen DPI evasion, and extreme performance.

### 🛡️ Intelligence & Accuracy (WAF & Captcha Bypass)
- ~~**Next-Gen TLS Fingerprinting (JA4+ / `rquest`):**~~
    - ~~Transition from `wreq` to **`rquest`** (BoringSSL-based) for perfect JA4+ signatures.~~ *(Completed)*
    - ~~Implement mandatory support for **X25519-MLKEM768** (Group ID `0x11EC`) to match Chrome 146+ defaults.~~ *(Completed)*
    - ~~Synchronize HTTP/2 SETTINGS and WINDOW_UPDATE frame ordering with the impersonated browser profile.~~ *(Completed)*
- **AI Labyrinth Evasion:**
    - Replace generic headless probing with **`Nodriver`** (CDP-based) to bypass `navigator.webdriver` detection.
    - Implement **Visibility-Only Interaction**: Ensure the scanner never follows "invisible" (honeypot) links used by Cloudflare's 2026 AI Labyrinth.
    - Integrate **CapSolver/2Captcha** API hooks for mandatory interactive Turnstile challenges.
- **Smart WAF/Captcha Promotion:** 
    - Automatically promote WAF (403) or Captcha results to `ConfirmedProxyRequired` if the local path is blocked but the Control Proxy sees `200 OK`.
- **HTTP-Level IP Spoofing:**
    - Inject resident IP headers (`X-Forwarded-For`, `X-Real-IP`, `True-Client-IP`) with randomized residential CIDR ranges to bypass backend-level reputation filters.

### 🚀 Performance & Scale
- **O(N log N) Domain Minimization:** 
    - Implement a zero-allocation minimizer: Reverse domains (`com.google.www`), sort, and filter redundant subdomains in a single linear pass. 
    - Goal: Sub-second processing for lists > 100k domains.
- **Concurrent Domain Ingestion:** 
    - Parallelize input file processing using `tokio::fs` and async tasks to eliminate startup latency when loading massive community lists.
- **Moving Average Speed Smoothing:** 
    - Implement a 3-second moving window for the progress bar to provide stable velocity metrics.

### 📡 Network & Evasion
- **ECH (Encrypted Client Hello) Support:** 
    - Add `--enable-ech` to fetch ECH configurations via DoH and fully encrypt the SNI field, bypassing SNI-based DPI for ECH-enabled CDNs.
- **XHTTP & HTTP/3 Probing:** 
    - Add support for **Xray's XHTTP** (transaction-based) transport.
    - Implement **Referer Padding**: Distribute random obfuscation bytes into the `Referer` header to mimic XHTTP v26.2 behavior.
    - Test UDP-based HTTP/3 (QUIC) viability as an alternative to TCP-blocked routes.
- **DNS-level block detection:** 
    - Compare System DNS vs DoH responses to detect NXDOMAIN injection and blockpage IP poisoning.

### 📦 Output & Export Formats
- **Direct `.srs` (sing-box Rule Set v4) Compilation:** 
    - Implement direct binary serialization to **.srs v4** using **Succinct Sets** for maximum performance and minimal memory footprint on low-end routers.
- **Mihomo Rule-Set (`.mrs`) Export:** 
    - Support binary rule-sets for the latest Mihomo (Clash) kernels.
- **GeoIP `geoip.dat` Generation:** 
    - Aggregate results into binary GeoIP CIDR subnets.

### 🛠️ Tooling & State
- **Global Configuration (`bulbascan.toml`):** Persistent settings for proxies, timeouts, and default export profiles.
- **Daemon / REST API Mode:** Long-running background scan service with a JSON API for dashboard integration.
- **Enhanced Scan Reports:** Add confidence histograms and non-technical per-service summaries to `reports.rs`.
