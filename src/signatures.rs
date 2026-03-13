use aho_corasick::AhoCorasick;
use serde::Serialize;
use std::sync::OnceLock;

static UA_POOL: OnceLock<Vec<String>> = OnceLock::new();

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum BlockType {
    Geo,
    Waf,
    Captcha,
    Api,
    Isp,
    Limit,
    Dead,
    Unknown,
}

impl BlockType {
    pub fn report_priority(self) -> u8 {
        match self {
            Self::Geo => 10,
            Self::Isp => 9,
            Self::Captcha => 8,
            Self::Waf => 7,
            Self::Api => 6,
            Self::Limit => 5,
            Self::Dead => 4,
            Self::Unknown => 1,
        }
    }

    pub fn match_weight(self) -> u16 {
        match self {
            Self::Geo => 50,
            Self::Captcha => 45,
            Self::Isp => 40,
            Self::Waf => 35,
            Self::Api => 30,
            Self::Limit => 20,
            Self::Dead => 15,
            Self::Unknown => 0,
        }
    }
}

impl std::fmt::Display for BlockType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Geo => "GEO",
            Self::Waf => "WAF",
            Self::Captcha => "CAPTCHA",
            Self::Api => "API",
            Self::Isp => "ISP",
            Self::Limit => "LIMIT",
            Self::Dead => "DEAD",
            Self::Unknown => "BLOCK",
        };
        write!(f, "{s}")
    }
}

pub fn get_random_user_agent() -> &'static str {
    let pool = UA_POOL.get_or_init(|| {
        let mut agents = Vec::with_capacity(32);

        // Chrome on Windows (primary — matches wreq Emulation profile)
        for _ in 0..16 {
            let chrome_ver = fastrand::u32(144..=148);
            agents.push(format!(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_ver}.0.0.0 Safari/537.36"
            ));
        }

        // Chrome on macOS
        for _ in 0..8 {
            let chrome_ver = fastrand::u32(144..=148);
            agents.push(format!(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_ver}.0.0.0 Safari/537.36"
            ));
        }

        // Chrome on Linux
        for _ in 0..8 {
            let chrome_ver = fastrand::u32(144..=148);
            agents.push(format!(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_ver}.0.0.0 Safari/537.36"
            ));
        }

        agents
    });

    let idx = fastrand::usize(..pool.len());
    &pool[idx]
}

fn is_low_signal_body_pattern(sig: &str, btype: BlockType) -> bool {
    let normalized = sig.trim().to_ascii_lowercase();

    if normalized.len() < 6 {
        return true;
    }

    if matches!(btype, BlockType::Waf | BlockType::Geo | BlockType::Unknown) {
        return matches!(
            normalized.as_str(),
            "blocked"
                | "denied"
                | "forbidden"
                | "restricted"
                | "unavailable"
                | "suspended"
                | "not available"
                | "is not available"
                | "service is not available"
                | "access denied"
                | "not supported"
                | "is currently unavailable"
                | "currently unavailable"
                | "document.cookie="
                | "<meta http-equiv=\"refresh\""
        );
    }

    false
}

fn pattern_specificity(sig: &str, btype: BlockType) -> u16 {
    let normalized = sig.trim().to_ascii_lowercase();
    let mut score = u16::try_from(normalized.len()).unwrap_or(u16::MAX);

    if matches!(btype, BlockType::Geo)
        && (normalized.contains("your region")
            || normalized.contains("your country")
            || normalized.contains("your location")
            || normalized.contains("certain regions")
            || normalized.contains("available in your"))
    {
        score += 80;
    }

    if matches!(btype, BlockType::Waf | BlockType::Captcha)
        && (normalized.contains("challenge")
            || normalized.contains("captcha")
            || normalized.contains("cf-")
            || normalized.contains("access denied"))
    {
        score += 60;
    }

    score + btype.match_weight()
}

// ─── Header signatures ─────────────────────────────────────────────────────────

const SIGNATURES_HEADERS: &[(&str, BlockType)] = &[
    // Sucuri
    ("x-sucuri-id", BlockType::Waf),
    ("x-sucuri-cache", BlockType::Waf),
    ("server: sucuri", BlockType::Waf),
    // Akamai
    ("x-akamaized", BlockType::Waf),
    ("akamai-grn", BlockType::Waf),
    // Generic CDN / WAF presence
    ("x-firewall", BlockType::Waf),
    ("x-waf", BlockType::Waf),
    // Imperva / Incapsula
    ("visid_incap", BlockType::Waf),
    ("incap_ses", BlockType::Waf),
    ("x-iinfo", BlockType::Waf),
    ("x-cdn: imperva", BlockType::Waf),
    // Barracuda
    ("barra counter", BlockType::Waf),
    ("barra_counter_session", BlockType::Waf),
    // Radware
    ("rdwr", BlockType::Waf),
    // AWS WAF
    ("x-amzn-waf-action", BlockType::Waf),
    // Reblaze
    ("rbzid", BlockType::Waf),
    ("x-reblaze-protection", BlockType::Waf),
    // Qrator
    ("qrator-jsid", BlockType::Waf),
    // DDoS-Guard
    ("ddos-guard", BlockType::Waf),
    ("__ddg", BlockType::Waf),
    ("server: ddos-guard", BlockType::Waf),
    // Wallarm
    ("x-wallarm-waf-check", BlockType::Waf),
    // F5 BIG-IP
    ("x-wa-info", BlockType::Waf),
    ("f5-trafficshield", BlockType::Waf),
    // Cloudflare
    ("cf-mitigated: challenge", BlockType::Waf),
    ("cf-chl-bypass", BlockType::Waf),
    // ═══ RU/BY ISP block headers ═══
    // Rostelecom / MGTS / TTKSIP
    ("x-blocked-by", BlockType::Isp),
    ("x-rkn-block", BlockType::Isp),
    ("x-filter-reason", BlockType::Isp),
    ("x-filter-url", BlockType::Isp),
    // Beltelecom / BELPAK
    ("x-beltelecom-block", BlockType::Isp),
    ("server: beltelecom", BlockType::Isp),
    // MTS / Beeline / Megafon stubs
    ("x-squid-error", BlockType::Isp),
    ("x-cache: error", BlockType::Isp),
    ("server: squid", BlockType::Isp),
];

// ─── Body signatures (deduplicated, sorted by specificity) ──────────────────────

const SIGNATURES_BODY: &[(&str, BlockType)] = &[
    // ═══ JS Challenge / Anti-Bot ═══
    ("settimeout(function(){location.reload", BlockType::Waf),
    ("window._cf_chl_opt", BlockType::Waf),
    ("cf_chl_prog", BlockType::Waf),
    ("cf_chl_jschl", BlockType::Waf),
    ("challenge-form", BlockType::Waf),
    ("challenge-running", BlockType::Waf),
    ("jschl-answer", BlockType::Waf),
    ("id=\"challenge-form\"", BlockType::Waf),
    ("id=\"cf-error-details\"", BlockType::Waf),
    ("class=\"cf-browser-verification\"", BlockType::Waf),
    ("window.location.reload()", BlockType::Waf),
    ("location.href=location.href", BlockType::Waf),
    ("cdn-cgi/challenge-platform", BlockType::Waf),
    ("cf-browser-verification", BlockType::Waf),
    ("cf-error-details", BlockType::Waf),
    ("checking if the site connection is secure", BlockType::Waf),
    ("checking your browser", BlockType::Waf),
    ("please enable cookies", BlockType::Waf),
    ("verify you are human", BlockType::Waf),
    ("verify your identity", BlockType::Waf),
    // ═══ Bot Detection Frameworks ═══
    ("bot-detection", BlockType::Waf),
    ("bot protection", BlockType::Waf),
    ("browser verification", BlockType::Waf),
    ("fingerprintjs", BlockType::Waf),
    ("fp.min.js", BlockType::Waf),
    ("clientjs", BlockType::Waf),
    ("datadome protection", BlockType::Waf),
    ("datadome cookie", BlockType::Waf),
    ("id=\"px-captcha\"", BlockType::Waf),
    ("class=\"px-captcha\"", BlockType::Waf),
    ("client.px-cdn.net", BlockType::Waf),
    ("wordfence", BlockType::Waf),
    ("bitninja", BlockType::Waf),
    ("radware bot manager", BlockType::Waf),
    ("istlwashere", BlockType::Waf),
    // Shape Security
    ("shape security", BlockType::Waf),
    ("shape-ts", BlockType::Waf),
    // Kasada
    ("kasada", BlockType::Waf),
    ("kpf-challenge", BlockType::Waf),
    // F5 Distributed Cloud
    ("f5-distributed-cloud", BlockType::Waf),
    // Edgio
    ("this request was blocked by edgio", BlockType::Waf),
    // Vercel
    ("vercel security", BlockType::Waf),
    // ═══ Captcha ═══
    ("class=\"g-recaptcha\"", BlockType::Captcha),
    ("id=\"captcha\"", BlockType::Captcha),
    ("recaptcha/api2/anchor", BlockType::Captcha),
    ("recaptcha/api2/reload", BlockType::Captcha),
    ("hcaptcha.com/1/api.js", BlockType::Captcha),
    ("hcaptcha-widget", BlockType::Captcha),
    ("id=\"cf-turnstile\"", BlockType::Captcha),
    ("class=\"cf-turnstile\"", BlockType::Captcha),
    ("cf-turnstile-response", BlockType::Captcha),
    ("arkoselabs", BlockType::Captcha),
    ("funcaptcha", BlockType::Captcha),
    ("geetest", BlockType::Captcha),
    // ═══ CDN Errors ═══
    ("fastly error", BlockType::Waf),
    ("access denied. reference", BlockType::Waf),
    ("akamai ghost", BlockType::Waf),
    ("errors.edgesuite.net", BlockType::Waf),
    // ═══ TLS / Fingerprint Blocks ═══
    ("ja4_fingerprint_mismatch", BlockType::Waf),
    ("fingerprint_blocked", BlockType::Waf),
    ("fingerprint mismatch", BlockType::Waf),
    ("ja4 fingerprint blocked", BlockType::Waf),
    ("ech_required", BlockType::Waf),
    ("zstd compression required", BlockType::Waf),
    ("unsupported protocol version", BlockType::Isp),
    // ═══ Generic WAF / Block page markers ═══
    ("<title>access denied</title>", BlockType::Waf),
    ("<title>Access Denied", BlockType::Waf),
    ("<title>forbidden</title>", BlockType::Waf),
    ("<title>Forbidden", BlockType::Waf),
    ("<title>blocked</title>", BlockType::Waf),
    ("<title>Request blocked", BlockType::Waf),
    ("you don't have permission to access", BlockType::Waf),
    ("access denied by", BlockType::Waf),
    // Removed bare "access denied" — too broad; caught by more specific signatures
    ("403 forbidden", BlockType::Waf),
    // Removed bare "reference #" — too broad, appears in legitimate pages
    // Removed "unable to load site" — too broad, appears on network errors
    // AWS Shield
    ("request blocked by aws", BlockType::Waf),
    // ═══ Geo — English (most specific first) ═══
    ("<h1>not supported in your country</h1>", BlockType::Geo),
    (
        "<title>not available in your region</title>",
        BlockType::Geo,
    ),
    (">not available in your region<", BlockType::Geo),
    (">disney+ is not available in your region<", BlockType::Geo),
    (">App unavailable<", BlockType::Geo),
    (
        ">Claude is only available in certain regions<",
        BlockType::Geo,
    ),
    ("service is not available in your region", BlockType::Geo),
    ("service restricted in your region", BlockType::Geo),
    ("not supported in your country", BlockType::Geo),
    ("not supported in your region", BlockType::Geo),
    ("not available in your region", BlockType::Geo),
    ("not available in your country", BlockType::Geo),
    ("not available in your location", BlockType::Geo),
    ("not available in your area", BlockType::Geo),
    ("not yet available in your", BlockType::Geo),
    ("is not supported in your country", BlockType::Geo),
    ("is not supported in your", BlockType::Geo),
    ("is not available in your", BlockType::Geo),
    ("isn't available in your", BlockType::Geo),
    ("isn't supported in your", BlockType::Geo),
    ("isn't available in your country", BlockType::Geo),
    ("isn't supported in your country", BlockType::Geo),
    ("only available in certain", BlockType::Geo),
    ("available in certain regions", BlockType::Geo),
    ("currently unavailable in your", BlockType::Geo),
    ("is currently unavailable", BlockType::Geo),
    ("region-lock", BlockType::Geo),
    ("geoblocked", BlockType::Geo),
    ("geo-blocked", BlockType::Geo),
    ("not currently supported", BlockType::Geo),
    ("location is not supported", BlockType::Geo),
    ("attention-needed-block", BlockType::Geo),
    ("not available in your", BlockType::Geo),
    ("not available in this", BlockType::Geo),
    ("not supported in your", BlockType::Geo),
    ("unavailable in your", BlockType::Geo),
    ("restriced in your", BlockType::Geo),
    ("suspended in your", BlockType::Geo),
    ("blocked in your", BlockType::Geo),
    ("service is not available", BlockType::Geo),
    ("services are not available", BlockType::Geo),
    ("site is not available", BlockType::Geo),
    ("app is not available", BlockType::Geo),
    // ═══ Geo — Region-specific ═══
    ("not available in russia", BlockType::Geo),
    ("not available in belarus", BlockType::Geo),
    ("suspended in russia", BlockType::Geo),
    ("suspended operations", BlockType::Geo),
    ("withdrawal only", BlockType::Geo),
    ("limited service", BlockType::Geo),
    ("borderfree", BlockType::Geo),
    ("esw.com", BlockType::Geo),
    ("hbo max is not available", BlockType::Geo),
    ("max is not available", BlockType::Geo),
    ("prime video is not available", BlockType::Geo),
    // ═══ Geo — AI Services ═══
    ("openai's services are not available", BlockType::Geo),
    ("chatgpt is not available", BlockType::Geo),
    ("claude is not yet available", BlockType::Geo),
    ("claude is only available", BlockType::Geo),
    ("app unavailable in region", BlockType::Geo),
    ("gemini пока не поддерживается", BlockType::Geo),
    ("gemini is not yet supported", BlockType::Geo),
    ("gemini isn't available", BlockType::Geo),
    ("gemini is not available", BlockType::Geo),
    ("boq-bard-web", BlockType::Geo),
    ("bard-web-client", BlockType::Geo),
    // ═══ Geo — Brand-specific ═══
    ("grammarly is suspending service", BlockType::Geo),
    ("grammarly has suspended our services", BlockType::Geo),
    (
        "not be able to access your grammarly account",
        BlockType::Geo,
    ),
    ("grammarly is not available", BlockType::Geo),
    (
        "under the current circumstances, we are suspending paypal services in russia",
        BlockType::Geo,
    ),
    // ═══ ISP / Government blocks ═══
    ("149-fz", BlockType::Geo),
    ("rkn.gov.ru", BlockType::Geo),
    ("доступ к ресурсу ограничен", BlockType::Geo),
    ("на основании федерального закона", BlockType::Geo),
    ("реестр запрещенных", BlockType::Isp),
    ("доступ ограничен", BlockType::Isp),
    ("Доступ ограничен", BlockType::Isp),
    ("该内容无法访问", BlockType::Isp),
    // ═══ ISP / Government — RU (Роскомнадзор) ═══
    // Rostelecom/MGTS/Beeline/TTK block pages
    ("rkn-informer", BlockType::Isp),
    ("roscomnadzor", BlockType::Isp),
    ("internet-filter-response", BlockType::Isp),
    ("warning.rt.ru", BlockType::Isp),
    ("eais.rkn.gov.ru", BlockType::Geo),
    ("zapret-info.gov.ru", BlockType::Geo),
    ("мфц.рф", BlockType::Isp),
    ("заблокирован", BlockType::Isp),
    ("ресурс заблокирован", BlockType::Geo),
    ("сайт заблокирован", BlockType::Geo),
    ("доступ к сайту ограничен", BlockType::Geo),
    ("данный сайт заблокирован", BlockType::Geo),
    ("данный ресурс заблокирован", BlockType::Geo),
    ("сайт заблокирован по решению", BlockType::Geo),
    ("роскомнадзор", BlockType::Geo),
    ("rostelekom-stub", BlockType::Isp),
    ("mts-block-page", BlockType::Isp),
    ("beeline-block", BlockType::Isp),
    ("megafon-block", BlockType::Isp),
    ("ttk-block", BlockType::Isp),
    ("er-telecom-block", BlockType::Isp),
    // ═══ ISP / Government — BY (Beltelecom / BELPAK) ═══
    ("beltelecom.by", BlockType::Isp),
    ("belpak.by", BlockType::Isp),
    ("доступ к запрошенному ресурсу ограничен", BlockType::Isp),
    ("доступ к данному ресурсу ограничен", BlockType::Isp),
    ("доступ заблокирован", BlockType::Isp),
    ("операционно-аналитический центр", BlockType::Geo),
    ("оац при президенте республики беларусь", BlockType::Geo),
    ("ministerstvo informacii", BlockType::Geo),
    ("minskaya oblast", BlockType::Isp),
    // Generic ISP stub page patterns (seen across RU/BY ISPs)
    ("squid proxy server", BlockType::Isp),
    ("generated by squid", BlockType::Isp),
    (
        "your access to this website has been blocked",
        BlockType::Isp,
    ),
    ("this content is blocked", BlockType::Isp),
    ("blocked by your internet service provider", BlockType::Isp),
    ("blocked by isp", BlockType::Isp),
    // ═══ Geo — Russian / Cyrillic ═══
    ("не поддерживается в вашей стране", BlockType::Geo),
    ("не поддерживается в вашем регионе", BlockType::Geo),
    ("недоступно в вашей стране", BlockType::Geo),
    ("недоступно в вашем регионе", BlockType::Geo),
    ("ограничен по географическому", BlockType::Geo),
    ("географическим ограничением", BlockType::Geo),
    ("пока не поддерживается в вашей стране", BlockType::Geo),
    ("сервис недоступен в вашем регионе", BlockType::Geo),
    ("услуга недоступна в вашей стране", BlockType::Geo),
    ("контент ограничен в вашем регионе", BlockType::Geo),
    // ═══ Geo — Turkish ═══
    ("bölgenizde kullanılamıyor", BlockType::Geo),
    ("ülkenizde desteklenmiyor", BlockType::Geo),
    ("bu hizmet bölgenizde", BlockType::Geo),
    ("coğrafi kısıtlama", BlockType::Geo),
    // ═══ Geo — German ═══
    ("in ihrem land nicht verfügbar", BlockType::Geo),
    ("in ihrer region nicht verfügbar", BlockType::Geo),
    ("dieser dienst ist in ihrem land", BlockType::Geo),
    ("dieser inhalt ist nicht verfügbar", BlockType::Geo),
    // ═══ Geo — French ═══
    ("n'est pas disponible dans votre", BlockType::Geo),
    ("indisponible dans votre région", BlockType::Geo),
    ("ce service n'est pas disponible", BlockType::Geo),
    ("n'est pas accessible depuis votre", BlockType::Geo),
    // ═══ Geo — Arabic ═══
    ("غير متاح في منطقتك", BlockType::Geo),
    ("غير متوفر في بلدك", BlockType::Geo),
    ("هذه الخدمة غير متاحة", BlockType::Geo),
    // ═══ Geo — Korean ═══
    ("지역에서는 이용할 수 없", BlockType::Geo),
    ("귀하의 국가에서는", BlockType::Geo),
    ("해당 지역에서 사용할 수 없습니다", BlockType::Geo),
    // ═══ Geo — Japanese ═══
    ("お住まいの地域では", BlockType::Geo),
    ("この地域ではご利用いただけ", BlockType::Geo),
    ("お客様の国ではご利用いただけません", BlockType::Geo),
    // ═══ Geo — Chinese ═══
    ("你所在的地区不可用", BlockType::Geo),
    ("因地域限制无法访问", BlockType::Geo),
    ("该服务在您的地区不可用", BlockType::Geo),
    ("此内容在您的国家不可用", BlockType::Geo),
    // ═══ Geo — Portuguese / Spanish ═══
    ("não está disponível na sua região", BlockType::Geo),
    ("no está disponible en tu región", BlockType::Geo),
    ("no está disponible en su país", BlockType::Geo),
    ("serviço indisponível na sua região", BlockType::Geo),
    // ═══ Dead services ═══
    ("paxful has ceased operations", BlockType::Dead),
    ("paxful is currently suspended", BlockType::Dead),
    ("ceased operations", BlockType::Dead),
    // ═══ Rate limiting ═══
    ("too many requests", BlockType::Limit),
    ("rate limit exceeded", BlockType::Limit),
    ("rate limited", BlockType::Limit),
    ("throttled", BlockType::Limit),
    // ═══ Misc markers ═══
    ("wiz_global_data", BlockType::Unknown),
];

// ─── API signatures ─────────────────────────────────────────────────────────────

const SIGNATURES_API: &[(&str, BlockType)] = &[
    ("\"error\":\"access_denied\"", BlockType::Api),
    ("\"error\":\"forbidden\"", BlockType::Api),
    ("\"error\":\"blocked\"", BlockType::Api),
    ("\"error\":\"not_allowed\"", BlockType::Api),
    ("\"error\":\"geo_restricted\"", BlockType::Api),
    ("\"error\":\"region_locked\"", BlockType::Api),
    ("\"error\":\"country_blocked\"", BlockType::Api),
    ("\"message\":\"access denied\"", BlockType::Api),
    ("\"detail\":\"access denied\"", BlockType::Api),
    ("\"status\":403", BlockType::Api),
    ("\"status\":451", BlockType::Api),
    // GraphQL-style errors
    ("\"code\":\"FORBIDDEN\"", BlockType::Api),
    ("\"code\":\"GEO_RESTRICTED\"", BlockType::Api),
    ("\"code\":\"COUNTRY_BLOCKED\"", BlockType::Api),
    ("\"code\":\"REGION_BLOCKED\"", BlockType::Api),
    // Common REST patterns
    ("\"error\":\"unavailable_in_region\"", BlockType::Api),
    (
        "\"error\":\"service_unavailable_in_country\"",
        BlockType::Api,
    ),
    ("\"type\":\"geo_restriction\"", BlockType::Api),
];

// ─── BlockMatcher ────────────────────────────────────────────────────────────────

pub struct BlockMatcher {
    ac_headers: AhoCorasick,
    patterns_headers: Vec<(String, BlockType)>,
    ac_body: AhoCorasick,
    patterns_body: Vec<(String, BlockType)>,
    ac_api: AhoCorasick,
    patterns_api: Vec<(String, BlockType)>,
}

impl BlockMatcher {
    pub fn new(signatures_file: Option<&std::path::Path>) -> anyhow::Result<Self> {
        let mut p_headers = Vec::new();
        let mut p_body = Vec::new();
        let mut p_api = Vec::new();

        // 1. Headers
        for &(sig, btype) in SIGNATURES_HEADERS {
            p_headers.push((sig.to_lowercase(), btype));
        }

        // 2. Body
        for &(sig, btype) in SIGNATURES_BODY {
            if !is_low_signal_body_pattern(sig, btype) {
                p_body.push((sig.to_lowercase(), btype));
            }
        }

        // 3. API
        for &(sig, btype) in SIGNATURES_API {
            p_api.push((sig.to_lowercase(), btype));
        }

        // 4. User Signatures (Targeting BODY)
        if let Some(path) = signatures_file
            && path.exists()
        {
            let content = std::fs::read_to_string(path)?;
            for line in content.lines() {
                let clean = line.trim();
                if !clean.is_empty() && !clean.starts_with('#') {
                    p_body.push((clean.to_lowercase(), BlockType::Unknown));
                }
            }
        }

        // Helper to build AC and dedup patterns
        let finalize = |mut p: Vec<(String, BlockType)>| -> anyhow::Result<(AhoCorasick, Vec<(String, BlockType)>)> {
            p.sort();
            p.dedup();

            let strings: Vec<String> = p.iter().map(|(s, _)| s.clone()).collect();
            let ac = AhoCorasick::builder()
                .match_kind(aho_corasick::MatchKind::LeftmostLongest)
                .build(&strings)
                .map_err(|e| anyhow::anyhow!("AC build error: {e:?}"))?;
            Ok((ac, p))
        };

        let (ac_headers, patterns_headers) = finalize(p_headers)?;
        let (ac_body, patterns_body) = finalize(p_body)?;
        let (ac_api, patterns_api) = finalize(p_api)?;

        Ok(Self {
            ac_headers,
            patterns_headers,
            ac_body,
            patterns_body,
            ac_api,
            patterns_api,
        })
    }

    pub fn find_header_pairs(&self, headers: &[(String, String)]) -> Option<(String, BlockType)> {
        let mut best: Option<(usize, u16)> = None;

        for (key, value) in headers {
            let combined = format!("{}: {}", key.to_lowercase(), value.to_lowercase());
            for m in self.ac_headers.find_iter(combined.as_bytes()) {
                let idx = m.pattern().as_usize();
                let score = pattern_specificity(
                    &self.patterns_headers[idx].0,
                    self.patterns_headers[idx].1,
                );
                if best.is_none_or(|(_, best_score)| score > best_score) {
                    best = Some((idx, score));
                }
            }

            let val_lower = value.to_lowercase();
            for m in self.ac_headers.find_iter(val_lower.as_bytes()) {
                let idx = m.pattern().as_usize();
                let score = pattern_specificity(
                    &self.patterns_headers[idx].0,
                    self.patterns_headers[idx].1,
                );
                if best.is_none_or(|(_, best_score)| score > best_score) {
                    best = Some((idx, score));
                }
            }

            let key_lower = key.to_lowercase();
            for m in self.ac_headers.find_iter(key_lower.as_bytes()) {
                let idx = m.pattern().as_usize();
                let score = pattern_specificity(
                    &self.patterns_headers[idx].0,
                    self.patterns_headers[idx].1,
                );
                if best.is_none_or(|(_, best_score)| score > best_score) {
                    best = Some((idx, score));
                }
            }
        }

        best.map(|(idx, _)| self.patterns_headers[idx].clone())
    }

    /// Match body text for block signatures.
    /// CONTRACT: `body` is passed as-is; this method lowercases internally.
    pub fn find_body_text(&self, body: &str) -> Option<(String, BlockType)> {
        let lower = body.to_lowercase();
        let mut best: Option<(usize, u16)> = None;
        for m in self.ac_body.find_iter(lower.as_bytes()) {
            let idx = m.pattern().as_usize();
            let score = pattern_specificity(&self.patterns_body[idx].0, self.patterns_body[idx].1);
            if best.is_none_or(|(_, best_score)| score > best_score) {
                best = Some((idx, score));
            }
        }
        best.map(|(idx, _)| self.patterns_body[idx].clone())
    }

    /// Match API/JSON body text for block signatures.
    /// CONTRACT: `body` is passed as-is; this method lowercases internally.
    pub fn find_api_text(&self, body: &str) -> Option<(String, BlockType)> {
        let lower = body.to_lowercase();
        let mut best: Option<(usize, u16)> = None;
        for m in self.ac_api.find_iter(lower.as_bytes()) {
            let idx = m.pattern().as_usize();
            let score = pattern_specificity(&self.patterns_api[idx].0, self.patterns_api[idx].1);
            if best.is_none_or(|(_, best_score)| score > best_score) {
                best = Some((idx, score));
            }
        }
        best.map(|(idx, _)| self.patterns_api[idx].clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_body() {
        let matcher = BlockMatcher::new(None).unwrap();

        let res = matcher
            .find_body_text("<html><div id=\"challenge-form\"></div></html>")
            .unwrap();
        assert_eq!(res.0, "id=\"challenge-form\"");
        assert_eq!(res.1, BlockType::Waf);
    }

    #[test]
    fn low_signal_patterns_are_filtered() {
        assert!(is_low_signal_body_pattern("blocked", BlockType::Geo));
        assert!(is_low_signal_body_pattern("access denied", BlockType::Waf));
        assert!(is_low_signal_body_pattern(
            "document.cookie=",
            BlockType::Waf
        ));
        assert!(is_low_signal_body_pattern(
            "<meta http-equiv=\"refresh\"",
            BlockType::Unknown
        ));
        assert!(!is_low_signal_body_pattern(
            "not available in your region",
            BlockType::Geo
        ));
        assert!(!is_low_signal_body_pattern(
            "cf-browser-verification",
            BlockType::Waf
        ));
    }

    #[test]
    fn header_matcher_supports_combined_header_and_value() {
        let matcher = BlockMatcher::new(None).unwrap();
        let headers = vec![("server".to_string(), "Sucuri".to_string())];

        let res = matcher.find_header_pairs(&headers).unwrap();
        assert_eq!(res.1, BlockType::Waf);
    }

    #[test]
    fn cdn_presence_headers_are_not_treated_as_waf_by_themselves() {
        let matcher = BlockMatcher::new(None).unwrap();
        let headers = vec![("x-amz-cf-pop".to_string(), "FRA60-P1".to_string())];

        assert!(matcher.find_header_pairs(&headers).is_none());
    }

    #[test]
    fn body_matcher_prefers_more_specific_geo_phrase() {
        let matcher = BlockMatcher::new(None).unwrap();
        let res = matcher
            .find_body_text("service is not available in your region")
            .unwrap();

        assert_eq!(res.1, BlockType::Geo);
        assert!(res.0.len() >= "not available in your".len());
    }

    #[test]
    fn detects_multilingual_geo_blocks() {
        let matcher = BlockMatcher::new(None).unwrap();

        // Turkish
        let res = matcher.find_body_text("bölgenizde kullanılamıyor").unwrap();
        assert_eq!(res.1, BlockType::Geo);

        // German
        let res = matcher
            .find_body_text("in ihrem land nicht verfügbar")
            .unwrap();
        assert_eq!(res.1, BlockType::Geo);

        // French
        let res = matcher
            .find_body_text("n'est pas disponible dans votre pays")
            .unwrap();
        assert_eq!(res.1, BlockType::Geo);

        // Japanese
        let res = matcher
            .find_body_text("お住まいの地域では利用できません")
            .unwrap();
        assert_eq!(res.1, BlockType::Geo);
    }

    #[test]
    fn detects_api_block_patterns() {
        let matcher = BlockMatcher::new(None).unwrap();

        let res = matcher
            .find_api_text("{\"error\":\"geo_restricted\",\"status\":403}")
            .unwrap();
        assert_eq!(res.1, BlockType::Api);

        let res = matcher
            .find_api_text("{\"code\":\"GEO_RESTRICTED\",\"message\":\"Blocked\"}")
            .unwrap();
        assert_eq!(res.1, BlockType::Api);
    }

    #[test]
    fn user_agent_pool_has_variety() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..100 {
            seen.insert(get_random_user_agent().to_string());
        }
        // Should get at least a few different UAs
        assert!(seen.len() >= 3);
    }
}
