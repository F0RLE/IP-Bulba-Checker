use crate::service_profiles;
use crate::signatures;

use super::TransportErrorKind;
use super::types::{
    DomainStatus, Evidence, EvidenceBundle, RoutingDecision, ScanPolicy, ScanResult, Verdict,
    build_scan_result, path_from_url_like, routing_decision_for, with_evidence,
};

const INFRA_DOMAIN_MARKERS: &[&str] = &[
    "akamai",
    "akamaiedge",
    "amazonaws",
    "analytics",
    "app-measurement",
    "app-analytics",
    "appsflyersdk",
    "apple-dns",
    "aaplimg",
    "azureedge",
    "azurewebsites",
    "cdn",
    "cloudflare-dns",
    "cloudfront",
    "dns.google",
    "doubleclick",
    "edgekey",
    "edgesuite",
    "fastly",
    "ggpht",
    "googleadservices",
    "googleapis",
    "googletagmanager",
    "googleusercontent",
    "googlevideo",
    "gstatic",
    "gvt1",
    "gvt2",
    "img",
    "measurement",
    "msftconnecttest",
    "msftncsi",
    "static",
    "trafficmanager",
    "windowsupdate",
    "ytimg",
];

const NON_CONSUMER_PLATFORM_MARKERS: &[&str] = &[
    "a2z",
    "amazon.dev",
    "aws.dev",
    "azure",
    "microsoftonline",
    "windows.net",
];

const CONSUMER_DOMAIN_MARKERS: &[&str] = &[
    "avast",
    "chatgpt",
    "facebook",
    "instagram",
    "linkedin",
    "netflix",
    "playstation",
    "roblox",
    "samsung",
    "sentry",
    "spotify",
    "tiktok",
    "whatsapp",
    "youtube",
];

/// Adjust confidence based on the service profile match for the domain.
///
/// - Known service with `browser_verification = true` → +5 for geo/captcha verdicts.
///   These services actively challenge non-target-region users, so our signal is reliable.
/// - Unknown domain (no profile match) → −10 for WAF verdict.
///   WAF signatures on unmapped domains are noisier; pull them toward `ManualReview` threshold.
pub(crate) fn apply_profile_confidence_adjustment(
    domain: &str,
    mut result: ScanResult,
) -> ScanResult {
    match service_profiles::match_target(domain) {
        Some(profile) if profile.browser_verification => {
            if matches!(result.verdict, Verdict::GeoBlocked | Verdict::Captcha) {
                result.confidence = result.confidence.saturating_add(5).min(99);
                result.routing_decision = routing_decision_for(result.verdict, result.confidence);
            }
        }
        None => {
            if result.verdict == Verdict::WafBlocked {
                result.confidence = result.confidence.saturating_sub(10);
                result.routing_decision = routing_decision_for(result.verdict, result.confidence);
            }
        }
        _ => {}
    }
    result
}

pub(crate) fn is_block_status(code: u16) -> bool {
    matches!(code, 403 | 418 | 429 | 451)
}

pub(crate) fn verdict_from_block_type(block_type: signatures::BlockType) -> Verdict {
    match block_type {
        signatures::BlockType::Geo => Verdict::GeoBlocked,
        signatures::BlockType::Waf | signatures::BlockType::Unknown => Verdict::WafBlocked,
        signatures::BlockType::Captcha => Verdict::Captcha,
        signatures::BlockType::Api => Verdict::ApiBlocked,
        signatures::BlockType::Isp => Verdict::NetworkBlocked,
        signatures::BlockType::Limit => Verdict::RateLimited,
        signatures::BlockType::Dead => Verdict::Unreachable,
    }
}

pub(crate) fn status_from_verdict(verdict: Verdict) -> DomainStatus {
    match verdict {
        Verdict::Accessible => DomainStatus::Ok,
        Verdict::TlsFailure | Verdict::Unreachable => DomainStatus::Dead,
        Verdict::GeoBlocked
        | Verdict::WafBlocked
        | Verdict::Captcha
        | Verdict::RateLimited
        | Verdict::ApiBlocked
        | Verdict::NetworkBlocked
        | Verdict::UnexpectedStatus => DomainStatus::Blocked,
    }
}

pub(crate) fn classify_status_code(code: u16) -> Option<Evidence> {
    if !is_block_status(code) {
        return None;
    }

    let (verdict, block_type, confidence) = match code {
        451 => (Verdict::GeoBlocked, signatures::BlockType::Geo, 95),
        429 => (Verdict::RateLimited, signatures::BlockType::Limit, 90),
        418 => (Verdict::WafBlocked, signatures::BlockType::Waf, 70),
        403 => (Verdict::WafBlocked, signatures::BlockType::Waf, 72),
        _ => return None,
    };

    Some(Evidence {
        verdict,
        reason: format!("HTTP {code}"),
        block_type: Some(block_type),
        confidence,
    })
}

pub(crate) fn classify_redirect(url: &str) -> Option<Evidence> {
    let lower = url.to_ascii_lowercase();
    let parsed = reqwest::Url::parse(url).ok();

    let path = parsed
        .as_ref()
        .map(|u| u.path().to_ascii_lowercase())
        .unwrap_or_default();
    let host = parsed
        .as_ref()
        .and_then(|u| u.host_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    let is_captcha = host.contains("captcha")
        || host.contains("challenge")
        || path.starts_with("/cdn-cgi/challenge")
        || path == "/challenge"
        || path == "/captcha"
        || path.starts_with("/captcha-delivery")
        || lower.contains("google.com/sorry");

    if is_captcha {
        return Some(Evidence {
            verdict: Verdict::Captcha,
            reason: format!("Redirect: {url}"),
            block_type: Some(signatures::BlockType::Captcha),
            confidence: 82,
        });
    }

    let patterns = [
        "geo-",
        "not-available",
        "not-supported",
        "servicerestricted",
        "access-denied",
        "warning.rt.ru",
        "internet-filter-response",
        "rkn-block",
        "rkn.gov.ru",
        "zapret-info",
        "eais.rkn",
        "roscomnadzor",
        "beltelecom.by/blocked",
        "belpak.by/block",
        "oac.gov.by",
    ];

    let matched = patterns.iter().find(|pattern| lower.contains(**pattern))?;

    let (verdict, block_type, confidence) = if matches!(
        *matched,
        "warning.rt.ru"
            | "internet-filter-response"
            | "rkn-block"
            | "rkn.gov.ru"
            | "zapret-info"
            | "eais.rkn"
            | "roscomnadzor"
            | "beltelecom.by/blocked"
            | "belpak.by/block"
            | "oac.gov.by"
    ) {
        (Verdict::NetworkBlocked, signatures::BlockType::Isp, 93)
    } else {
        (Verdict::GeoBlocked, signatures::BlockType::Geo, 80)
    };

    Some(Evidence {
        verdict,
        reason: format!("Redirect: {url}"),
        block_type: Some(block_type),
        confidence,
    })
}

pub(crate) fn make_signal(
    prefix: &str,
    sig: &str,
    btype: signatures::BlockType,
    confidence: u8,
) -> Evidence {
    Evidence {
        verdict: verdict_from_block_type(btype),
        reason: format!("{prefix}: {sig}"),
        block_type: Some(btype),
        confidence,
    }
}

pub(crate) fn choose_better_signal(current: &mut Option<Evidence>, candidate: Evidence) {
    match current {
        Some(existing) => {
            let current_priority = existing
                .block_type
                .map_or(0, signatures::BlockType::report_priority);
            let candidate_priority = candidate
                .block_type
                .map_or(0, signatures::BlockType::report_priority);

            if candidate.confidence > existing.confidence
                || (candidate.confidence == existing.confidence
                    && candidate_priority > current_priority)
            {
                *current = Some(candidate);
            }
        }
        None => *current = Some(candidate),
    }
}

pub(crate) fn classify_transport_error(error: &str) -> TransportErrorKind {
    let err = error.to_lowercase();

    if err.contains("certificate")
        || err.contains(" cert ")
        || err.contains("tls")
        || err.contains("ssl")
        || err.contains("handshake")
        || err.contains("hostname mismatch")
    {
        return TransportErrorKind::TlsFailure;
    }

    TransportErrorKind::Unreachable
}

fn normalized_host(domain: &str) -> String {
    domain
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(domain)
        .to_ascii_lowercase()
}

fn match_domain_marker(host: &str, markers: &[&str]) -> bool {
    markers.iter().any(|&marker| {
        if marker.contains('.') {
            host == marker || host.ends_with(&format!(".{marker}"))
        } else {
            host.split('.')
                .any(|label| label == marker || label.starts_with(&format!("{marker}-")))
        }
    })
}

fn is_infra_like_domain(domain: &str) -> bool {
    match_domain_marker(&normalized_host(domain), INFRA_DOMAIN_MARKERS)
}

fn is_non_consumer_platform_domain(domain: &str) -> bool {
    match_domain_marker(&normalized_host(domain), NON_CONSUMER_PLATFORM_MARKERS)
}

fn is_consumer_like_domain(domain: &str) -> bool {
    match_domain_marker(&normalized_host(domain), CONSUMER_DOMAIN_MARKERS)
}

pub(crate) fn relax_infra_root_result(mut result: ScanResult) -> ScanResult {
    if result.service.is_some()
        || result.evidence.path.as_deref() != Some("/")
        || is_consumer_like_domain(&result.domain)
        || (!is_infra_like_domain(&result.domain)
            && !is_non_consumer_platform_domain(&result.domain))
    {
        return result;
    }

    match result.verdict {
        Verdict::UnexpectedStatus if matches!(result.http_status, Some(400 | 404 | 405 | 421)) => {
            let status = result.http_status.unwrap_or_default();
            let reason =
                format!("infra apex returned HTTP {status}; treating as non-proxyable root");
            result.status = DomainStatus::Ok;
            result.verdict = Verdict::Accessible;
            result.routing_decision = RoutingDecision::DirectOk;
            result.confidence = 68;
            result.reason.clone_from(&reason);
            result.block_type = None;
            result.evidence.signal = Some(reason);
            result
        }
        Verdict::Unreachable | Verdict::TlsFailure => {
            let reason =
                "infra apex is not reliably probeable as a standalone web target".to_string();
            result.status = DomainStatus::Ok;
            result.verdict = Verdict::Accessible;
            result.routing_decision = RoutingDecision::DirectOk;
            result.confidence = 62;
            result.reason.clone_from(&reason);
            result.block_type = None;
            result.evidence.signal = Some(reason);
            result
        }
        _ => result,
    }
}

pub(crate) fn is_transient_error(error: &str) -> bool {
    let err = error.to_lowercase();
    err.contains("timed out")
        || err.contains("timeout")
        || err.contains("tempor")
        || err.contains("refused")
        || err.contains("dns")
        || err.contains("name or service not known")
        || err.contains("could not resolve")
        || err.contains("no such host")
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) fn analyze_http_observation(
    domain: String,
    matcher: &signatures::BlockMatcher,
    status_code: u16,
    status_label: &str,
    final_url: &str,
    headers: &[(String, String)],
    body_raw: &[u8],
    verbose: bool,
) -> ScanResult {
    let mut best_signal: Option<Evidence> = None;
    let mut signals = Vec::new();
    let body_text = String::from_utf8_lossy(body_raw).into_owned();
    let title = extract_title(&body_text);
    let path = path_from_url_like(final_url);

    // ── Quick Win #1: Status-gated header scoring ──────────────────
    // On 200 OK, CDN-presence headers are informational (confidence 35,
    // well below the should_block threshold of 88). On error status codes
    // (403/429/503 etc.) the full confidence 84 applies.
    if let Some((sig, btype)) = matcher.find_header_pairs(headers) {
        let header_confidence = if (200..300).contains(&status_code) {
            35
        } else {
            84
        };
        let signal = make_signal("Header", &sig, btype, header_confidence);
        choose_better_signal(&mut best_signal, signal.clone());
        signals.push(signal);
    }

    if let Some(signal) = classify_redirect(final_url) {
        choose_better_signal(&mut best_signal, signal.clone());
        signals.push(signal);
    }

    let body_str = body_text.to_lowercase();

    if verbose {
        println!(
            "--- DEBUG BODY [{domain}] ---\n{}\n------------------",
            body_str.chars().take(500).collect::<String>()
        );
    }

    // ── Quick Win #2 & #3: Body scan gating ──────────────────────
    // Skip body signature scan when:
    // - HTTP 429 (rate-limit page often contains WAF-like patterns)
    // - 200 OK with body > 32KB (legitimate content, not a block page)
    let skip_body_scan =
        status_code == 429 || ((200..300).contains(&status_code) && body_raw.len() > 32_768);

    if !skip_body_scan {
        if let Some((sig, btype)) = matcher.find_api_text(&body_text) {
            let signal = make_signal("API", &sig, btype, 95);
            choose_better_signal(&mut best_signal, signal.clone());
            signals.push(signal);
        }
        if let Some((sig, btype)) = matcher.find_body_text(&body_text) {
            let confidence = match btype {
                signatures::BlockType::Captcha => 92,
                signatures::BlockType::Geo => 93,
                signatures::BlockType::Waf => 88,
                signatures::BlockType::Isp | signatures::BlockType::Api => 90,
                signatures::BlockType::Limit => 85,
                signatures::BlockType::Dead => 80,
                signatures::BlockType::Unknown => 65,
            };
            let signal = make_signal("Match", &sig, btype, confidence);
            choose_better_signal(&mut best_signal, signal.clone());
            signals.push(signal);
        }
    }

    if let Some(mut signal) = classify_status_code(status_code) {
        signal.reason = format!("HTTP {status_code} {status_label}");
        choose_better_signal(&mut best_signal, signal.clone());
        signals.push(signal);
    }

    if let Some(signal) = best_signal {
        let verdict_consensus = signals
            .iter()
            .filter(|candidate| candidate.verdict == signal.verdict)
            .count();
        let explicit_geo = signal.verdict == Verdict::GeoBlocked
            && (signal.reason.contains("your region")
                || signal.reason.contains("your country")
                || signal.reason.contains("certain regions")
                || signal.reason.contains("app unavailable in region")
                || signal.reason.contains("boq-bard-web"));
        let non_success = !(200..300).contains(&status_code);
        let status_supports_block =
            is_block_status(status_code) || matches!(status_code, 502..=504);

        let should_block = signal.confidence >= 88
            || (verdict_consensus >= 2 && signal.confidence >= 70)
            || explicit_geo
            || (non_success && status_supports_block && signal.confidence >= 70);

        if should_block {
            return apply_profile_confidence_adjustment(
                &domain.clone(),
                relax_infra_root_result(with_evidence(
                    build_scan_result(
                        domain,
                        status_from_verdict(signal.verdict),
                        signal.verdict,
                        signal.confidence,
                        Some(status_code),
                        signal.reason.clone(),
                        signal.block_type,
                    ),
                    EvidenceBundle {
                        source: Some("http".to_string()),
                        path,
                        final_url: Some(final_url.to_string()),
                        title,
                        signal: Some(signal.reason),
                    },
                )),
            );
        }
    }

    if !(200..300).contains(&status_code) {
        // 503/502/504 without a known signature are typical ISP block stubs.
        // Raise their confidence to 72 (above the 70 threshold for multi-signal consensus)
        // so they don't fall into the "needs review" bucket.  Other 4xx/5xx stay at 60.
        let (isp_verdict, isp_block_type, isp_confidence) = if matches!(status_code, 502..=504) {
            (
                Verdict::NetworkBlocked,
                Some(signatures::BlockType::Isp),
                72u8,
            )
        } else {
            (Verdict::UnexpectedStatus, None, 60u8)
        };
        let reason = format!("HTTP {status_code} {status_label} without block signature");
        return relax_infra_root_result(with_evidence(
            build_scan_result(
                domain,
                DomainStatus::Blocked,
                isp_verdict,
                isp_confidence,
                Some(status_code),
                reason.clone(),
                isp_block_type,
            ),
            EvidenceBundle {
                source: Some("http".to_string()),
                path,
                final_url: Some(final_url.to_string()),
                title,
                signal: Some(reason),
            },
        ));
    }

    let reason = format!("OK ({status_label})");
    relax_infra_root_result(with_evidence(
        build_scan_result(
            domain,
            DomainStatus::Ok,
            Verdict::Accessible,
            85,
            Some(status_code),
            reason.clone(),
            None,
        ),
        EvidenceBundle {
            source: Some("http".to_string()),
            path,
            final_url: Some(final_url.to_string()),
            title,
            signal: Some(reason),
        },
    ))
}

pub(crate) fn verdict_rank(result: &ScanResult) -> (u8, u8) {
    let rank = match result.verdict {
        Verdict::GeoBlocked => 10,
        Verdict::ApiBlocked => 9,
        Verdict::NetworkBlocked => 8,
        Verdict::WafBlocked => 7,
        Verdict::Captcha => 6,
        Verdict::RateLimited => 5,
        Verdict::UnexpectedStatus => 4,
        Verdict::Accessible => 3,
        Verdict::TlsFailure | Verdict::Unreachable => 2,
    };

    (rank, result.confidence)
}

fn scan_identity(result: &ScanResult) -> String {
    format!(
        "{}/{}",
        super::verdict_label(result.verdict),
        super::routing_decision_label(result.routing_decision)
    )
}

pub(crate) fn same_measurement(a: &ScanResult, b: &ScanResult) -> bool {
    a.status == b.status
        && a.verdict == b.verdict
        && a.routing_decision == b.routing_decision
        && a.http_status == b.http_status
}

pub(crate) fn should_try_retest(result: &ScanResult, scan_policy: ScanPolicy) -> bool {
    if scan_policy.retest_attempts == 0 {
        return false;
    }

    matches!(
        result.verdict,
        Verdict::GeoBlocked
            | Verdict::ApiBlocked
            | Verdict::NetworkBlocked
            | Verdict::UnexpectedStatus
            | Verdict::TlsFailure
            | Verdict::Unreachable
    )
}

pub(crate) fn stabilize_scan_attempts(attempts: Vec<ScanResult>) -> ScanResult {
    if attempts.len() == 1 {
        return attempts.into_iter().next().expect("one attempt");
    }

    let stable = attempts
        .windows(2)
        .all(|window| same_measurement(&window[0], &window[1]));

    if stable {
        let mut chosen = attempts
            .into_iter()
            .max_by_key(verdict_rank)
            .expect("stable attempts are not empty");
        // Boost confidence for stable multiple observations
        chosen.confidence = chosen.confidence.saturating_add(3).min(99);
        // Annotate reason only — evidence.signal stays clean for machine use
        chosen.reason = format!("{} | retest=stable", chosen.reason);
        return chosen;
    }

    // ── Multi-probe consensus ───────────────────────────────────────────────
    // For ambiguous results (confidence 60–85) require a majority vote (≥2/3)
    // before accepting the winning verdict. Without a clear majority → ManualReview.
    let n = attempts.len();
    if n >= 3 {
        // Count verdict+routing pairs
        let mut counts: std::collections::HashMap<(Verdict, RoutingDecision), usize> =
            std::collections::HashMap::new();
        for a in &attempts {
            *counts.entry((a.verdict, a.routing_decision)).or_default() += 1;
        }
        let majority_threshold = (n * 2).div_ceil(3);
        if let Some(((majority_verdict, majority_routing), _)) =
            counts.iter().find(|(_, cnt)| **cnt >= majority_threshold)
        {
            // Use .iter().cloned() so `attempts` is not moved and remains usable below.
            if let Some(mut chosen) = attempts
                .iter()
                .filter(|a| {
                    a.verdict == *majority_verdict && a.routing_decision == *majority_routing
                })
                .max_by_key(|a| verdict_rank(a))
                .cloned()
            {
                chosen.confidence = chosen.confidence.saturating_add(3).min(99);
                chosen.routing_decision = routing_decision_for(chosen.verdict, chosen.confidence);
                chosen.reason = format!("{} | retest=consensus", chosen.reason);
                return chosen;
            }
        }
    }

    // No majority — fall back to ManualReview on the worst observed result
    let mut chosen = attempts
        .iter()
        .filter(|attempt| attempt.verdict != Verdict::Accessible)
        .max_by_key(|attempt| verdict_rank(attempt))
        .cloned()
        .unwrap_or_else(|| attempts[0].clone());
    let attempt_labels = attempts
        .iter()
        .map(scan_identity)
        .collect::<Vec<_>>()
        .join(" -> ");

    chosen.routing_decision = RoutingDecision::ManualReview;
    // Do not lower confidence here — the chosen result's confidence already reflects
    // the worst-case observation. Lowering it further produces misleading numbers.
    chosen.reason = format!("{} | retest=unstable [{attempt_labels}]", chosen.reason);
    // evidence.signal stays clean (no retest annotation) for downstream machine use
    chosen
}

fn find_ascii_case_insensitive(haystack: &str, needle: &str) -> Option<usize> {
    haystack
        .as_bytes()
        .windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle.as_bytes()))
}

pub(crate) fn extract_title(html: &str) -> Option<String> {
    let start = find_ascii_case_insensitive(html, "<title>")?;
    let content_start = start + "<title>".len();
    let rel_end = find_ascii_case_insensitive(&html[content_start..], "</title>")?;
    Some(
        html[content_start..content_start + rel_end]
            .trim()
            .to_string(),
    )
}

#[allow(clippy::too_many_lines)]
pub(crate) fn classify_browser_html(
    domain: &str,
    matcher: &signatures::BlockMatcher,
    html: &str,
) -> Option<ScanResult> {
    let lower = html.to_lowercase();
    let title = extract_title(html).unwrap_or_default();
    let title_lower = title.to_lowercase();

    let direct_geo = [
        "app unavailable in region",
        "not available in your region",
        "not supported in your region",
        "not available in your country",
        "claude isn't available here",
    ];
    if direct_geo
        .iter()
        .any(|needle| lower.contains(needle) || title_lower.contains(needle))
    {
        let reason = if title.is_empty() {
            "Browser DOM: strong geo restriction marker".to_string()
        } else {
            format!("Browser DOM title: {title}")
        };
        return Some(with_evidence(
            build_scan_result(
                domain.to_string(),
                DomainStatus::Blocked,
                Verdict::GeoBlocked,
                99,
                None,
                reason.clone(),
                Some(signatures::BlockType::Geo),
            ),
            EvidenceBundle {
                source: Some("browser_dom".to_string()),
                path: None,
                final_url: None,
                title: (!title.is_empty()).then_some(title.clone()),
                signal: Some(reason),
            },
        ));
    }

    let strong_waf_markers = [
        "challenge-platform",
        "cf-challenge",
        "/cdn-cgi/challenge-platform",
        "cf-mitigated",
        "turnstile",
    ];
    let weak_waf_markers = ["just a moment", "one moment", "один момент", "captcha"];
    let has_strong_waf_marker = strong_waf_markers
        .iter()
        .any(|needle| lower.contains(needle) || title_lower.contains(needle));
    let weak_waf_hits = weak_waf_markers
        .iter()
        .filter(|needle| lower.contains(**needle) || title_lower.contains(**needle))
        .count();
    if has_strong_waf_marker || weak_waf_hits >= 2 {
        let reason = if title.is_empty() {
            "Browser DOM: challenge page".to_string()
        } else {
            format!("Browser DOM title: {title}")
        };
        return Some(with_evidence(
            build_scan_result(
                domain.to_string(),
                DomainStatus::Blocked,
                Verdict::WafBlocked,
                97,
                None,
                reason.clone(),
                Some(signatures::BlockType::Waf),
            ),
            EvidenceBundle {
                source: Some("browser_dom".to_string()),
                path: None,
                final_url: None,
                title: (!title.is_empty()).then_some(title.clone()),
                signal: Some(reason),
            },
        ));
    }
    if let Some((sig, btype)) = matcher.find_body_text(html) {
        if btype == signatures::BlockType::Geo
            && !title.is_empty()
            && !browser_title_supports_geo(&title_lower)
        {
            return None;
        }

        let confidence = match btype {
            signatures::BlockType::Geo => 97,
            signatures::BlockType::Captcha => 96,
            signatures::BlockType::Waf => 94,
            signatures::BlockType::Isp | signatures::BlockType::Api => 92,
            signatures::BlockType::Limit => 88,
            signatures::BlockType::Dead => 80,
            signatures::BlockType::Unknown => 70,
        };

        let reason = format!("Browser DOM: {sig}");
        return Some(with_evidence(
            build_scan_result(
                domain.to_string(),
                status_from_verdict(verdict_from_block_type(btype)),
                verdict_from_block_type(btype),
                confidence,
                None,
                reason.clone(),
                Some(btype),
            ),
            EvidenceBundle {
                source: Some("browser_dom".to_string()),
                path: None,
                final_url: None,
                title: (!title.is_empty()).then_some(title.clone()),
                signal: Some(reason),
            },
        ));
    }

    None
}

fn browser_title_supports_geo(title_lower: &str) -> bool {
    [
        "region",
        "country",
        "unavailable",
        "not available",
        "not supported",
        "restricted",
        "blocked",
        "недоступ",
        "не поддерж",
        "регион",
        "стране",
    ]
    .iter()
    .any(|needle| title_lower.contains(needle))
}

#[cfg(test)]
mod infra_tests {
    use super::{
        analyze_http_observation, apply_profile_confidence_adjustment, classify_browser_html,
        is_consumer_like_domain, is_infra_like_domain, is_non_consumer_platform_domain,
        relax_infra_root_result, stabilize_scan_attempts,
    };
    use crate::scanner::types::build_scan_result;
    use crate::scanner::{DomainStatus, EvidenceBundle, RoutingDecision, Verdict, with_evidence};
    use crate::signatures::BlockMatcher;

    #[test]
    fn detects_known_infra_like_domains() {
        assert!(is_infra_like_domain("googleapis.com"));
        assert!(is_infra_like_domain("cloudfront.net"));
        assert!(!is_infra_like_domain("chatgpt.com"));
    }

    #[test]
    fn distinguishes_consumer_from_non_consumer_domains() {
        assert!(is_non_consumer_platform_domain("azure.com"));
        assert!(is_non_consumer_platform_domain("microsoftonline.com"));
        assert!(is_consumer_like_domain("facebook.com"));
        assert!(is_consumer_like_domain("playstation.net"));
        assert!(!is_consumer_like_domain("cloudfront.net"));
    }

    #[test]
    fn relaxes_infra_root_unexpected_status_into_direct_ok() {
        let matcher = BlockMatcher::new(None).unwrap();
        let result = analyze_http_observation(
            "googleapis.com".to_string(),
            &matcher,
            404,
            "404 Not Found",
            "https://googleapis.com/",
            &[],
            b"<html><title>Error 404 (Not Found)!!1</title></html>",
            false,
        );

        assert_eq!(result.verdict, Verdict::Accessible);
        assert_eq!(result.routing_decision, RoutingDecision::DirectOk);
        assert!(result.reason.contains("infra apex"));
    }

    #[test]
    fn relaxes_infra_root_transport_failure_into_direct_ok() {
        let result = relax_infra_root_result(with_evidence(
            build_scan_result(
                "cloudfront.net".to_string(),
                DomainStatus::Dead,
                Verdict::Unreachable,
                55,
                None,
                "client error (Connect)".to_string(),
                None,
            ),
            EvidenceBundle {
                source: Some("transport".to_string()),
                path: Some("/".to_string()),
                final_url: Some("https://cloudfront.net".to_string()),
                title: None,
                signal: Some("client error (Connect)".to_string()),
            },
        ));

        assert_eq!(result.verdict, Verdict::Accessible);
        assert_eq!(result.routing_decision, RoutingDecision::DirectOk);
        assert!(result.reason.contains("infra apex"));
    }

    #[test]
    fn browser_challenge_requires_strong_or_multiple_markers() {
        let matcher = BlockMatcher::new(None).unwrap();

        let weak_only = classify_browser_html(
            "facebook.com",
            &matcher,
            "<html><title>Facebook</title><body>captcha support docs</body></html>",
        );
        assert!(weak_only.is_none());

        let strong_marker = classify_browser_html(
            "chatgpt.com",
            &matcher,
            "<html><title>One moment</title><script src=\"/cdn-cgi/challenge-platform\"></script></html>",
        )
        .unwrap();
        assert_eq!(strong_marker.verdict, Verdict::WafBlocked);
    }

    #[test]
    fn browser_geo_body_match_requires_title_support() {
        let matcher = BlockMatcher::new(None).unwrap();

        let ambiguous = classify_browser_html(
            "tiktok.com",
            &matcher,
            "<html><title>Интересное — Ищите и смотрите свои любимые видео в TikTok</title><body>не поддерживается в вашем регионе</body></html>",
        );
        assert!(ambiguous.is_none());
    }

    #[test]
    fn detects_new_infra_markers_fastly_edgekey_azure() {
        assert!(is_infra_like_domain("global.prod.fastly.net"));
        assert!(is_infra_like_domain("e12345.x.edgekey.net"));
        assert!(is_infra_like_domain("myapp.azurewebsites.net"));
        assert!(is_infra_like_domain("assets.azureedge.net"));
        assert!(is_infra_like_domain("e4321.g.edgesuite.net"));
        // Consumer domains must not be mistakenly infra-classified
        assert!(!is_infra_like_domain("netflix.com"));
        assert!(!is_infra_like_domain("chatgpt.com"));
    }

    #[test]
    fn profile_confidence_adjustment_boosts_geo_for_browser_verification_services() {
        use crate::scanner::types::{DomainStatus, build_scan_result};

        // OpenAI has browser_verification = true — geo confidence should increase
        let result = build_scan_result(
            "chat.openai.com".to_string(),
            DomainStatus::Blocked,
            Verdict::GeoBlocked,
            88,
            Some(403),
            "HTTP 403".to_string(),
            Some(crate::signatures::BlockType::Geo),
        );
        let adjusted = apply_profile_confidence_adjustment("chat.openai.com", result);
        assert_eq!(
            adjusted.confidence, 93,
            "geo confidence for browser_verification service should be +5"
        );

        // Unknown domain WAF confidence should decrease
        let waf_result = build_scan_result(
            "unknown-random-site.example".to_string(),
            DomainStatus::Blocked,
            Verdict::WafBlocked,
            84,
            Some(403),
            "HTTP 403".to_string(),
            Some(crate::signatures::BlockType::Waf),
        );
        let adjusted_waf =
            apply_profile_confidence_adjustment("unknown-random-site.example", waf_result);
        assert_eq!(
            adjusted_waf.confidence, 74,
            "WAF confidence for unknown domain should be -10"
        );
    }

    #[test]
    fn multi_probe_consensus_accepts_majority_verdict() {
        use crate::scanner::types::{DomainStatus, build_scan_result};

        let make = |v: Verdict, r: RoutingDecision, conf: u8| {
            let mut res = build_scan_result(
                "example.com".to_string(),
                DomainStatus::Blocked,
                v,
                conf,
                Some(403),
                "test".to_string(),
                None,
            );
            res.routing_decision = r;
            res
        };

        // 2 of 3 agree on GeoBlocked/ProxyRequired → consensus
        let attempts = vec![
            make(Verdict::GeoBlocked, RoutingDecision::ProxyRequired, 78),
            make(Verdict::GeoBlocked, RoutingDecision::ProxyRequired, 75),
            make(Verdict::WafBlocked, RoutingDecision::ManualReview, 65),
        ];
        let result = stabilize_scan_attempts(attempts);
        assert_eq!(result.verdict, Verdict::GeoBlocked);
        assert_eq!(result.routing_decision, RoutingDecision::ProxyRequired);
        assert!(
            result.reason.contains("consensus"),
            "should be consensus, got: {}",
            result.reason
        );
        assert_eq!(result.confidence, 81, "78 + 3 consensus boost");
    }

    #[test]
    fn multi_probe_no_majority_falls_to_manual_review() {
        use crate::scanner::types::{DomainStatus, build_scan_result};

        let make = |v: Verdict, conf: u8| {
            build_scan_result(
                "example.com".to_string(),
                DomainStatus::Blocked,
                v,
                conf,
                Some(403),
                "test".to_string(),
                None,
            )
        };

        // All three different — no majority
        let attempts = vec![
            make(Verdict::GeoBlocked, 78),
            make(Verdict::WafBlocked, 72),
            make(Verdict::Captcha, 68),
        ];
        let result = stabilize_scan_attempts(attempts);
        assert_eq!(result.routing_decision, RoutingDecision::ManualReview);
        assert!(
            result.reason.contains("unstable"),
            "should be unstable, got: {}",
            result.reason
        );
    }
}
