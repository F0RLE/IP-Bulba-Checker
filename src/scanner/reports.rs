use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

const TXT_DIR: &str = "txt";

use super::types::{
    ComparisonDecision, ComparisonResult, ProbeStatus, RoutingDecision, ScanResult,
    ServiceGeoSummary, Verdict, evidence_summary, network_summary, routing_decision_label,
    service_context_label, service_name_label, verdict_label,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ManualReviewBucket {
    Challenge,
    RateLimited,
    ControlPathAmbiguity,
    TransportFailure,
    WeakServiceCoverage,
    Other,
}

impl ManualReviewBucket {
    fn label(self) -> &'static str {
        match self {
            Self::Challenge => "captcha_or_challenge",
            Self::RateLimited => "rate_limited",
            Self::ControlPathAmbiguity => "control_path_ambiguity",
            Self::TransportFailure => "transport_failure",
            Self::WeakServiceCoverage => "weak_service_coverage",
            Self::Other => "other",
        }
    }

    fn operator_guidance(self) -> &'static str {
        match self {
            Self::Challenge => {
                "challenge-heavy domains should stay in review until a later refresh or stronger dual-vantage confirmation"
            }
            Self::RateLimited => {
                "rate-limited domains should be retried later and should not be treated as publishable proxy-required results yet"
            }
            Self::ControlPathAmbiguity => {
                "control-path ambiguity means the comparison side is too weak to promote safely; keep these domains out of strict exports"
            }
            Self::TransportFailure => {
                "transport failures are technical noise until later refreshes confirm a stable routing outcome"
            }
            Self::WeakServiceCoverage => {
                "weak service coverage means the service bundle still lacks enough critical-role evidence for publication-grade decisions"
            }
            Self::Other => {
                "other manual-review cases should remain in review until a later cycle produces stronger evidence"
            }
        }
    }
}

fn looks_like_challenge(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "captcha",
        "challenge",
        "turnstile",
        "cf-mitigated",
        "just a moment",
        "one moment",
        "cdn-cgi/challenge-platform",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn is_transport_like_manual_review(result: &ScanResult) -> bool {
    matches!(
        result.verdict,
        Verdict::NetworkBlocked
            | Verdict::TlsFailure
            | Verdict::Unreachable
            | Verdict::UnexpectedStatus
    ) && (result.network_evidence.dns.status == ProbeStatus::Failed
        || result.network_evidence.tcp_443.status == ProbeStatus::Failed
        || result.network_evidence.tls_443.status == ProbeStatus::Failed
        || result
            .evidence
            .source
            .as_deref()
            .is_some_and(|src| matches!(src, "transport" | "scanner"))
        || result.reason.to_ascii_lowercase().contains("worker error"))
}

fn control_note_is_ambiguous(note: &str) -> bool {
    note.contains("control direct signal is weak")
        || note.contains("control path is too weak")
        || note.contains("control direct evidence is too weak")
}

fn classify_manual_review_bucket(
    result: &ScanResult,
    comparison: Option<&ComparisonResult>,
    weak_service_domains: &BTreeSet<String>,
) -> ManualReviewBucket {
    if result.verdict == Verdict::RateLimited {
        return ManualReviewBucket::RateLimited;
    }

    if matches!(result.verdict, Verdict::Captcha | Verdict::WafBlocked)
        || looks_like_challenge(&result.reason)
        || result
            .evidence
            .signal
            .as_deref()
            .is_some_and(looks_like_challenge)
        || result
            .evidence
            .title
            .as_deref()
            .is_some_and(looks_like_challenge)
    {
        return ManualReviewBucket::Challenge;
    }

    if let Some(comparison) = comparison
        && comparison.decision == ComparisonDecision::NeedsReview
        && (comparison
            .network_notes
            .iter()
            .any(|note| control_note_is_ambiguous(note))
            || comparison
                .reason
                .contains("control direct evidence is too weak")
            || comparison
                .reason
                .contains("control is too weak to confirm a shared blocked outcome"))
    {
        return ManualReviewBucket::ControlPathAmbiguity;
    }

    if weak_service_domains.contains(&result.domain) {
        return ManualReviewBucket::WeakServiceCoverage;
    }

    if is_transport_like_manual_review(result) {
        return ManualReviewBucket::TransportFailure;
    }

    ManualReviewBucket::Other
}

fn weak_service_domains(service_geo: Option<&[ServiceGeoSummary]>) -> BTreeSet<String> {
    let mut domains = BTreeSet::new();
    let Some(service_geo) = service_geo else {
        return domains;
    };

    for summary in service_geo {
        if summary.missing_critical_roles.is_empty() {
            continue;
        }
        domains.extend(summary.review_assisted_hosts.iter().cloned());
        domains.extend(summary.candidate_hosts.iter().cloned());
        domains.extend(summary.confirmed_hosts.iter().cloned());
    }

    domains
}

fn manual_review_hotspots<'a>(
    results: &'a [ScanResult],
    comparisons: Option<&'a [ComparisonResult]>,
    service_geo: Option<&'a [ServiceGeoSummary]>,
) -> BTreeMap<ManualReviewBucket, Vec<&'a ScanResult>> {
    let weak_service_domains = weak_service_domains(service_geo);
    let comparison_by_domain = comparisons.map(|items| {
        items
            .iter()
            .map(|item| (item.domain.as_str(), item))
            .collect::<BTreeMap<_, _>>()
    });

    let mut buckets = BTreeMap::<ManualReviewBucket, Vec<&ScanResult>>::new();
    for result in results
        .iter()
        .filter(|result| result.routing_decision == RoutingDecision::ManualReview)
    {
        let comparison = comparison_by_domain
            .as_ref()
            .and_then(|map| map.get(result.domain.as_str()).copied());
        let bucket = classify_manual_review_bucket(result, comparison, &weak_service_domains);
        buckets.entry(bucket).or_default().push(result);
    }

    for items in buckets.values_mut() {
        items.sort_by(|a, b| {
            b.confidence
                .cmp(&a.confidence)
                .then_with(|| a.domain.cmp(&b.domain))
        });
    }

    buckets
}

#[allow(clippy::too_many_lines)]
pub(crate) fn write_human_report(results: &[ScanResult], output_path: &Path) -> anyhow::Result<()> {
    let mut counts = BTreeMap::<&str, usize>::new();
    let mut routing_counts = BTreeMap::<&str, usize>::new();
    let mut service_counts = BTreeMap::<String, usize>::new();
    let mut network_counts = BTreeMap::<&str, usize>::new();
    for result in results {
        *counts.entry(verdict_label(result.verdict)).or_default() += 1;
        *routing_counts
            .entry(routing_decision_label(result.routing_decision))
            .or_default() += 1;
        *service_counts
            .entry(service_name_label(result))
            .or_default() += 1;
        if result.network_evidence.dns.status == ProbeStatus::Failed {
            *network_counts.entry("dns_failed").or_default() += 1;
        }
        if result.reason.contains("while DoH resolved") {
            *network_counts
                .entry("dns_locally_blocked_vs_doh")
                .or_default() += 1;
        }
        if result.reason.contains("system DNS differs from DoH:") {
            *network_counts.entry("dns_mismatch_vs_doh").or_default() += 1;
        }
        if result.network_evidence.tcp_443.status == ProbeStatus::Failed {
            *network_counts.entry("tcp_443_failed").or_default() += 1;
        }
        if result.network_evidence.tls_443.status == ProbeStatus::Failed {
            *network_counts.entry("tls_443_failed").or_default() += 1;
        }
        if result.network_evidence.tcp_80.status == ProbeStatus::Failed {
            *network_counts.entry("tcp_80_failed").or_default() += 1;
        }
    }

    let mut report = String::new();
    writeln!(&mut report, "Bulbascan report")?;
    writeln!(&mut report, "======================")?;
    writeln!(&mut report)?;
    writeln!(&mut report, "Routing summary")?;
    for (decision, count) in routing_counts {
        writeln!(&mut report, "- {decision}: {count}")?;
    }
    writeln!(&mut report)?;
    writeln!(&mut report, "Verdict summary")?;
    for (verdict, count) in counts {
        writeln!(&mut report, "- {verdict}: {count}")?;
    }
    writeln!(&mut report)?;
    writeln!(&mut report, "Service summary")?;
    for (service, count) in service_counts {
        writeln!(&mut report, "- {service}: {count}")?;
    }
    writeln!(&mut report)?;
    writeln!(&mut report, "Network summary")?;
    if network_counts.is_empty() {
        writeln!(&mut report, "- no network probe failures")?;
    } else {
        for (label, count) in network_counts {
            writeln!(&mut report, "- {label}: {count}")?;
        }
    }

    let manual_review_buckets = manual_review_hotspots(results, None, None);
    writeln!(&mut report)?;
    writeln!(&mut report, "Manual Review hotspots")?;
    if manual_review_buckets.is_empty() {
        writeln!(&mut report, "- none")?;
    } else {
        for (bucket, items) in &manual_review_buckets {
            writeln!(&mut report, "- {}: {}", bucket.label(), items.len())?;
        }
    }

    let routing_sections = [
        ("Proxy Required", RoutingDecision::ProxyRequired),
        ("Manual Review", RoutingDecision::ManualReview),
        ("Direct OK", RoutingDecision::DirectOk),
    ];

    for (title, decision) in routing_sections {
        writeln!(&mut report)?;
        writeln!(&mut report, "{title}")?;
        writeln!(&mut report, "{}", "-".repeat(title.len()))?;

        let mut section_items = results
            .iter()
            .filter(|result| result.routing_decision == decision)
            .collect::<Vec<_>>();
        section_items.sort_by(|a, b| {
            b.confidence
                .cmp(&a.confidence)
                .then_with(|| a.domain.cmp(&b.domain))
        });

        if section_items.is_empty() {
            writeln!(&mut report, "none")?;
            continue;
        }

        for item in section_items {
            writeln!(
                &mut report,
                "- {} [{}%] {} ({}, {}, {}, evidence={})",
                item.domain,
                item.confidence,
                item.reason,
                verdict_label(item.verdict),
                service_context_label(item),
                network_summary(&item.network_evidence),
                evidence_summary(&item.evidence)
            )?;
        }
    }

    let sections = [
        ("Geo Blocked", Verdict::GeoBlocked),
        ("WAF Blocked", Verdict::WafBlocked),
        ("Rate Limited", Verdict::RateLimited),
        ("Unexpected Status", Verdict::UnexpectedStatus),
        ("Unreachable", Verdict::Unreachable),
        ("Accessible", Verdict::Accessible),
    ];

    for (title, verdict) in sections {
        writeln!(&mut report)?;
        writeln!(&mut report, "{title}")?;
        writeln!(&mut report, "{}", "-".repeat(title.len()))?;

        let mut section_items = results
            .iter()
            .filter(|result| result.verdict == verdict)
            .collect::<Vec<_>>();
        section_items.sort_by(|a, b| {
            b.confidence
                .cmp(&a.confidence)
                .then_with(|| a.domain.cmp(&b.domain))
        });

        if section_items.is_empty() {
            writeln!(&mut report, "none")?;
            continue;
        }

        for item in section_items {
            writeln!(
                &mut report,
                "- {} [{}%] {} ({}, {}, evidence={})",
                item.domain,
                item.confidence,
                item.reason,
                service_context_label(item),
                network_summary(&item.network_evidence),
                evidence_summary(&item.evidence)
            )?;
        }
    }

    // ── v1.3: Confidence histogram ──────────────────────────────────────────
    let bands = [
        ("90-100", 90u8, 100u8),
        ("80-89 ", 80, 89),
        ("70-79 ", 70, 79),
        ("<70   ", 0, 69),
    ];
    writeln!(&mut report)?;
    writeln!(&mut report, "Confidence distribution")?;
    writeln!(&mut report, "-----------------------")?;
    let max_bar = 30usize;
    let total = results.len().max(1);
    for (label, lo, hi) in bands {
        let count = results
            .iter()
            .filter(|r| r.confidence >= lo && r.confidence <= hi)
            .count();
        let bar_len = (count * max_bar) / total;
        let bar = "█".repeat(bar_len);
        writeln!(&mut report, "{label} {bar:<30} [{count}]")?;
    }

    // ── v1.3: Non-technical per-service summary ─────────────────────────────
    {
        let mut svc_map: BTreeMap<String, (usize, usize, usize)> = BTreeMap::new();
        for r in results {
            let svc = service_name_label(r);
            let entry = svc_map.entry(svc).or_default();
            match r.routing_decision {
                RoutingDecision::ProxyRequired => entry.0 += 1,
                RoutingDecision::DirectOk => entry.1 += 1,
                RoutingDecision::ManualReview => entry.2 += 1,
            }
        }
        if !svc_map.is_empty() {
            writeln!(&mut report)?;
            writeln!(&mut report, "Service summary (plain)")?;
            writeln!(&mut report, "-----------------------")?;
            for (svc, (proxy, direct, review)) in &svc_map {
                let svc_label = if *proxy > 0 && *direct == 0 && *review == 0 {
                    format!("BLOCKED ({}%)", proxy * 100 / (*proxy + direct + review))
                } else if *direct > 0 && *proxy == 0 && *review == 0 {
                    "OK — accessible directly".to_string()
                } else if *proxy == 0 && *direct == 0 {
                    "INCONCLUSIVE".to_string()
                } else {
                    format!("PARTIAL — {proxy} blocked / {direct} direct / {review} review")
                };
                writeln!(&mut report, "{svc:<30} {svc_label}")?;
            }
        }
    }

    std::fs::write(output_path, report)?;
    Ok(())
}

pub(crate) fn write_manual_review_hotspot_report(
    results: &[ScanResult],
    comparisons: Option<&[ComparisonResult]>,
    service_geo: Option<&[ServiceGeoSummary]>,
    output_path: &Path,
) -> anyhow::Result<()> {
    let buckets = manual_review_hotspots(results, comparisons, service_geo);
    let total = results
        .iter()
        .filter(|result| result.routing_decision == RoutingDecision::ManualReview)
        .count();

    let mut report = String::new();
    writeln!(&mut report, "Bulbascan manual review hotspot report")?;
    writeln!(&mut report, "=====================================")?;
    writeln!(&mut report)?;
    writeln!(&mut report, "Summary")?;
    writeln!(&mut report, "- total_manual_review: {total}")?;

    if buckets.is_empty() {
        writeln!(&mut report, "- no manual review domains")?;
        std::fs::write(output_path, report)?;
        return Ok(());
    }

    for (bucket, items) in &buckets {
        writeln!(&mut report, "- {}: {}", bucket.label(), items.len())?;
    }

    for (bucket, items) in buckets {
        writeln!(&mut report)?;
        writeln!(&mut report, "{}", bucket.label())?;
        writeln!(&mut report, "{}", "-".repeat(bucket.label().len()))?;
        writeln!(&mut report, "guidance: {}", bucket.operator_guidance())?;
        for item in items.iter().take(25) {
            writeln!(
                &mut report,
                "- {} [{}%] {} ({}, {}, evidence={})",
                item.domain,
                item.confidence,
                item.reason,
                verdict_label(item.verdict),
                service_context_label(item),
                evidence_summary(&item.evidence)
            )?;
        }
        if items.len() > 25 {
            writeln!(&mut report, "... {} more", items.len() - 25)?;
        }
    }

    std::fs::write(output_path, report)?;
    Ok(())
}

pub(crate) fn write_service_report(
    results: &[ScanResult],
    output_path: &Path,
) -> anyhow::Result<()> {
    let mut grouped = BTreeMap::<String, Vec<&ScanResult>>::new();
    for result in results {
        grouped
            .entry(service_name_label(result))
            .or_default()
            .push(result);
    }

    let mut report = String::new();
    writeln!(&mut report, "Bulbascan service report")?;
    writeln!(&mut report, "=============================")?;

    for (service, mut items) in grouped {
        items.sort_by(|a, b| a.domain.cmp(&b.domain));

        let proxy_required = items
            .iter()
            .filter(|item| item.routing_decision == RoutingDecision::ProxyRequired)
            .count();
        let direct_ok = items
            .iter()
            .filter(|item| item.routing_decision == RoutingDecision::DirectOk)
            .count();
        let manual_review = items
            .iter()
            .filter(|item| item.routing_decision == RoutingDecision::ManualReview)
            .count();

        writeln!(&mut report)?;
        writeln!(&mut report, "{service}")?;
        writeln!(&mut report, "{}", "-".repeat(service.len()))?;
        writeln!(
            &mut report,
            "proxy_required={proxy_required} direct_ok={direct_ok} manual_review={manual_review}"
        )?;

        for item in items {
            let role = item.service_role.as_deref().unwrap_or("unknown");
            writeln!(
                &mut report,
                "- {} role={} route={} verdict={} confidence={}% network={} evidence={} {}",
                item.domain,
                role,
                routing_decision_label(item.routing_decision),
                verdict_label(item.verdict),
                item.confidence,
                network_summary(&item.network_evidence),
                evidence_summary(&item.evidence),
                item.reason
            )?;
        }
    }

    std::fs::write(output_path, report)?;
    Ok(())
}

pub(crate) fn write_routing_lists(results: &[ScanResult], output_dir: &Path) -> anyhow::Result<()> {
    let mut proxy_required = results
        .iter()
        .filter(|result| result.routing_decision == RoutingDecision::ProxyRequired)
        .map(|result| result.domain.clone())
        .collect::<Vec<_>>();
    proxy_required.sort();
    proxy_required.dedup();

    let mut direct_ok = results
        .iter()
        .filter(|result| result.routing_decision == RoutingDecision::DirectOk)
        .map(|result| result.domain.clone())
        .collect::<Vec<_>>();
    direct_ok.sort();
    direct_ok.dedup();

    let mut manual_review = results
        .iter()
        .filter(|result| result.routing_decision == RoutingDecision::ManualReview)
        .map(|result| result.domain.clone())
        .collect::<Vec<_>>();
    manual_review.sort();
    manual_review.dedup();

    let txt_dir = output_dir.join(TXT_DIR);
    std::fs::create_dir_all(&txt_dir)?;

    let write_list = |path: &Path, items: &[String]| -> anyhow::Result<()> {
        let mut content = items.join("\n");
        if !content.is_empty() {
            content.push('\n');
        }
        std::fs::write(path, content)?;
        Ok(())
    };

    write_list(&txt_dir.join("proxy.txt"), &proxy_required)?;
    write_list(&txt_dir.join("direct.txt"), &direct_ok)?;
    write_list(&txt_dir.join("review.txt"), &manual_review)?;
    Ok(())
}
