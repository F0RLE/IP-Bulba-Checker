use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use std::net::IpAddr;

use super::types::{
    ComparisonDecision, ComparisonResult, ControlProxyHealth, EvidenceBundle, NetworkEvidence,
    ProbeStatus, RoutingDecision, ScanResult, ServiceGeoDecision, ServiceGeoSummary, Verdict,
    comparison_decision_label, control_proxy_failure_label, evidence_summary, network_summary,
    routing_decision_label, service_geo_decision_label, verdict_label,
};
use crate::service_profiles;

fn ensure_parent_dir(output_path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = output_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn dns_failure_kind(detail: Option<&str>) -> Option<&str> {
    let detail = detail?;
    detail
        .strip_prefix("kind=")
        .and_then(|rest| rest.split_whitespace().next())
}

fn resolver_health_note(detail: Option<&str>) -> Option<&str> {
    let detail = detail?;
    [
        "resolver_control_ok",
        "resolver_control_empty",
        "resolver_control_timeout",
        "resolver_control_servfail",
        "resolver_control_nxdomain",
        "resolver_control_nodata",
        "resolver_control_refused",
        "resolver_control_failed",
        "resolver_control_unknown",
    ]
    .into_iter()
    .find(|marker| detail.contains(marker))
}

const MIN_CONFIDENT_CONTROL_DIRECT: u8 = 80;
const MIN_CONFIDENT_CONTROL_BLOCKED: u8 = 80;
const MIN_CONFIDENT_LOCAL_BLOCK_SIGNAL: u8 = 75;

fn is_transport_noise_result(result: &ScanResult) -> bool {
    let both_dns_paths_failed = matches!(result.network_evidence.dns.status, ProbeStatus::Failed)
        && matches!(result.network_evidence.path_dns.status, ProbeStatus::Failed);
    let has_path_level_reachability = result.network_evidence.path_dns.status == ProbeStatus::Ok
        || result.network_evidence.dns.status == ProbeStatus::Ok;
    let has_transport_break = result.network_evidence.tcp_443.status != ProbeStatus::Ok
        || result.network_evidence.tls_443.status != ProbeStatus::Ok;
    let structured_transport_block = matches!(
        result.verdict,
        Verdict::NetworkBlocked | Verdict::TlsFailure | Verdict::Unreachable
    ) && has_path_level_reachability
        && has_transport_break;

    result
        .evidence
        .signal
        .as_deref()
        .is_some_and(|signal| signal.contains("worker error"))
        || result
            .evidence
            .source
            .as_deref()
            .is_some_and(|source| matches!(source, "scanner" | "transport"))
        || ((!structured_transport_block)
            && matches!(result.verdict, Verdict::Unreachable | Verdict::TlsFailure))
        || both_dns_paths_failed
}

fn classify_needs_review_reason(local: &ScanResult, control: &ScanResult) -> String {
    let local_transport_noise = is_transport_noise_result(local);
    let control_transport_noise = is_transport_noise_result(control);
    let control_is_weak = control_note(control).is_some();

    if local_transport_noise && control_transport_noise {
        return "transport ambiguity: both local and control paths are too noisy to classify confidently"
            .to_string();
    }

    if local_transport_noise {
        return "transport ambiguity: local path is dominated by transient or technical failure"
            .to_string();
    }

    if control_transport_noise || control_is_weak {
        return "control-path ambiguity: control side is too weak to separate local blocking from broader failure"
            .to_string();
    }

    format!(
        "local route={} control route={}",
        routing_decision_label(local.routing_decision),
        routing_decision_label(control.routing_decision)
    )
}

fn local_supports_proxy_promotion(local: &ScanResult) -> bool {
    if is_transport_noise_result(local) {
        return false;
    }

    match local.verdict {
        Verdict::GeoBlocked
        | Verdict::WafBlocked
        | Verdict::Captcha
        | Verdict::RateLimited
        | Verdict::ApiBlocked => true,
        Verdict::NetworkBlocked | Verdict::TlsFailure | Verdict::Unreachable => {
            local.confidence >= MIN_CONFIDENT_LOCAL_BLOCK_SIGNAL
                && (local.network_evidence.path_dns.status == ProbeStatus::Ok
                    || local.network_evidence.dns.status == ProbeStatus::Ok)
                && (local.network_evidence.tcp_443.status != ProbeStatus::Ok
                    || local.network_evidence.tls_443.status != ProbeStatus::Ok)
        }
        Verdict::UnexpectedStatus => {
            local.confidence >= MIN_CONFIDENT_LOCAL_BLOCK_SIGNAL
                && local.http_status.is_some_and(|status| status >= 400)
        }
        Verdict::Accessible => false,
    }
}

fn local_supports_consistent_blocked(local: &ScanResult) -> bool {
    local.routing_decision != RoutingDecision::DirectOk
        && local_supports_proxy_promotion(local)
        && local.confidence >= MIN_CONFIDENT_CONTROL_BLOCKED
}

fn control_supports_direct_promotion(control: &ScanResult) -> bool {
    control.routing_decision == RoutingDecision::DirectOk
        && control.verdict == Verdict::Accessible
        && control.confidence >= MIN_CONFIDENT_CONTROL_DIRECT
}

fn control_non_direct_is_weak(control: &ScanResult) -> bool {
    if control.routing_decision == RoutingDecision::DirectOk {
        return false;
    }

    if control.confidence < MIN_CONFIDENT_CONTROL_BLOCKED {
        return true;
    }

    if matches!(
        control.verdict,
        Verdict::WafBlocked | Verdict::Captcha | Verdict::RateLimited | Verdict::UnexpectedStatus
    ) {
        return true;
    }

    matches!(
        control.verdict,
        Verdict::GeoBlocked | Verdict::NetworkBlocked | Verdict::TlsFailure | Verdict::Unreachable
    ) && control.network_evidence.path_dns.status != ProbeStatus::Ok
        && control.network_evidence.tcp_443.status != ProbeStatus::Ok
        && control.network_evidence.tls_443.status != ProbeStatus::Ok
}

fn control_note(control: &ScanResult) -> Option<String> {
    if control.routing_decision == RoutingDecision::DirectOk
        && !control_supports_direct_promotion(control)
    {
        return Some(format!(
            "control direct signal is weak: verdict={} confidence={}",
            verdict_label(control.verdict),
            control.confidence
        ));
    }

    if control_non_direct_is_weak(control) {
        return Some(format!(
            "control path is too weak for a blocked-side comparison: verdict={} confidence={}",
            verdict_label(control.verdict),
            control.confidence
        ));
    }

    None
}

#[allow(clippy::too_many_lines)]
pub(crate) fn compare_result_pair(local: &ScanResult, control: &ScanResult) -> ComparisonResult {
    let control_supports_direct = control_supports_direct_promotion(control);
    let control_blocked_is_weak = control_non_direct_is_weak(control);
    let local_supports_promotion = local_supports_proxy_promotion(local);

    let mut decision = if local.routing_decision == RoutingDecision::ProxyRequired
        && control_supports_direct
        && local_supports_promotion
    {
        ComparisonDecision::ConfirmedProxyRequired
    } else if matches!(
        local.verdict,
        Verdict::GeoBlocked
            | Verdict::NetworkBlocked
            | Verdict::TlsFailure
            | Verdict::Unreachable
            | Verdict::UnexpectedStatus
            | Verdict::WafBlocked
            | Verdict::Captcha
    ) && control_supports_direct
        && local_supports_promotion
    {
        // "Smart WAF/Captcha Promotion": If local is WAF/Captcha but control proxy is DirectOk,
        // it means the site is selectively blocking the local IP/geo, not down globally.
        ComparisonDecision::CandidateProxyRequired
    } else if local.routing_decision == RoutingDecision::DirectOk
        && control.routing_decision == RoutingDecision::DirectOk
    {
        ComparisonDecision::ConsistentDirect
    } else if local_supports_consistent_blocked(local)
        && control.routing_decision != RoutingDecision::DirectOk
        && !control_blocked_is_weak
    {
        ComparisonDecision::ConsistentBlocked
    } else {
        ComparisonDecision::NeedsReview
    };

    let mut network_notes =
        compare_network_evidence(&local.network_evidence, &control.network_evidence);
    if let Some(note) = control_note(control) {
        network_notes.push(note);
    }
    if control_supports_direct
        && !local_supports_promotion
        && local.routing_decision != RoutingDecision::DirectOk
    {
        network_notes.push(format!(
            "local signal is too weak for direct-vs-proxy promotion: verdict={} confidence={}",
            verdict_label(local.verdict),
            local.confidence
        ));
    }
    if control.routing_decision != RoutingDecision::DirectOk
        && !control_blocked_is_weak
        && !local_supports_consistent_blocked(local)
        && local.routing_decision != RoutingDecision::DirectOk
    {
        network_notes.push(format!(
            "local side is too weak to confirm a shared blocked outcome: verdict={} confidence={}",
            verdict_label(local.verdict),
            local.confidence
        ));
    }

    let mut local_verdict_confidence = local.confidence;
    let mut local_routing_decision = local.routing_decision;

    if decision == ComparisonDecision::CandidateProxyRequired {
        let is_strong_network_block = (local.network_evidence.tcp_443.status != ProbeStatus::Ok
            || local.network_evidence.tls_443.status != ProbeStatus::Ok)
            && (local.network_evidence.dns.status != ProbeStatus::Ok
                || local.network_evidence.path_dns.status != ProbeStatus::Ok)
            && control.network_evidence.path_dns.status == ProbeStatus::Ok;

        if is_strong_network_block {
            local_verdict_confidence = local_verdict_confidence.max(92);
            local_routing_decision = RoutingDecision::ProxyRequired;
            // Upgrade the decision since we escalated the routing requirement
            decision = ComparisonDecision::ConfirmedProxyRequired;
        }
    }
    let reason = match decision {
        ComparisonDecision::ConfirmedProxyRequired => format!(
            "local {} but control is direct_ok",
            verdict_label(local.verdict)
        ),
        ComparisonDecision::CandidateProxyRequired => format!(
            "local {} differs from control direct_ok",
            verdict_label(local.verdict)
        ),
        ComparisonDecision::ConsistentDirect => "both paths look direct_ok".to_string(),
        ComparisonDecision::ConsistentBlocked => format!(
            "local {} and control {} are both non-direct",
            verdict_label(local.verdict),
            verdict_label(control.verdict)
        ),
        ComparisonDecision::NeedsReview => classify_needs_review_reason(local, control),
    };
    let reason = if network_notes.is_empty() {
        reason
    } else {
        format!("{reason}; {}", network_notes.join("; "))
    };

    ComparisonResult {
        domain: local.domain.clone(),
        service: local.service.clone(),
        service_role: local.service_role.clone(),
        local_verdict: local.verdict,
        local_routing_decision,
        local_confidence: local_verdict_confidence,
        local_evidence: local.evidence.clone(),
        control_verdict: control.verdict,
        control_routing_decision: control.routing_decision,
        control_evidence: control.evidence.clone(),
        decision,
        local_network_evidence: local.network_evidence.clone(),
        control_network_evidence: control.network_evidence.clone(),
        network_notes,
        reason,
    }
}

fn compare_network_evidence(local: &NetworkEvidence, control: &NetworkEvidence) -> Vec<String> {
    let mut notes = Vec::new();

    if local.dns.status != ProbeStatus::Ok && control.path_dns.status == ProbeStatus::Ok {
        let dns_kind = dns_failure_kind(local.dns.detail.as_deref()).unwrap_or("failed");
        let resolver_health = resolver_health_note(local.dns.detail.as_deref());
        match (dns_kind, resolver_health) {
            ("nxdomain" | "servfail" | "timeout" | "refused", Some("resolver_control_ok")) => {
                notes.push(format!(
                    "local DNS manipulation suspected: system resolver returned {dns_kind} while control path DNS resolved"
                ));
            }
            (
                _,
                Some(
                    "resolver_control_timeout"
                    | "resolver_control_servfail"
                    | "resolver_control_failed",
                ),
            ) => {
                notes.push(format!(
                    "local resolver appears unhealthy: target query failed with {dns_kind} and innocuous control query also failed"
                ));
            }
            _ => {
                notes.push(format!(
                    "local system DNS failed ({dns_kind}) while control path DNS resolved"
                ));
            }
        }
    }
    if local.tcp_443.status != ProbeStatus::Ok && control.path_dns.status == ProbeStatus::Ok {
        notes.push("local tcp/443 failed while control path DNS still resolved".to_string());
    }
    if local.tls_443.status != ProbeStatus::Ok && control.path_dns.status == ProbeStatus::Ok {
        notes.push("local tls/443 failed while control path DNS still resolved".to_string());
    }

    if local.path_dns.status == ProbeStatus::Ok && control.path_dns.status == ProbeStatus::Ok {
        let local_path_dns = parse_ip_detail_set(local.path_dns.detail.as_deref());
        let control_path_dns = parse_ip_detail_set(control.path_dns.detail.as_deref());
        if !local_path_dns.is_empty() && !control_path_dns.is_empty() {
            let overlap = local_path_dns
                .intersection(&control_path_dns)
                .copied()
                .collect::<Vec<_>>();
            let local_preview = local.path_dns.detail.as_deref().unwrap_or_default();
            let control_preview = control.path_dns.detail.as_deref().unwrap_or_default();
            if overlap.is_empty() {
                if local.tcp_443.status != ProbeStatus::Ok
                    || local.tls_443.status != ProbeStatus::Ok
                {
                    notes.push(format!(
                        "DNS mismatch confirmed by failed direct tcp/tls: local={local_preview} control={control_preview}"
                    ));
                } else {
                    notes.push(format!(
                        "unconfirmed DNS mismatch: local={local_preview} control={control_preview}"
                    ));
                }
            } else if local_path_dns != control_path_dns {
                notes.push(format!(
                    "path DNS partially overlaps: local={local_preview} control={control_preview}"
                ));
            }
        }
    }

    notes
}

fn parse_ip_detail_set(detail: Option<&str>) -> BTreeSet<IpAddr> {
    detail
        .unwrap_or_default()
        .split(',')
        .filter_map(|part| part.trim().parse::<IpAddr>().ok())
        .collect()
}

pub fn compare_with_control(
    local_results: &[ScanResult],
    control_results: &[ScanResult],
) -> Vec<ComparisonResult> {
    let control_by_domain = control_results
        .iter()
        .map(|result| (result.domain.as_str(), result))
        .collect::<std::collections::HashMap<_, _>>();

    let mut comparisons = local_results
        .iter()
        .filter_map(|local| {
            control_by_domain
                .get(local.domain.as_str())
                .map(|control| compare_result_pair(local, control))
        })
        .collect::<Vec<_>>();

    comparisons.sort_by(|a, b| a.domain.cmp(&b.domain));
    comparisons
}

#[allow(clippy::too_many_lines)]
pub fn write_control_comparison_report(
    comparisons: &[ComparisonResult],
    output_path: &Path,
) -> anyhow::Result<()> {
    ensure_parent_dir(output_path)?;
    let mut counts = BTreeMap::<&str, usize>::new();
    let mut dns_note_counts = BTreeMap::<&str, usize>::new();
    let mut needs_review_counts = BTreeMap::<&str, usize>::new();
    for comparison in comparisons {
        *counts
            .entry(comparison_decision_label(comparison.decision))
            .or_default() += 1;
        if comparison.decision == ComparisonDecision::NeedsReview {
            let bucket = if comparison.reason.starts_with("control-path ambiguity:") {
                "control_path_ambiguity"
            } else if comparison.reason.starts_with("transport ambiguity:") {
                "transport_ambiguity"
            } else {
                "mixed_or_other"
            };
            *needs_review_counts.entry(bucket).or_default() += 1;
        }
        for note in &comparison.network_notes {
            let bucket = if note.contains("local DNS manipulation suspected") {
                "dns_manipulation_suspected"
            } else if note.contains("local resolver appears unhealthy") {
                "resolver_unhealthy"
            } else if note.contains("DNS mismatch confirmed by failed direct tcp/tls") {
                "dns_mismatch_confirmed"
            } else if note.contains("unconfirmed DNS mismatch") {
                "dns_mismatch_unconfirmed"
            } else {
                continue;
            };
            *dns_note_counts.entry(bucket).or_default() += 1;
        }
    }

    let mut report = String::new();
    writeln!(&mut report, "Bulbascan control comparison report")?;
    writeln!(&mut report, "=========================================")?;
    writeln!(&mut report)?;
    writeln!(&mut report, "Summary")?;
    for (decision, count) in counts {
        writeln!(&mut report, "- {decision}: {count}")?;
    }
    if !needs_review_counts.is_empty() {
        writeln!(&mut report)?;
        writeln!(&mut report, "Needs review breakdown")?;
        for (label, count) in needs_review_counts {
            writeln!(&mut report, "- {label}: {count}")?;
        }
    }
    if !dns_note_counts.is_empty() {
        writeln!(&mut report)?;
        writeln!(&mut report, "DNS signals")?;
        for (label, count) in dns_note_counts {
            writeln!(&mut report, "- {label}: {count}")?;
        }
    }

    let sections = [
        (
            "Confirmed Proxy Required",
            ComparisonDecision::ConfirmedProxyRequired,
        ),
        (
            "Candidate Proxy Required",
            ComparisonDecision::CandidateProxyRequired,
        ),
        ("Needs Review", ComparisonDecision::NeedsReview),
        ("Consistent Blocked", ComparisonDecision::ConsistentBlocked),
        ("Consistent Direct", ComparisonDecision::ConsistentDirect),
    ];

    for (title, decision) in sections {
        writeln!(&mut report)?;
        writeln!(&mut report, "{title}")?;
        writeln!(&mut report, "{}", "-".repeat(title.len()))?;

        let items = comparisons
            .iter()
            .filter(|comparison| comparison.decision == decision)
            .collect::<Vec<_>>();

        if items.is_empty() {
            writeln!(&mut report, "none")?;
            continue;
        }

        for item in items {
            let service = match (&item.service, &item.service_role) {
                (Some(service), Some(role)) => format!("{service}/{role}"),
                (Some(service), None) => service.clone(),
                _ => "unmapped".to_string(),
            };
            writeln!(
                &mut report,
                "- {} [{}] local={}/{} ({}) control={}/{} ({}) {}",
                item.domain,
                service,
                verdict_label(item.local_verdict),
                routing_decision_label(item.local_routing_decision),
                network_summary(&item.local_network_evidence),
                verdict_label(item.control_verdict),
                routing_decision_label(item.control_routing_decision),
                network_summary(&item.control_network_evidence),
                item.reason
            )?;
            writeln!(
                &mut report,
                "  local_evidence={}",
                format_evidence_for_report(&item.local_evidence)
            )?;
            writeln!(
                &mut report,
                "  control_evidence={}",
                format_evidence_for_report(&item.control_evidence)
            )?;
        }
    }

    std::fs::write(output_path, report)?;
    Ok(())
}

pub fn write_confirmed_proxy_required(
    comparisons: &[ComparisonResult],
    output_path: &Path,
) -> anyhow::Result<()> {
    ensure_parent_dir(output_path)?;
    let mut domains = comparisons
        .iter()
        .filter(|comparison| comparison.decision == ComparisonDecision::ConfirmedProxyRequired)
        .map(|comparison| comparison.domain.clone())
        .collect::<Vec<_>>();
    domains.sort();
    domains.dedup();

    let mut content = domains.join("\n");
    if !content.is_empty() {
        content.push('\n');
    }
    std::fs::write(output_path, content)?;
    Ok(())
}

fn augment_service_geo_comparisons(
    comparisons: &[ComparisonResult],
    local_results: &[ScanResult],
) -> Vec<ComparisonResult> {
    let mut augmented = comparisons.to_vec();
    let existing_domains = comparisons
        .iter()
        .map(|comparison| comparison.domain.as_str())
        .collect::<BTreeSet<_>>();

    for local in local_results.iter().filter(|result| {
        result.routing_decision == RoutingDecision::DirectOk && result.service.is_some()
    }) {
        if existing_domains.contains(local.domain.as_str()) {
            continue;
        }

        augmented.push(ComparisonResult {
            domain: local.domain.clone(),
            service: local.service.clone(),
            service_role: local.service_role.clone(),
            local_verdict: local.verdict,
            local_routing_decision: local.routing_decision,
            local_confidence: local.confidence,
            local_evidence: local.evidence.clone(),
            control_verdict: Verdict::Accessible,
            control_routing_decision: RoutingDecision::DirectOk,
            control_evidence: EvidenceBundle::default(),
            decision: ComparisonDecision::ConsistentDirect,
            local_network_evidence: local.network_evidence.clone(),
            control_network_evidence: NetworkEvidence::default(),
            network_notes: vec![
                "service coverage derived from local direct_ok result skipped by comparison pre-filter"
                    .to_string(),
            ],
            reason: "local direct_ok service coverage".to_string(),
        });
    }

    augmented
}

pub fn summarize_service_geo_with_local_results(
    comparisons: &[ComparisonResult],
    local_results: &[ScanResult],
) -> Vec<ServiceGeoSummary> {
    let augmented = augment_service_geo_comparisons(comparisons, local_results);
    summarize_service_geo(&augmented)
}

#[allow(clippy::too_many_lines)]
pub fn summarize_service_geo(comparisons: &[ComparisonResult]) -> Vec<ServiceGeoSummary> {
    let mut grouped = BTreeMap::<String, Vec<&ComparisonResult>>::new();
    for comparison in comparisons {
        grouped
            .entry(
                comparison
                    .service
                    .clone()
                    .unwrap_or_else(|| "unmapped".to_string()),
            )
            .or_default()
            .push(comparison);
    }

    let mut summaries = Vec::new();
    for (service, mut items) in grouped {
        items.sort_by(|a, b| a.domain.cmp(&b.domain));

        let mut confirmed_hosts = Vec::new();
        let mut candidate_hosts = Vec::new();
        let mut review_assisted_hosts = Vec::new();
        let mut direct_hosts = Vec::new();
        let mut observed_roles = BTreeSet::new();
        let mut confirmed_roles = BTreeSet::new();
        let mut candidate_roles = BTreeSet::new();
        let mut review_assisted_roles = BTreeSet::new();
        let mut local_geo_roles = BTreeSet::new();
        let mut direct_critical_roles = BTreeSet::new();
        let expected_roles = service_profiles::expected_roles_for_service(&service);
        let critical_roles = service_profiles::critical_roles_for_service(&service);

        for item in &items {
            if let Some(role) = item.service_role.as_deref() {
                observed_roles.insert(role.to_string());
                for satisfied in service_profiles::satisfied_roles(&item.domain) {
                    observed_roles.insert(satisfied);
                }
                if item.local_verdict == Verdict::GeoBlocked {
                    local_geo_roles.insert(role.to_string());
                    for satisfied in service_profiles::satisfied_roles(&item.domain) {
                        local_geo_roles.insert(satisfied);
                    }
                }
            }
            match item.decision {
                ComparisonDecision::ConfirmedProxyRequired => {
                    confirmed_hosts.push(item.domain.clone());
                    if let Some(role) = item.service_role.as_deref() {
                        confirmed_roles.insert(role.to_string());
                        for satisfied in service_profiles::satisfied_roles(&item.domain) {
                            confirmed_roles.insert(satisfied);
                        }
                    }
                }
                ComparisonDecision::CandidateProxyRequired => {
                    candidate_hosts.push(item.domain.clone());
                    if let Some(role) = item.service_role.as_deref() {
                        candidate_roles.insert(role.to_string());
                        for satisfied in service_profiles::satisfied_roles(&item.domain) {
                            candidate_roles.insert(satisfied);
                        }
                    }
                }
                ComparisonDecision::ConsistentDirect => {
                    direct_hosts.push(item.domain.clone());
                    if let Some(role) = item.service_role.as_deref()
                        && service_profiles::is_service_role_critical(Some(&service), Some(role))
                    {
                        direct_critical_roles.insert(role.to_string());
                    }
                    for satisfied in service_profiles::satisfied_roles(&item.domain) {
                        if service_profiles::is_service_role_critical(
                            Some(&service),
                            Some(satisfied.as_str()),
                        ) {
                            direct_critical_roles.insert(satisfied);
                        }
                    }
                }
                ComparisonDecision::NeedsReview => {
                    if item.control_routing_decision == RoutingDecision::DirectOk {
                        review_assisted_hosts.push(item.domain.clone());
                        if let Some(role) = item.service_role.as_deref() {
                            review_assisted_roles.insert(role.to_string());
                            for satisfied in service_profiles::satisfied_roles(&item.domain) {
                                review_assisted_roles.insert(satisfied);
                            }
                        }
                    }
                }
                ComparisonDecision::ConsistentBlocked => {}
            }
        }

        let observed_role_list = observed_roles.iter().cloned().collect::<Vec<_>>();
        let expected_role_list = expected_roles.clone();
        let missing_critical_roles = critical_roles
            .iter()
            .filter(|role| !observed_roles.iter().any(|observed| observed == *role))
            .cloned()
            .collect::<Vec<_>>();
        let observed_critical_count = observed_roles
            .iter()
            .filter(|role| {
                service_profiles::is_service_role_critical(Some(&service), Some(role.as_str()))
            })
            .count();
        let confirmed_critical_count = confirmed_roles
            .iter()
            .filter(|role| {
                service_profiles::is_service_role_critical(Some(&service), Some(role.as_str()))
            })
            .count();
        let candidate_critical_count = candidate_roles
            .iter()
            .filter(|role| {
                service_profiles::is_service_role_critical(Some(&service), Some(role.as_str()))
            })
            .count();
        let review_assisted_critical_count = review_assisted_roles
            .iter()
            .filter(|role| {
                service_profiles::is_service_role_critical(Some(&service), Some(role.as_str()))
            })
            .count();
        let local_geo_critical_count = local_geo_roles
            .iter()
            .filter(|role| {
                service_profiles::is_service_role_critical(Some(&service), Some(role.as_str()))
            })
            .count();
        let critical_coverage_complete =
            !critical_roles.is_empty() && missing_critical_roles.is_empty();

        let non_direct = items
            .iter()
            .filter(|item| item.decision != ComparisonDecision::ConsistentDirect)
            .count();

        let (decision, confidence, reason) = if critical_coverage_complete
            && (confirmed_critical_count >= 2
                || (!confirmed_hosts.is_empty()
                    && confirmed_hosts.len() >= 2
                    && observed_critical_count >= 1))
        {
            (
                ServiceGeoDecision::ConfirmedGeoBlocked,
                98,
                format!(
                    "control comparison confirms multiple critical service roles differ from the direct path (observed roles: {}; missing critical roles: {})",
                    format_roles(&observed_role_list),
                    format_roles(&missing_critical_roles)
                ),
            )
        } else if !confirmed_hosts.is_empty() {
            (
                ServiceGeoDecision::LikelyGeoBlocked,
                if confirmed_critical_count >= 1 {
                    88
                } else {
                    82
                },
                format!(
                    "at least one host differs between direct and control paths, but service-level coverage is still thin (observed roles: {}; expected roles: {}; missing critical roles: {})",
                    format_roles(&observed_role_list),
                    format_roles(&expected_role_list),
                    format_roles(&missing_critical_roles)
                ),
            )
        } else if candidate_hosts.len() >= 2
            || (candidate_critical_count >= 1 && observed_critical_count >= 1)
        {
            (
                ServiceGeoDecision::LikelyGeoBlocked,
                if candidate_critical_count >= 1 {
                    78
                } else {
                    72
                },
                format!(
                    "candidate differences touch important service roles, but confirmation is still incomplete (observed roles: {}; missing critical roles: {})",
                    format_roles(&observed_role_list),
                    format_roles(&missing_critical_roles)
                ),
            )
        } else if review_assisted_critical_count >= 1 && non_direct >= 2 {
            (
                ServiceGeoDecision::LikelyGeoBlocked,
                if review_assisted_critical_count >= 2 {
                    74
                } else {
                    68
                },
                format!(
                    "control path is direct for at least one critical service role while local observations stay blocked or challenged (review-assisted hosts: {}; observed roles: {}; missing critical roles: {})",
                    format_roles(&review_assisted_hosts),
                    format_roles(&observed_role_list),
                    format_roles(&missing_critical_roles)
                ),
            )
        } else if local_geo_critical_count >= 1
            && critical_coverage_complete
            && direct_critical_roles.len() + local_geo_critical_count >= critical_roles.len()
        {
            (
                ServiceGeoDecision::LikelyGeoBlocked,
                if local_geo_critical_count >= 2 {
                    72
                } else {
                    66
                },
                format!(
                    "critical service roles include strong local geo markers even though control-path separation is incomplete (local geo roles: {}; direct critical roles: {}; missing critical roles: {})",
                    format_roles(&local_geo_roles.iter().cloned().collect::<Vec<_>>()),
                    format_roles(&direct_critical_roles.iter().cloned().collect::<Vec<_>>()),
                    format_roles(&missing_critical_roles)
                ),
            )
        } else if local_geo_critical_count >= 1
            && critical_coverage_complete
            && observed_critical_count == critical_roles.len()
            && direct_critical_roles.is_empty()
            && non_direct >= critical_roles.len()
        {
            (
                ServiceGeoDecision::LikelyGeoBlocked,
                64,
                format!(
                    "all critical service roles are non-direct and at least one of them carries a strong local geo marker (local geo roles: {}; observed critical roles: {})",
                    format_roles(&local_geo_roles.iter().cloned().collect::<Vec<_>>()),
                    observed_critical_count
                ),
            )
        } else if !critical_roles.is_empty()
            && direct_critical_roles.len() == critical_roles.len()
            && confirmed_hosts.is_empty()
            && candidate_hosts.is_empty()
            && review_assisted_hosts.is_empty()
        {
            (
                ServiceGeoDecision::DirectOk,
                42,
                format!(
                    "all critical service roles look direct_ok, while remaining noise sits in non-critical roles (critical roles: {})",
                    format_roles(&direct_critical_roles.iter().cloned().collect::<Vec<_>>())
                ),
            )
        } else if !items.is_empty()
            && direct_hosts.len() == items.len()
            && (critical_roles.is_empty() || observed_critical_count >= 1)
            && missing_critical_roles.is_empty()
        {
            (
                ServiceGeoDecision::DirectOk,
                34,
                format!(
                    "all observed service roles look direct_ok on both paths (roles: {})",
                    format_roles(&observed_role_list)
                ),
            )
        } else if non_direct == items.len() {
            (
                ServiceGeoDecision::Inconclusive,
                52,
                format!(
                    "all observed hosts are non-direct on both paths, so geo-specific separation is not proven (observed roles: {}; missing critical roles: {})",
                    format_roles(&observed_role_list),
                    format_roles(&missing_critical_roles)
                ),
            )
        } else {
            (
                ServiceGeoDecision::Inconclusive,
                56,
                format!(
                    "service bundle mixes direct and ambiguous observations without enough role coverage (observed roles: {}; expected roles: {}; missing critical roles: {})",
                    format_roles(&observed_role_list),
                    format_roles(&expected_role_list),
                    format_roles(&missing_critical_roles)
                ),
            )
        };

        summaries.push(ServiceGeoSummary {
            service,
            decision,
            confidence,
            observed_roles: observed_role_list,
            missing_critical_roles,
            confirmed_hosts,
            candidate_hosts,
            review_assisted_hosts,
            direct_hosts,
            reason,
        });
    }

    summaries.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then_with(|| a.service.cmp(&b.service))
    });
    summaries
}

#[allow(clippy::too_many_lines)]
pub fn write_service_geo_report(
    summaries: &[ServiceGeoSummary],
    output_path: &Path,
) -> anyhow::Result<()> {
    ensure_parent_dir(output_path)?;
    let mut counts = BTreeMap::<&str, usize>::new();
    let mut publishable_services = Vec::new();
    let mut review_services = Vec::new();
    let mut direct_services = Vec::new();
    for summary in summaries {
        *counts
            .entry(service_geo_decision_label(summary.decision))
            .or_default() += 1;
        match service_publication_tier(summary) {
            "strict_publishable" => publishable_services.push(summary.service.clone()),
            "review_only" => review_services.push(summary.service.clone()),
            "direct_only" => direct_services.push(summary.service.clone()),
            _ => {}
        }
    }

    let mut report = String::new();
    writeln!(&mut report, "Bulbascan service geo report")?;
    writeln!(&mut report, "================================")?;
    writeln!(&mut report)?;
    writeln!(&mut report, "Summary")?;
    for (decision, count) in counts {
        writeln!(&mut report, "- {decision}: {count}")?;
    }
    writeln!(&mut report)?;
    writeln!(&mut report, "Publication guidance")?;
    writeln!(
        &mut report,
        "- strict_publishable_services: {}",
        format_report_list(&publishable_services)
    )?;
    writeln!(
        &mut report,
        "- review_only_services: {}",
        format_report_list(&review_services)
    )?;
    writeln!(
        &mut report,
        "- direct_only_services: {}",
        format_report_list(&direct_services)
    )?;

    let sections = [
        (
            "Confirmed Geo Blocked",
            ServiceGeoDecision::ConfirmedGeoBlocked,
        ),
        ("Likely Geo Blocked", ServiceGeoDecision::LikelyGeoBlocked),
        ("Inconclusive", ServiceGeoDecision::Inconclusive),
        ("Direct OK", ServiceGeoDecision::DirectOk),
    ];

    for (title, decision) in sections {
        writeln!(&mut report)?;
        writeln!(&mut report, "{title}")?;
        writeln!(&mut report, "{}", "-".repeat(title.len()))?;

        let items = summaries
            .iter()
            .filter(|summary| summary.decision == decision)
            .collect::<Vec<_>>();
        if items.is_empty() {
            writeln!(&mut report, "none")?;
            continue;
        }

        for item in items {
            let confirmed = if item.confirmed_hosts.is_empty() {
                "-".to_string()
            } else {
                item.confirmed_hosts.join(", ")
            };
            let candidates = if item.candidate_hosts.is_empty() {
                "-".to_string()
            } else {
                item.candidate_hosts.join(", ")
            };
            let direct = if item.direct_hosts.is_empty() {
                "-".to_string()
            } else {
                item.direct_hosts.join(", ")
            };
            let review_assisted = if item.review_assisted_hosts.is_empty() {
                "-".to_string()
            } else {
                item.review_assisted_hosts.join(", ")
            };
            let observed_roles = if item.observed_roles.is_empty() {
                "-".to_string()
            } else {
                item.observed_roles.join(", ")
            };
            let missing_critical = if item.missing_critical_roles.is_empty() {
                "-".to_string()
            } else {
                item.missing_critical_roles.join(", ")
            };

            writeln!(
                &mut report,
                "- {} [{}%] publish_tier={} roles={} missing_critical={} confirmed={} candidates={} review_assisted={} direct={} {}",
                item.service,
                item.confidence,
                service_publication_tier(item),
                observed_roles,
                missing_critical,
                confirmed,
                candidates,
                review_assisted,
                direct,
                item.reason
            )?;
        }
    }

    std::fs::write(output_path, report)?;
    Ok(())
}

fn service_publication_tier(summary: &ServiceGeoSummary) -> &'static str {
    if summary.decision == ServiceGeoDecision::ConfirmedGeoBlocked
        && summary.missing_critical_roles.is_empty()
    {
        "strict_publishable"
    } else if summary.decision == ServiceGeoDecision::DirectOk {
        "direct_only"
    } else {
        "review_only"
    }
}

fn format_roles(roles: &[String]) -> String {
    if roles.is_empty() {
        "-".to_string()
    } else {
        roles.join(", ")
    }
}

fn format_report_list(items: &[String]) -> String {
    if items.is_empty() {
        "none".to_string()
    } else {
        items.join(", ")
    }
}

fn format_evidence_for_report(evidence: &super::types::EvidenceBundle) -> String {
    let summary = evidence_summary(evidence);
    if summary.is_empty() {
        "-".to_string()
    } else {
        summary
    }
}

pub fn write_control_proxy_health(
    health: &ControlProxyHealth,
    output_path: &Path,
) -> anyhow::Result<()> {
    ensure_parent_dir(output_path)?;
    let mut report = String::new();
    writeln!(&mut report, "Bulbascan control proxy health")?;
    writeln!(&mut report, "==================================")?;
    writeln!(&mut report)?;
    writeln!(&mut report, "proxy_url: {}", health.proxy_url)?;
    writeln!(&mut report, "healthy: {}", health.healthy)?;
    writeln!(&mut report, "http_ok: {}", health.http_ok)?;
    writeln!(&mut report, "https_connect_ok: {}", health.https_connect_ok)?;
    writeln!(&mut report)?;
    writeln!(
        &mut report,
        "http_check: {} ({})",
        control_proxy_failure_label(health.http_check.kind),
        health.http_check.detail
    )?;
    writeln!(
        &mut report,
        "https_example_check: {} ({})",
        control_proxy_failure_label(health.https_example_check.kind),
        health.https_example_check.detail
    )?;
    writeln!(
        &mut report,
        "https_trace_check: {} ({})",
        control_proxy_failure_label(health.https_trace_check.kind),
        health.https_trace_check.detail
    )?;

    if !health.notes.is_empty() {
        writeln!(&mut report)?;
        writeln!(&mut report, "notes")?;
        writeln!(&mut report, "-----")?;
        for note in &health.notes {
            writeln!(&mut report, "- {note}")?;
        }
    }

    std::fs::write(output_path, report)?;
    Ok(())
}
