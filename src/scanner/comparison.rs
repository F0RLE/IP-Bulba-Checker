use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use std::net::IpAddr;

use super::types::{
    ComparisonDecision, ComparisonResult, ControlProxyHealth, NetworkEvidence, ProbeStatus,
    RoutingDecision, ScanResult, ServiceGeoDecision, ServiceGeoSummary, Verdict,
    comparison_decision_label, control_proxy_failure_label, evidence_summary, network_summary,
    routing_decision_label, service_geo_decision_label, verdict_label,
};
use crate::service_profiles;

pub(crate) fn compare_result_pair(local: &ScanResult, control: &ScanResult) -> ComparisonResult {
    let decision = if local.routing_decision == RoutingDecision::ProxyRequired
        && control.routing_decision == RoutingDecision::DirectOk
    {
        ComparisonDecision::ConfirmedProxyRequired
    } else if matches!(
        local.verdict,
        Verdict::GeoBlocked
            | Verdict::NetworkBlocked
            | Verdict::TlsFailure
            | Verdict::Unreachable
            | Verdict::UnexpectedStatus
    ) && control.routing_decision == RoutingDecision::DirectOk
    {
        ComparisonDecision::CandidateProxyRequired
    } else if local.routing_decision == RoutingDecision::DirectOk
        && control.routing_decision == RoutingDecision::DirectOk
    {
        ComparisonDecision::ConsistentDirect
    } else if local.routing_decision != RoutingDecision::DirectOk
        && control.routing_decision != RoutingDecision::DirectOk
    {
        ComparisonDecision::ConsistentBlocked
    } else {
        ComparisonDecision::NeedsReview
    };

    let network_notes =
        compare_network_evidence(&local.network_evidence, &control.network_evidence);
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
        ComparisonDecision::NeedsReview => format!(
            "local route={} control route={}",
            routing_decision_label(local.routing_decision),
            routing_decision_label(control.routing_decision)
        ),
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
        local_routing_decision: local.routing_decision,
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
        notes.push("local system DNS failed while control path DNS resolved".to_string());
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
                notes.push(format!(
                    "path DNS has no IP overlap: local={local_preview} control={control_preview}"
                ));
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

pub fn write_control_comparison_report(
    comparisons: &[ComparisonResult],
    output_path: &Path,
) -> anyhow::Result<()> {
    let mut counts = BTreeMap::<&str, usize>::new();
    for comparison in comparisons {
        *counts
            .entry(comparison_decision_label(comparison.decision))
            .or_default() += 1;
    }

    let mut report = String::new();
    writeln!(&mut report, "Bulbascan control comparison report")?;
    writeln!(&mut report, "=========================================")?;
    writeln!(&mut report)?;
    writeln!(&mut report, "Summary")?;
    for (decision, count) in counts {
        writeln!(&mut report, "- {decision}: {count}")?;
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
                if item.local_verdict == Verdict::GeoBlocked {
                    local_geo_roles.insert(role.to_string());
                }
            }
            match item.decision {
                ComparisonDecision::ConfirmedProxyRequired => {
                    confirmed_hosts.push(item.domain.clone());
                    if let Some(role) = item.service_role.as_deref() {
                        confirmed_roles.insert(role.to_string());
                    }
                }
                ComparisonDecision::CandidateProxyRequired => {
                    candidate_hosts.push(item.domain.clone());
                    if let Some(role) = item.service_role.as_deref() {
                        candidate_roles.insert(role.to_string());
                    }
                }
                ComparisonDecision::ConsistentDirect => {
                    direct_hosts.push(item.domain.clone());
                    if let Some(role) = item.service_role.as_deref()
                        && service_profiles::is_service_role_critical(Some(&service), Some(role))
                    {
                        direct_critical_roles.insert(role.to_string());
                    }
                }
                ComparisonDecision::NeedsReview => {
                    if item.control_routing_decision == RoutingDecision::DirectOk {
                        review_assisted_hosts.push(item.domain.clone());
                        if let Some(role) = item.service_role.as_deref() {
                            review_assisted_roles.insert(role.to_string());
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

        let (decision, confidence, reason) = if confirmed_critical_count >= 2
            || (!confirmed_hosts.is_empty()
                && confirmed_hosts.len() >= 2
                && observed_critical_count >= 1)
        {
            let reason = if critical_coverage_complete {
                "control comparison confirms multiple critical service roles differ from the direct path"
            } else {
                "multiple confirmed hosts differ from control, but critical role coverage is still partial"
            };
            (
                ServiceGeoDecision::ConfirmedGeoBlocked,
                if critical_coverage_complete { 98 } else { 92 },
                format!(
                    "{reason} (observed roles: {}; missing critical roles: {})",
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

pub fn write_service_geo_report(
    summaries: &[ServiceGeoSummary],
    output_path: &Path,
) -> anyhow::Result<()> {
    let mut counts = BTreeMap::<&str, usize>::new();
    for summary in summaries {
        *counts
            .entry(service_geo_decision_label(summary.decision))
            .or_default() += 1;
    }

    let mut report = String::new();
    writeln!(&mut report, "Bulbascan service geo report")?;
    writeln!(&mut report, "================================")?;
    writeln!(&mut report)?;
    writeln!(&mut report, "Summary")?;
    for (decision, count) in counts {
        writeln!(&mut report, "- {decision}: {count}")?;
    }

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
                "- {} [{}%] roles={} missing_critical={} confirmed={} candidates={} review_assisted={} direct={} {}",
                item.service,
                item.confidence,
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

fn format_roles(roles: &[String]) -> String {
    if roles.is_empty() {
        "-".to_string()
    } else {
        roles.join(", ")
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
