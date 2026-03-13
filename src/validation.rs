use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::path::Path;

use crate::scanner::types::{
    ComparisonDecision, ComparisonResult, ServiceGeoDecision, ServiceGeoSummary,
    routing_decision_label, service_context_label, verdict_label,
};
use crate::scanner::{RoutingDecision, ScanResult, Verdict};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpectedOutcome {
    Geo,
    Waf,
    Direct,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum OutcomeBucket {
    GeoDetected,
    GeoMissed,
    WafDetected,
    WafMissed,
    DirectOk,
    DirectFalsePositive,
    MissingResults,
}

impl OutcomeBucket {
    fn as_str(self) -> &'static str {
        match self {
            Self::GeoDetected => "expected_geo_detected",
            Self::GeoMissed => "expected_geo_missed",
            Self::WafDetected => "expected_waf_detected",
            Self::WafMissed => "expected_waf_missed",
            Self::DirectOk => "expected_direct_ok",
            Self::DirectFalsePositive => "expected_direct_false_positive",
            Self::MissingResults => "expected_missing_results",
        }
    }
}

#[derive(Debug, Default)]
struct ExpectedOutcomeSummary {
    counts: BTreeMap<OutcomeBucket, usize>,
    details: BTreeMap<OutcomeBucket, Vec<String>>,
}

#[allow(clippy::too_many_lines)]
pub fn write_validation_report(
    results: &[ScanResult],
    comparisons: Option<&[ComparisonResult]>,
    service_geo: Option<&[ServiceGeoSummary]>,
    expectations: Option<&HashMap<String, ExpectedOutcome>>,
    output_path: &Path,
) -> anyhow::Result<()> {
    let total = results.len();
    let routing_counts = count_by(
        results
            .iter()
            .map(|result| routing_decision_label(result.routing_decision).to_string()),
    );
    let verdict_counts = count_by(
        results
            .iter()
            .map(|result| verdict_label(result.verdict).to_string()),
    );

    let proxy_required = results
        .iter()
        .filter(|result| result.routing_decision == RoutingDecision::ProxyRequired)
        .count();
    let manual_review = results
        .iter()
        .filter(|result| result.routing_decision == RoutingDecision::ManualReview)
        .count();
    let direct_ok = results
        .iter()
        .filter(|result| result.routing_decision == RoutingDecision::DirectOk)
        .count();
    let geo_blocked = results
        .iter()
        .filter(|result| result.verdict == Verdict::GeoBlocked)
        .count();
    let local_high_confidence_proxy = results
        .iter()
        .filter(|result| {
            result.routing_decision == RoutingDecision::ProxyRequired && result.confidence >= 90
        })
        .count();

    let noisy_manual_review = top_services_for_route(results, RoutingDecision::ManualReview, 8);
    let strong_local_proxy = top_proxy_required_domains(results, 8);

    let mut report = String::new();
    writeln!(&mut report, "Bulbascan validation report")?;
    writeln!(&mut report, "=================================")?;
    writeln!(&mut report)?;
    writeln!(&mut report, "Scan quality")?;
    writeln!(&mut report, "- scanned_domains: {total}")?;
    writeln!(
        &mut report,
        "- direct_ok: {} ({})",
        direct_ok,
        percent(direct_ok, total)
    )?;
    writeln!(
        &mut report,
        "- proxy_required: {} ({})",
        proxy_required,
        percent(proxy_required, total)
    )?;
    writeln!(
        &mut report,
        "- manual_review: {} ({})",
        manual_review,
        percent(manual_review, total)
    )?;
    writeln!(
        &mut report,
        "- geo_blocked verdicts: {} ({})",
        geo_blocked,
        percent(geo_blocked, total)
    )?;
    writeln!(
        &mut report,
        "- high_confidence_proxy_required: {} ({})",
        local_high_confidence_proxy,
        percent(local_high_confidence_proxy, total)
    )?;
    writeln!(
        &mut report,
        "- manual_review_pressure: {}",
        describe_manual_review_pressure(manual_review, total)
    )?;

    writeln!(&mut report)?;
    writeln!(&mut report, "Routing distribution")?;
    write_count_section(&mut report, &routing_counts)?;

    writeln!(&mut report)?;
    writeln!(&mut report, "Verdict distribution")?;
    write_count_section(&mut report, &verdict_counts)?;

    writeln!(&mut report)?;
    writeln!(&mut report, "Hotspots")?;
    writeln!(
        &mut report,
        "- manual_review_services: {}",
        format_pairs(&noisy_manual_review)
    )?;
    writeln!(
        &mut report,
        "- strongest_local_proxy_required: {}",
        format_strings(&strong_local_proxy)
    )?;

    if let Some(expectations) = expectations
        && !expectations.is_empty()
    {
        let accuracy = summarize_expected_outcomes(results, comparisons, expectations);
        let expected_total = accuracy.counts.values().sum::<usize>();

        writeln!(&mut report)?;
        writeln!(&mut report, "Expected-outcome accuracy")?;
        writeln!(&mut report, "- annotated_targets: {expected_total}")?;
        for bucket in [
            OutcomeBucket::GeoDetected,
            OutcomeBucket::GeoMissed,
            OutcomeBucket::WafDetected,
            OutcomeBucket::WafMissed,
            OutcomeBucket::DirectOk,
            OutcomeBucket::DirectFalsePositive,
            OutcomeBucket::MissingResults,
        ] {
            let count = accuracy.counts.get(&bucket).copied().unwrap_or_default();
            writeln!(
                &mut report,
                "- {}: {} ({})",
                bucket.as_str(),
                count,
                percent(count, expected_total)
            )?;
        }
        writeln!(
            &mut report,
            "- geo_detected_targets: {}",
            format_strings(
                accuracy
                    .details
                    .get(&OutcomeBucket::GeoDetected)
                    .map_or(&[][..], Vec::as_slice)
            )
        )?;
        writeln!(
            &mut report,
            "- geo_missed_targets: {}",
            format_strings(
                accuracy
                    .details
                    .get(&OutcomeBucket::GeoMissed)
                    .map_or(&[][..], Vec::as_slice)
            )
        )?;
        writeln!(
            &mut report,
            "- waf_detected_targets: {}",
            format_strings(
                accuracy
                    .details
                    .get(&OutcomeBucket::WafDetected)
                    .map_or(&[][..], Vec::as_slice)
            )
        )?;
        writeln!(
            &mut report,
            "- waf_missed_targets: {}",
            format_strings(
                accuracy
                    .details
                    .get(&OutcomeBucket::WafMissed)
                    .map_or(&[][..], Vec::as_slice)
            )
        )?;
        writeln!(
            &mut report,
            "- direct_ok_targets: {}",
            format_strings(
                accuracy
                    .details
                    .get(&OutcomeBucket::DirectOk)
                    .map_or(&[][..], Vec::as_slice)
            )
        )?;
        writeln!(
            &mut report,
            "- direct_false_positive_targets: {}",
            format_strings(
                accuracy
                    .details
                    .get(&OutcomeBucket::DirectFalsePositive)
                    .map_or(&[][..], Vec::as_slice)
            )
        )?;
    }

    if let Some(comparisons) = comparisons {
        let comparison_counts = count_by(
            comparisons
                .iter()
                .map(|comparison| format!("{:?}", comparison.decision).to_ascii_lowercase()),
        );
        let confirmed_proxy_required = comparisons
            .iter()
            .filter(|comparison| comparison.decision == ComparisonDecision::ConfirmedProxyRequired)
            .count();
        let candidate_proxy_required = comparisons
            .iter()
            .filter(|comparison| comparison.decision == ComparisonDecision::CandidateProxyRequired)
            .count();

        let locally_proxy_required_with_comparison = comparisons
            .iter()
            .filter(|c| c.local_routing_decision == RoutingDecision::ProxyRequired)
            .count();

        let strict_confirmation_rate = if locally_proxy_required_with_comparison == 0 {
            "n/a".to_string()
        } else {
            percent(
                confirmed_proxy_required,
                locally_proxy_required_with_comparison,
            )
        };
        let top_unconfirmed_proxy = strongest_unconfirmed_proxy(results, comparisons, 8);

        writeln!(&mut report)?;
        writeln!(&mut report, "Dual-vantage quality")?;
        writeln!(
            &mut report,
            "- confirmed_proxy_required: {} ({})",
            confirmed_proxy_required,
            percent(confirmed_proxy_required, comparisons.len())
        )?;
        writeln!(
            &mut report,
            "- candidate_proxy_required: {} ({})",
            candidate_proxy_required,
            percent(candidate_proxy_required, comparisons.len())
        )?;
        writeln!(
            &mut report,
            "- strict_confirmation_rate_vs_local_proxy_required: {strict_confirmation_rate}"
        )?;
        writeln!(
            &mut report,
            "- strongest_unconfirmed_local_proxy_required: {}",
            format_strings(&top_unconfirmed_proxy)
        )?;

        writeln!(&mut report)?;
        writeln!(&mut report, "Comparison distribution")?;
        write_count_section(&mut report, &comparison_counts)?;
    }

    if let Some(service_geo) = service_geo {
        let service_geo_counts = count_by(service_geo.iter().map(|summary| {
            match summary.decision {
                ServiceGeoDecision::ConfirmedGeoBlocked => "confirmed_geo_blocked",
                ServiceGeoDecision::LikelyGeoBlocked => "likely_geo_blocked",
                ServiceGeoDecision::DirectOk => "direct_ok",
                ServiceGeoDecision::Inconclusive => "inconclusive",
            }
            .to_string()
        }));
        let mut incomplete = service_geo
            .iter()
            .filter(|summary| !summary.missing_critical_roles.is_empty())
            .collect::<Vec<_>>();
        incomplete.sort_by(|a, b| {
            b.missing_critical_roles
                .len()
                .cmp(&a.missing_critical_roles.len())
                .then_with(|| a.service.cmp(&b.service))
        });

        let top_incomplete_services = incomplete
            .into_iter()
            .take(8)
            .map(|summary| {
                format!(
                    "{} [{}]",
                    summary.service,
                    summary.missing_critical_roles.join(", ")
                )
            })
            .collect::<Vec<_>>();

        writeln!(&mut report)?;
        writeln!(&mut report, "Service bundle quality")?;
        write_count_section(&mut report, &service_geo_counts)?;
        writeln!(
            &mut report,
            "- services_missing_critical_roles: {}",
            format_strings(&top_incomplete_services)
        )?;
    }

    std::fs::write(output_path, report)?;
    Ok(())
}

fn count_by<I, S>(values: I) -> BTreeMap<String, usize>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut counts = BTreeMap::new();
    for value in values {
        *counts.entry(value.into()).or_default() += 1;
    }
    counts
}

fn write_count_section(
    report: &mut String,
    counts: &BTreeMap<String, usize>,
) -> anyhow::Result<()> {
    if counts.is_empty() {
        writeln!(report, "- none")?;
        return Ok(());
    }
    for (label, count) in counts {
        writeln!(report, "- {label}: {count}")?;
    }
    Ok(())
}

fn top_services_for_route(
    results: &[ScanResult],
    route: RoutingDecision,
    limit: usize,
) -> Vec<(String, usize)> {
    let mut counts = BTreeMap::<String, usize>::new();
    for result in results
        .iter()
        .filter(|result| result.routing_decision == route)
    {
        *counts
            .entry(
                result
                    .service
                    .clone()
                    .unwrap_or_else(|| "unmapped".to_string()),
            )
            .or_default() += 1;
    }
    let mut items = counts.into_iter().collect::<Vec<_>>();
    items.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    items.truncate(limit);
    items
}

fn top_proxy_required_domains(results: &[ScanResult], limit: usize) -> Vec<String> {
    let mut items = results
        .iter()
        .filter(|result| result.routing_decision == RoutingDecision::ProxyRequired)
        .collect::<Vec<_>>();

    items.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then_with(|| a.domain.cmp(&b.domain))
    });

    items
        .into_iter()
        .take(limit)
        .map(|result| {
            format!(
                "{} [{}% {} {}]",
                result.domain,
                result.confidence,
                verdict_label(result.verdict),
                service_context_label(result)
            )
        })
        .collect()
}

fn strongest_unconfirmed_proxy(
    results: &[ScanResult],
    comparisons: &[ComparisonResult],
    limit: usize,
) -> Vec<String> {
    let confirmed = comparisons
        .iter()
        .filter(|comparison| comparison.decision == ComparisonDecision::ConfirmedProxyRequired)
        .map(|comparison| comparison.domain.as_str())
        .collect::<std::collections::HashSet<_>>();

    let mut items = results
        .iter()
        .filter(|result| {
            result.routing_decision == RoutingDecision::ProxyRequired
                && !confirmed.contains(result.domain.as_str())
        })
        .collect::<Vec<_>>();

    items.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then_with(|| a.domain.cmp(&b.domain))
    });

    items
        .into_iter()
        .take(limit)
        .map(|result| {
            format!(
                "{} [{}% {} {}]",
                result.domain,
                result.confidence,
                verdict_label(result.verdict),
                service_context_label(result)
            )
        })
        .collect()
}

fn summarize_expected_outcomes(
    results: &[ScanResult],
    comparisons: Option<&[ComparisonResult]>,
    expectations: &HashMap<String, ExpectedOutcome>,
) -> ExpectedOutcomeSummary {
    let result_index = results
        .iter()
        .map(|result| (result.domain.as_str(), result))
        .collect::<HashMap<_, _>>();
    let comparison_index = comparisons.map(|items| {
        items
            .iter()
            .map(|comparison| (comparison.domain.as_str(), comparison))
            .collect::<HashMap<_, _>>()
    });

    let mut summary = ExpectedOutcomeSummary::default();
    for (domain, expected) in expectations {
        let Some(result) = result_index.get(domain.as_str()) else {
            *summary
                .counts
                .entry(OutcomeBucket::MissingResults)
                .or_default() += 1;
            summary
                .details
                .entry(OutcomeBucket::MissingResults)
                .or_default()
                .push(domain.clone());
            continue;
        };
        let comparison = comparison_index
            .as_ref()
            .and_then(|items| items.get(domain.as_str()).copied());
        let bucket = expected_outcome_bucket(*expected, result, comparison);
        *summary.counts.entry(bucket).or_default() += 1;
        summary
            .details
            .entry(bucket)
            .or_default()
            .push(format_expected_target(domain, result, comparison));
    }

    for items in summary.details.values_mut() {
        items.sort();
        items.truncate(10);
    }

    summary
}

fn expected_outcome_bucket(
    expected: ExpectedOutcome,
    result: &ScanResult,
    comparison: Option<&ComparisonResult>,
) -> OutcomeBucket {
    match expected {
        ExpectedOutcome::Geo => {
            let geo_like_local = matches!(result.verdict, Verdict::GeoBlocked);
            let geo_like_comparison = comparison.is_some_and(|item| {
                matches!(item.local_verdict, Verdict::GeoBlocked)
                    && item.decision == ComparisonDecision::ConfirmedProxyRequired
            });

            if geo_like_local || geo_like_comparison {
                OutcomeBucket::GeoDetected
            } else {
                OutcomeBucket::GeoMissed
            }
        }
        ExpectedOutcome::Waf => {
            let detected = matches!(result.verdict, Verdict::WafBlocked | Verdict::Captcha)
                || comparison.is_some_and(|item| {
                    matches!(item.local_verdict, Verdict::WafBlocked | Verdict::Captcha)
                        && item.decision == ComparisonDecision::ConfirmedProxyRequired
                });

            if detected {
                OutcomeBucket::WafDetected
            } else {
                OutcomeBucket::WafMissed
            }
        }
        ExpectedOutcome::Direct => {
            if result.routing_decision == RoutingDecision::DirectOk {
                OutcomeBucket::DirectOk
            } else {
                OutcomeBucket::DirectFalsePositive
            }
        }
    }
}

fn format_expected_target(
    domain: &str,
    result: &ScanResult,
    comparison: Option<&ComparisonResult>,
) -> String {
    if let Some(comparison) = comparison {
        format!(
            "{domain} [{} / {} -> {} / {}]",
            verdict_label(comparison.local_verdict),
            routing_decision_label(comparison.local_routing_decision),
            verdict_label(comparison.control_verdict),
            routing_decision_label(comparison.control_routing_decision)
        )
    } else {
        format!(
            "{domain} [{} / {}]",
            verdict_label(result.verdict),
            routing_decision_label(result.routing_decision)
        )
    }
}

fn format_pairs(items: &[(String, usize)]) -> String {
    if items.is_empty() {
        "-".to_string()
    } else {
        items
            .iter()
            .map(|(label, count)| format!("{label}:{count}"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn format_strings(items: &[String]) -> String {
    if items.is_empty() {
        "-".to_string()
    } else {
        items.join(", ")
    }
}

fn percent(count: usize, total: usize) -> String {
    if total == 0 {
        return "n/a".to_string();
    }
    let tenths = ((count as u128 * 1000) + (total as u128 / 2)) / total as u128;
    format!("{}.{}%", tenths / 10, tenths % 10)
}

fn describe_manual_review_pressure(manual_review: usize, total: usize) -> &'static str {
    if total == 0 {
        "no_data"
    } else {
        let manual_review = manual_review as u128;
        let total = total as u128;
        if manual_review * 100 <= total * 5 {
            "low"
        } else if manual_review * 100 <= total * 15 {
            "moderate"
        } else {
            "high"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ExpectedOutcome, write_validation_report};
    use crate::scanner::types::{
        ComparisonDecision, ComparisonResult, EvidenceBundle, NetworkEvidence, ServiceGeoDecision,
        ServiceGeoSummary, Verdict,
    };
    use crate::scanner::{DomainStatus, RoutingDecision, ScanResult};
    use std::collections::HashMap;

    #[test]
    fn writes_validation_report_with_comparison_and_service_sections() {
        let dir = std::env::temp_dir().join(format!("bulba-validation-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("validation_report.txt");

        let results = vec![
            ScanResult {
                domain: "claude.ai".into(),
                service: Some("Anthropic".into()),
                service_role: Some("web".into()),
                evidence: EvidenceBundle::default(),
                network_evidence: NetworkEvidence::default(),
                status: DomainStatus::Blocked,
                verdict: Verdict::GeoBlocked,
                routing_decision: RoutingDecision::ProxyRequired,
                confidence: 95,
                http_status: Some(451),
                reason: "geo".into(),
                block_type: None,
            },
            ScanResult {
                domain: "example.com".into(),
                service: None,
                service_role: None,
                evidence: EvidenceBundle::default(),
                network_evidence: NetworkEvidence::default(),
                status: DomainStatus::Ok,
                verdict: Verdict::Accessible,
                routing_decision: RoutingDecision::DirectOk,
                confidence: 80,
                http_status: Some(200),
                reason: "ok".into(),
                block_type: None,
            },
        ];
        let comparisons = vec![ComparisonResult {
            domain: "claude.ai".into(),
            service: Some("Anthropic".into()),
            service_role: Some("web".into()),
            local_verdict: Verdict::GeoBlocked,
            local_routing_decision: RoutingDecision::ProxyRequired,
            local_evidence: EvidenceBundle::default(),
            control_verdict: Verdict::Accessible,
            control_routing_decision: RoutingDecision::DirectOk,
            control_evidence: EvidenceBundle::default(),
            decision: ComparisonDecision::ConfirmedProxyRequired,
            local_network_evidence: NetworkEvidence::default(),
            control_network_evidence: NetworkEvidence::default(),
            network_notes: Vec::new(),
            reason: "confirmed".into(),
        }];
        let service_geo = vec![ServiceGeoSummary {
            service: "Anthropic".into(),
            decision: ServiceGeoDecision::ConfirmedGeoBlocked,
            confidence: 98,
            observed_roles: vec!["web".into()],
            missing_critical_roles: vec!["api".into()],
            confirmed_hosts: vec!["claude.ai".into()],
            candidate_hosts: Vec::new(),
            review_assisted_hosts: Vec::new(),
            direct_hosts: Vec::new(),
            reason: "confirmed".into(),
        }];
        let expectations = HashMap::from([
            ("claude.ai".to_string(), ExpectedOutcome::Geo),
            ("example.com".to_string(), ExpectedOutcome::Direct),
        ]);

        write_validation_report(
            &results,
            Some(&comparisons),
            Some(&service_geo),
            Some(&expectations),
            &path,
        )
        .unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("Scan quality"));
        assert!(content.contains("Expected-outcome accuracy"));
        assert!(content.contains("expected_geo_detected"));
        assert!(content.contains("geo_detected_targets"));
        assert!(content.contains("Dual-vantage quality"));
        assert!(content.contains("Service bundle quality"));
        assert!(content.contains("strict_confirmation_rate_vs_local_proxy_required"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
