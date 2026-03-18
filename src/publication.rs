use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use crate::scanner::{ComparisonDecision, ComparisonResult, RoutingDecision, ScanResult, Verdict};

const TXT_DIR: &str = "txt";
const PUBLISH_STRICT_FILE: &str = "publish-strict.txt";
const PUBLISH_REVIEW_FILE: &str = "publish-review.txt";
const PUBLISH_DIRECT_FILE: &str = "publish-direct.txt";
const HOT_RESCAN_FILE: &str = "rescan-hot.txt";
const WARM_RESCAN_FILE: &str = "rescan-warm.txt";
const COLD_RESCAN_FILE: &str = "rescan-cold.txt";
const PUBLICATION_REPORT_FILE: &str = "publication.txt";

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct PublicationPlan {
    strict_publish: BTreeSet<String>,
    review_only: BTreeSet<String>,
    direct_only: BTreeSet<String>,
    hot_rescan: BTreeSet<String>,
    warm_rescan: BTreeSet<String>,
    cold_rescan: BTreeSet<String>,
}

impl PublicationPlan {
    fn strict_publish_vec(&self) -> Vec<String> {
        self.strict_publish.iter().cloned().collect()
    }

    fn review_only_vec(&self) -> Vec<String> {
        self.review_only.iter().cloned().collect()
    }

    fn direct_only_vec(&self) -> Vec<String> {
        self.direct_only.iter().cloned().collect()
    }

    fn hot_rescan_vec(&self) -> Vec<String> {
        self.hot_rescan.iter().cloned().collect()
    }

    fn warm_rescan_vec(&self) -> Vec<String> {
        self.warm_rescan.iter().cloned().collect()
    }

    fn cold_rescan_vec(&self) -> Vec<String> {
        self.cold_rescan.iter().cloned().collect()
    }
}

pub(crate) fn write_publication_outputs(
    results: &[ScanResult],
    comparisons: Option<&[ComparisonResult]>,
    results_dir: &Path,
    state_dir: Option<&Path>,
) -> anyhow::Result<()> {
    let plan = build_publication_plan(results, comparisons);
    let txt_dir = results_dir.join(TXT_DIR);
    std::fs::create_dir_all(&txt_dir)?;

    write_list(
        &txt_dir.join(PUBLISH_STRICT_FILE),
        &plan.strict_publish_vec(),
    )?;
    write_list(&txt_dir.join(PUBLISH_REVIEW_FILE), &plan.review_only_vec())?;
    write_list(&txt_dir.join(PUBLISH_DIRECT_FILE), &plan.direct_only_vec())?;
    write_list(&txt_dir.join(HOT_RESCAN_FILE), &plan.hot_rescan_vec())?;
    write_list(&txt_dir.join(WARM_RESCAN_FILE), &plan.warm_rescan_vec())?;
    write_list(&txt_dir.join(COLD_RESCAN_FILE), &plan.cold_rescan_vec())?;
    std::fs::write(
        txt_dir.join(PUBLICATION_REPORT_FILE),
        render_publication_report(&plan, comparisons),
    )?;

    if let Some(state_dir) = state_dir {
        std::fs::create_dir_all(state_dir)?;
        write_list(&state_dir.join(HOT_RESCAN_FILE), &plan.hot_rescan_vec())?;
        write_list(&state_dir.join(WARM_RESCAN_FILE), &plan.warm_rescan_vec())?;
        write_list(&state_dir.join(COLD_RESCAN_FILE), &plan.cold_rescan_vec())?;
    }

    Ok(())
}

fn build_publication_plan(
    results: &[ScanResult],
    comparisons: Option<&[ComparisonResult]>,
) -> PublicationPlan {
    let mut plan = PublicationPlan::default();
    let mut comparison_by_domain = BTreeMap::new();

    if let Some(comparisons) = comparisons {
        for comparison in comparisons {
            comparison_by_domain.insert(comparison.domain.as_str(), comparison);
            match comparison.decision {
                ComparisonDecision::ConfirmedProxyRequired => {
                    plan.strict_publish.insert(comparison.domain.clone());
                }
                ComparisonDecision::CandidateProxyRequired | ComparisonDecision::NeedsReview => {
                    plan.review_only.insert(comparison.domain.clone());
                    plan.hot_rescan.insert(comparison.domain.clone());
                }
                ComparisonDecision::ConsistentBlocked => {
                    plan.review_only.insert(comparison.domain.clone());
                    plan.warm_rescan.insert(comparison.domain.clone());
                }
                ComparisonDecision::ConsistentDirect => {
                    plan.direct_only.insert(comparison.domain.clone());
                    plan.cold_rescan.insert(comparison.domain.clone());
                }
            }
        }
    }

    for result in results {
        match result.routing_decision {
            RoutingDecision::ProxyRequired => {
                if plan.strict_publish.contains(&result.domain) {
                    plan.cold_rescan.insert(result.domain.clone());
                } else {
                    plan.review_only.insert(result.domain.clone());
                    if comparison_by_domain.contains_key(result.domain.as_str()) {
                        plan.warm_rescan.insert(result.domain.clone());
                    } else {
                        plan.hot_rescan.insert(result.domain.clone());
                    }
                }
            }
            RoutingDecision::DirectOk => {
                plan.direct_only.insert(result.domain.clone());
                plan.cold_rescan.insert(result.domain.clone());
            }
            RoutingDecision::ManualReview => {
                plan.review_only.insert(result.domain.clone());
                if matches!(
                    result.verdict,
                    Verdict::Captcha | Verdict::WafBlocked | Verdict::RateLimited
                ) || result.reason.to_ascii_lowercase().contains("challenge")
                {
                    plan.hot_rescan.insert(result.domain.clone());
                } else {
                    plan.warm_rescan.insert(result.domain.clone());
                }
            }
        }
    }

    for domain in &plan.strict_publish {
        plan.review_only.remove(domain);
        plan.hot_rescan.remove(domain);
        plan.warm_rescan.remove(domain);
        plan.cold_rescan.insert(domain.clone());
    }

    for domain in &plan.direct_only {
        plan.hot_rescan.remove(domain);
        plan.warm_rescan.remove(domain);
        plan.cold_rescan.insert(domain.clone());
    }

    plan
}

fn render_publication_report(
    plan: &PublicationPlan,
    comparisons: Option<&[ComparisonResult]>,
) -> String {
    let mut report = String::new();
    let comparison_total = comparisons.map_or(0, <[ComparisonResult]>::len);
    let strict_count = plan.strict_publish.len();
    let review_count = plan.review_only.len();
    let direct_count = plan.direct_only.len();

    writeln!(&mut report, "Bulbascan publication report").ok();
    writeln!(&mut report, "===========================").ok();
    writeln!(&mut report).ok();
    writeln!(&mut report, "Publication tiers").ok();
    writeln!(&mut report, "- strict_publish: {strict_count}").ok();
    writeln!(&mut report, "- review_only: {review_count}").ok();
    writeln!(&mut report, "- direct_only: {direct_count}").ok();
    writeln!(&mut report).ok();
    writeln!(&mut report, "Rescan queues").ok();
    writeln!(&mut report, "- hot: {}", plan.hot_rescan.len()).ok();
    writeln!(&mut report, "- warm: {}", plan.warm_rescan.len()).ok();
    writeln!(&mut report, "- cold: {}", plan.cold_rescan.len()).ok();
    writeln!(&mut report).ok();
    writeln!(&mut report, "Guidance").ok();

    if comparison_total == 0 {
        writeln!(
            &mut report,
            "- no dual-vantage comparison data is available; publish only with caution and treat review queues as draft-only"
        )
        .ok();
    } else {
        writeln!(
            &mut report,
            "- strict publish should come from confirmed dual-vantage domains only"
        )
        .ok();
        writeln!(
            &mut report,
            "- review_only combines candidate, manual-review, and weaker non-strict blocked outcomes for later refresh cycles"
        )
        .ok();
    }

    writeln!(
        &mut report,
        "- hot queue is the short-interval refresh tier for challenge-heavy, candidate, and ambiguous domains"
    )
    .ok();
    writeln!(
        &mut report,
        "- warm queue is the medium-interval refresh tier for weaker blocked results and unresolved local-only outcomes"
    )
    .ok();
    writeln!(
        &mut report,
        "- cold queue is the long-interval refresh tier for strict confirmed blocked domains and direct-ok domains"
    )
    .ok();

    report
}

fn write_list(path: &Path, items: &[String]) -> anyhow::Result<()> {
    let mut content = items.join("\n");
    if !content.is_empty() {
        content.push('\n');
    }
    std::fs::write(path, content)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{build_publication_plan, write_publication_outputs};
    use crate::scanner::types::{
        ComparisonDecision, ComparisonResult, DomainStatus, EvidenceBundle, NetworkEvidence,
        RoutingDecision, ScanResult, Verdict,
    };

    fn result(domain: &str, routing_decision: RoutingDecision, verdict: Verdict) -> ScanResult {
        ScanResult {
            domain: domain.to_string(),
            service: None,
            service_role: None,
            evidence: EvidenceBundle::default(),
            network_evidence: NetworkEvidence::default(),
            status: DomainStatus::Ok,
            verdict,
            routing_decision,
            confidence: 80,
            http_status: Some(200),
            reason: String::new(),
            block_type: None,
        }
    }

    #[test]
    fn publication_plan_splits_strict_review_and_queues() {
        let results = vec![
            result(
                "strict.example",
                RoutingDecision::ProxyRequired,
                Verdict::GeoBlocked,
            ),
            result(
                "candidate.example",
                RoutingDecision::ManualReview,
                Verdict::GeoBlocked,
            ),
            result(
                "challenge.example",
                RoutingDecision::ManualReview,
                Verdict::Captcha,
            ),
            result(
                "direct.example",
                RoutingDecision::DirectOk,
                Verdict::Accessible,
            ),
        ];
        let comparisons = vec![
            ComparisonResult {
                domain: "strict.example".into(),
                service: None,
                service_role: None,
                local_verdict: Verdict::GeoBlocked,
                local_routing_decision: RoutingDecision::ProxyRequired,
                local_confidence: 95,
                local_evidence: EvidenceBundle::default(),
                control_verdict: Verdict::Accessible,
                control_routing_decision: RoutingDecision::DirectOk,
                control_evidence: EvidenceBundle::default(),
                decision: ComparisonDecision::ConfirmedProxyRequired,
                local_network_evidence: NetworkEvidence::default(),
                control_network_evidence: NetworkEvidence::default(),
                network_notes: Vec::new(),
                reason: "confirmed".into(),
            },
            ComparisonResult {
                domain: "candidate.example".into(),
                service: None,
                service_role: None,
                local_verdict: Verdict::GeoBlocked,
                local_routing_decision: RoutingDecision::ManualReview,
                local_confidence: 75,
                local_evidence: EvidenceBundle::default(),
                control_verdict: Verdict::Accessible,
                control_routing_decision: RoutingDecision::DirectOk,
                control_evidence: EvidenceBundle::default(),
                decision: ComparisonDecision::CandidateProxyRequired,
                local_network_evidence: NetworkEvidence::default(),
                control_network_evidence: NetworkEvidence::default(),
                network_notes: Vec::new(),
                reason: "candidate".into(),
            },
        ];

        let plan = build_publication_plan(&results, Some(&comparisons));
        assert!(plan.strict_publish.contains("strict.example"));
        assert!(plan.review_only.contains("candidate.example"));
        assert!(plan.review_only.contains("challenge.example"));
        assert!(plan.direct_only.contains("direct.example"));
        assert!(plan.hot_rescan.contains("candidate.example"));
        assert!(plan.hot_rescan.contains("challenge.example"));
        assert!(plan.cold_rescan.contains("strict.example"));
        assert!(plan.cold_rescan.contains("direct.example"));
    }

    #[test]
    fn publication_outputs_write_results_and_state_queues() {
        let dir = std::env::temp_dir().join(format!("bulba-publication-{}", std::process::id()));
        let state = dir.join("state");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let results = vec![
            result(
                "review.example",
                RoutingDecision::ManualReview,
                Verdict::WafBlocked,
            ),
            result(
                "direct.example",
                RoutingDecision::DirectOk,
                Verdict::Accessible,
            ),
        ];

        write_publication_outputs(&results, None, &dir, Some(&state)).unwrap();

        let report = std::fs::read_to_string(dir.join("txt").join("publication.txt")).unwrap();
        assert!(report.contains("Publication tiers"));
        assert!(report.contains("Rescan queues"));
        assert!(state.join("rescan-hot.txt").exists());
        assert!(state.join("rescan-warm.txt").exists());
        assert!(state.join("rescan-cold.txt").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
