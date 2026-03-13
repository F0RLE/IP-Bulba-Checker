//! Utility functions for domain-list manipulation and output file writing.
//!
//! This module is deliberately stateless — every function takes its inputs
//! explicitly and has no side-effects beyond what is returned or awaited.

use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::cli::{BlockedListFormatArg, normalize_domain};
use crate::scanner::{ComparisonDecision, ComparisonResult, RoutingDecision, ScanResult};
use crate::state::LocalState;
use crate::validation::ExpectedOutcome;

// ─── Domain filtering ─────────────────────────────────────────────────────────

/// Remove already-finalized domains (blocked or direct) from the scan queue
/// unless `refresh_known` is set.
///
/// Returns `(remaining_domains, skipped_count)`.
pub(crate) fn filter_pending_domains(
    domains: Vec<String>,
    expected_outcomes: &mut std::collections::HashMap<String, ExpectedOutcome>,
    local_state: &LocalState,
    refresh_known: bool,
) -> (Vec<String>, usize) {
    if refresh_known {
        return (domains, 0);
    }

    let before = domains.len();
    let filtered = domains
        .into_iter()
        .filter(|domain| !local_state.is_finalized(domain))
        .collect::<Vec<_>>();
    expected_outcomes.retain(|domain, _| !local_state.is_finalized(domain));
    let skipped = before.saturating_sub(filtered.len());
    (filtered, skipped)
}

// ─── Domain list assembly ─────────────────────────────────────────────────────

/// Collect all domains from scan results that require proxying.
pub(crate) fn blocked_domains_from_results(results: &[ScanResult]) -> Vec<String> {
    let mut domains = results
        .iter()
        .filter(|r| r.routing_decision == RoutingDecision::ProxyRequired)
        .map(|r| r.domain.clone())
        .collect::<Vec<_>>();
    domains.sort();
    domains.dedup();
    domains
}

/// Collect confirmed-proxy-required domains from control comparison results.
pub(crate) fn blocked_domains_from_comparisons(comparisons: &[ComparisonResult]) -> Vec<String> {
    let mut domains = comparisons
        .iter()
        .filter(|c| c.decision == ComparisonDecision::ConfirmedProxyRequired)
        .map(|c| c.domain.clone())
        .collect::<Vec<_>>();
    domains.sort();
    domains.dedup();
    domains
}

// ─── File writing ─────────────────────────────────────────────────────────────

/// Render domains to text using the requested list format.
pub(crate) fn render_blocked_domain_list(
    domains: &[String],
    format: BlockedListFormatArg,
) -> String {
    let mut content = String::new();
    for domain in domains {
        content.push_str(&format.format_domain(domain));
        content.push('\n');
    }
    content
}

/// Write the blocked-domain list synchronously (called from non-async context).
pub(crate) fn write_blocked_domain_list(
    domains: &[String],
    output_path: &PathBuf,
    format: BlockedListFormatArg,
) -> anyhow::Result<()> {
    std::fs::write(output_path, render_blocked_domain_list(domains, format))?;
    Ok(())
}

/// Merge blocked domains into an existing list file, deduplicating.
///
/// Returns the total number of unique domains in the merged file.
pub(crate) async fn merge_blocked_domains_into_list(
    merge_path: &PathBuf,
    blocked_domains: &[String],
    format: BlockedListFormatArg,
) -> anyhow::Result<usize> {
    let mut merged = BTreeSet::new();
    if merge_path.exists() {
        let content = tokio::fs::read_to_string(merge_path).await?;
        for line in content.lines() {
            if let Some(domain) = normalize_domain(line) {
                merged.insert(domain);
            }
        }
    }
    for domain in blocked_domains {
        merged.insert(domain.clone());
    }

    let merged_domains = merged.into_iter().collect::<Vec<_>>();
    if let Some(parent) = merge_path.parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(
        merge_path,
        render_blocked_domain_list(&merged_domains, format),
    )
    .await?;
    Ok(merged_domains.len())
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::BlockedListFormatArg;

    #[test]
    fn renders_geosite_source_blocked_list() {
        let rendered = render_blocked_domain_list(
            &["claude.ai".to_string(), "console.anthropic.com".to_string()],
            BlockedListFormatArg::GeositeSource,
        );
        assert!(rendered.contains("full:claude.ai"));
        assert!(rendered.contains("full:console.anthropic.com"));
    }

    #[test]
    fn state_filter_skips_blocked_and_direct_but_keeps_review() {
        let mut state = LocalState::default();
        state.blocked.insert("blocked.example".to_string());
        state.direct.insert("direct.example".to_string());
        state.manual_review.insert("review.example".to_string());

        let mut expected = std::collections::HashMap::from([
            ("blocked.example".to_string(), ExpectedOutcome::Geo),
            ("direct.example".to_string(), ExpectedOutcome::Direct),
            ("review.example".to_string(), ExpectedOutcome::Waf),
            ("new.example".to_string(), ExpectedOutcome::Geo),
        ]);

        let (pending, skipped) = filter_pending_domains(
            vec![
                "blocked.example".to_string(),
                "direct.example".to_string(),
                "review.example".to_string(),
                "new.example".to_string(),
            ],
            &mut expected,
            &state,
            false,
        );

        assert_eq!(skipped, 2);
        assert_eq!(
            pending,
            vec!["review.example".to_string(), "new.example".to_string()]
        );
        assert!(!expected.contains_key("blocked.example"));
        assert!(!expected.contains_key("direct.example"));
        assert!(expected.contains_key("review.example"));
        assert!(expected.contains_key("new.example"));
    }
}
