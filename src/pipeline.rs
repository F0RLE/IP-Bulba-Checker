//! Utility functions for domain-list manipulation and output file writing.
//!
//! This module is deliberately stateless — every function takes its inputs
//! explicitly and has no side-effects beyond what is returned or awaited.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::Value as JsonValue;
use tokio::io::AsyncBufReadExt;

use crate::cli::{BlockedListFormatArg, normalize_domain, parse_annotated_domain_line};
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

/// Collect strictly confirmed proxy-required domains from control comparison results.
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

/// Load one plain-text domain file line by line, preserving per-file order.
pub(crate) async fn load_annotated_domains_from_file(
    path: &Path,
) -> anyhow::Result<Vec<(String, Option<ExpectedOutcome>)>> {
    let file = tokio::fs::File::open(path).await?;
    let mut reader = tokio::io::BufReader::new(file);
    let mut line = String::new();
    let mut entries = Vec::new();

    while reader.read_line(&mut line).await? > 0 {
        if let Some(entry) = parse_annotated_domain_line(&line) {
            entries.push(entry);
        }
        line.clear();
    }

    Ok(entries)
}

/// Load one plain line-oriented file, trimming whitespace and comments.
pub(crate) async fn load_trimmed_lines_from_file(path: &Path) -> anyhow::Result<Vec<String>> {
    let file = tokio::fs::File::open(path).await?;
    let mut reader = tokio::io::BufReader::new(file);
    let mut line = String::new();
    let mut entries = Vec::new();

    while reader.read_line(&mut line).await? > 0 {
        let trimmed = line.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            entries.push(trimmed.to_string());
        }
        line.clear();
    }

    Ok(entries)
}

fn collect_domains_from_json_value(
    value: &JsonValue,
    key_hint: Option<&str>,
    domains: &mut BTreeSet<String>,
) {
    match value {
        JsonValue::String(text) => {
            let should_try = matches!(
                key_hint.unwrap_or_default(),
                "domain"
                    | "domains"
                    | "domain_suffix"
                    | "domain_full"
                    | "domain_keyword"
                    | "payload"
            ) || text.contains("full:")
                || text.contains("DOMAIN-SUFFIX,")
                || text.contains("ipset=/")
                || text.starts_with("+.")
                || text.contains("://");

            if should_try && let Some(domain) = normalize_domain(text) {
                domains.insert(domain);
            }
        }
        JsonValue::Array(items) => {
            for item in items {
                collect_domains_from_json_value(item, key_hint, domains);
            }
        }
        JsonValue::Object(map) => {
            for (key, item) in map {
                let next_hint = match key.as_str() {
                    "domain" | "domains" | "domain_suffix" | "domain_full" | "domain_keyword"
                    | "payload" | "rules" | "route" | "routing" => Some(key.as_str()),
                    _ => key_hint,
                };
                collect_domains_from_json_value(item, next_hint, domains);
            }
        }
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) => {}
    }
}

pub(crate) async fn load_domains_from_json_file(path: &Path) -> anyhow::Result<Vec<String>> {
    let content = tokio::fs::read_to_string(path).await?;
    let payload: JsonValue = serde_json::from_str(&content)?;
    let mut domains = BTreeSet::new();
    collect_domains_from_json_value(&payload, None, &mut domains);
    Ok(domains.into_iter().collect())
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
    if let Some(parent) = output_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
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
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_file_path(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock drift")
            .as_nanos();
        std::env::temp_dir().join(format!("bulbascan-{name}-{unique}.txt"))
    }

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

    #[tokio::test]
    async fn loads_annotated_domains_from_plain_text_file() {
        let path = temp_file_path("annotated-domains");
        std::fs::write(
            &path,
            "# comment\ngeo claude.ai\nDOMAIN-SUFFIX,chatgpt.com\n\n",
        )
        .unwrap();

        let entries = load_annotated_domains_from_file(&path).await.unwrap();
        std::fs::remove_file(&path).unwrap();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0, "claude.ai");
        assert!(entries[0].1.is_some());
        assert_eq!(entries[1].0, "chatgpt.com");
        assert!(entries[1].1.is_none());
    }

    #[tokio::test]
    async fn loads_trimmed_non_comment_lines() {
        let path = temp_file_path("trimmed-lines");
        std::fs::write(
            &path,
            "# comment\n  socks5://127.0.0.1:1080 \n\nhttp://1.2.3.4:8080\n",
        )
        .unwrap();

        let entries = load_trimmed_lines_from_file(&path).await.unwrap();
        std::fs::remove_file(&path).unwrap();

        assert_eq!(
            entries,
            vec![
                "socks5://127.0.0.1:1080".to_string(),
                "http://1.2.3.4:8080".to_string()
            ]
        );
    }

    #[tokio::test]
    async fn loads_domains_from_json_rule_sets() {
        let path = temp_file_path("json-domains");
        std::fs::write(
            &path,
            r#"{
  "routing": {
    "rules": [
      {
        "domain": ["full:claude.ai", "DOMAIN-SUFFIX,chat.openai.com"]
      }
    ]
  }
}"#,
        )
        .unwrap();

        let entries = load_domains_from_json_file(&path).await.unwrap();
        std::fs::remove_file(&path).unwrap();

        assert_eq!(
            entries,
            vec!["chat.openai.com".to_string(), "claude.ai".to_string()]
        );
    }

    #[tokio::test]
    async fn loads_domains_from_yaml_like_payload_files_via_text_parser() {
        let path = temp_file_path("yaml-payload");
        std::fs::write(
            &path,
            "payload:\n  - '+.claude.ai'\n  - DOMAIN-SUFFIX,chat.openai.com\n",
        )
        .unwrap();

        let entries = load_annotated_domains_from_file(&path).await.unwrap();
        std::fs::remove_file(&path).unwrap();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0, "claude.ai");
        assert_eq!(entries[1].0, "chat.openai.com");
    }

    #[tokio::test]
    async fn loads_domains_from_dnsmasq_style_rule_files_via_text_parser() {
        let path = temp_file_path("dnsmasq-rules");
        std::fs::write(
            &path,
            "ipset=/claude.ai/bulba_proxy\nserver=/chat.openai.com/1.1.1.1\n",
        )
        .unwrap();

        let entries = load_annotated_domains_from_file(&path).await.unwrap();
        std::fs::remove_file(&path).unwrap();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0, "claude.ai");
        assert_eq!(entries[1].0, "chat.openai.com");
    }

    #[test]
    fn comparison_blocked_domains_include_only_confirmed_proxy_required() {
        let comparisons = vec![
            ComparisonResult {
                domain: "confirmed.example".to_string(),
                service: None,
                service_role: None,
                local_verdict: crate::scanner::Verdict::GeoBlocked,
                local_routing_decision: crate::scanner::RoutingDecision::ProxyRequired,
                local_confidence: 95,
                local_evidence: crate::scanner::types::EvidenceBundle::default(),
                control_verdict: crate::scanner::Verdict::Accessible,
                control_routing_decision: crate::scanner::RoutingDecision::DirectOk,
                control_evidence: crate::scanner::types::EvidenceBundle::default(),
                decision: crate::scanner::ComparisonDecision::ConfirmedProxyRequired,
                local_network_evidence: crate::scanner::types::NetworkEvidence::default(),
                control_network_evidence: crate::scanner::types::NetworkEvidence::default(),
                network_notes: Vec::new(),
                reason: "confirmed".to_string(),
            },
            ComparisonResult {
                domain: "candidate.example".to_string(),
                service: None,
                service_role: None,
                local_verdict: crate::scanner::Verdict::WafBlocked,
                local_routing_decision: crate::scanner::RoutingDecision::ManualReview,
                local_confidence: 78,
                local_evidence: crate::scanner::types::EvidenceBundle::default(),
                control_verdict: crate::scanner::Verdict::Accessible,
                control_routing_decision: crate::scanner::RoutingDecision::DirectOk,
                control_evidence: crate::scanner::types::EvidenceBundle::default(),
                decision: crate::scanner::ComparisonDecision::CandidateProxyRequired,
                local_network_evidence: crate::scanner::types::NetworkEvidence::default(),
                control_network_evidence: crate::scanner::types::NetworkEvidence::default(),
                network_notes: Vec::new(),
                reason: "candidate".to_string(),
            },
        ];

        assert_eq!(
            blocked_domains_from_comparisons(&comparisons),
            vec!["confirmed.example".to_string()]
        );
    }

    #[test]
    fn blocked_list_writer_creates_parent_directories() {
        let root = std::env::temp_dir().join(format!(
            "bulbascan-blocked-list-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock drift")
                .as_nanos()
        ));
        let output = root.join("lists").join("blocked.txt");

        write_blocked_domain_list(
            &["claude.ai".to_string()],
            &output,
            BlockedListFormatArg::Plain,
        )
        .unwrap();

        let content = std::fs::read_to_string(&output).unwrap();
        assert_eq!(content, "claude.ai\n");

        std::fs::remove_dir_all(&root).unwrap();
    }
}
