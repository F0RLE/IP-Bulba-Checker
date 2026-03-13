use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::scanner::{RoutingDecision, ScanResult};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalState {
    pub blocked: BTreeSet<String>,
    pub direct: BTreeSet<String>,
    pub manual_review: BTreeSet<String>,
}

impl LocalState {
    pub fn load(state_dir: &Path) -> anyhow::Result<Self> {
        Ok(Self {
            blocked: read_domain_file(&state_dir.join("blocked.txt"))?,
            direct: read_domain_file(&state_dir.join("direct.txt"))?,
            manual_review: read_domain_file(&state_dir.join("manual_review.txt"))?,
        })
    }

    pub async fn save(&self, state_dir: &Path) -> anyhow::Result<()> {
        tokio::fs::create_dir_all(state_dir).await?;
        write_domain_file(&state_dir.join("blocked.txt"), &self.blocked).await?;
        write_domain_file(&state_dir.join("direct.txt"), &self.direct).await?;
        write_domain_file(&state_dir.join("manual_review.txt"), &self.manual_review).await?;
        Ok(())
    }

    pub fn ingest_scan_results(&mut self, results: &[ScanResult]) {
        for result in results {
            match result.routing_decision {
                RoutingDecision::ProxyRequired => {
                    self.blocked.insert(result.domain.clone());
                    self.direct.remove(&result.domain);
                    self.manual_review.remove(&result.domain);
                }
                RoutingDecision::DirectOk => {
                    if !self.blocked.contains(&result.domain) {
                        self.direct.insert(result.domain.clone());
                    }
                    self.manual_review.remove(&result.domain);
                }
                RoutingDecision::ManualReview => {
                    if !self.blocked.contains(&result.domain)
                        && !self.direct.contains(&result.domain)
                    {
                        self.manual_review.insert(result.domain.clone());
                    }
                }
            }
        }
    }

    pub fn ingest_confirmed_blocked(&mut self, domains: &[String]) {
        for domain in domains {
            self.blocked.insert(domain.clone());
            self.direct.remove(domain);
            self.manual_review.remove(domain);
        }
    }

    pub fn blocked_domains(&self) -> Vec<String> {
        self.blocked.iter().cloned().collect()
    }

    pub fn is_finalized(&self, domain: &str) -> bool {
        self.blocked.contains(domain) || self.direct.contains(domain)
    }
}

fn read_domain_file(path: &Path) -> anyhow::Result<BTreeSet<String>> {
    if !path.exists() {
        return Ok(BTreeSet::new());
    }

    let content = std::fs::read_to_string(path)?;
    let mut domains = BTreeSet::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        domains.insert(trimmed.to_string());
    }
    Ok(domains)
}

async fn write_domain_file(path: &PathBuf, domains: &BTreeSet<String>) -> anyhow::Result<()> {
    let mut content = String::new();
    for domain in domains {
        content.push_str(domain);
        content.push('\n');
    }
    tokio::fs::write(path, content).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::LocalState;
    use crate::scanner::types::{
        DomainStatus, EvidenceBundle, NetworkEvidence, ProbeEvidence, RoutingDecision, ScanResult,
        Verdict,
    };

    fn sample_result(domain: &str, routing_decision: RoutingDecision) -> ScanResult {
        ScanResult {
            domain: domain.to_string(),
            service: None,
            service_role: None,
            evidence: EvidenceBundle::default(),
            network_evidence: NetworkEvidence {
                dns: ProbeEvidence::skipped("n/a"),
                path_dns: ProbeEvidence::skipped("n/a"),
                tcp_443: ProbeEvidence::skipped("n/a"),
                tls_443: ProbeEvidence::skipped("n/a"),
                tcp_80: ProbeEvidence::skipped("n/a"),
            },
            status: DomainStatus::Ok,
            verdict: Verdict::Accessible,
            routing_decision,
            confidence: 50,
            http_status: Some(200),
            reason: String::new(),
            block_type: None,
        }
    }

    #[test]
    fn blocked_promotes_and_clears_other_buckets() {
        let mut state = LocalState::default();
        state.direct.insert("example.com".to_string());
        state.manual_review.insert("example.com".to_string());
        state.ingest_scan_results(&[sample_result("example.com", RoutingDecision::ProxyRequired)]);
        assert!(state.blocked.contains("example.com"));
        assert!(!state.direct.contains("example.com"));
        assert!(!state.manual_review.contains("example.com"));
    }

    #[test]
    fn finalized_domains_are_blocked_or_direct() {
        let mut state = LocalState::default();
        state.blocked.insert("blocked.example".to_string());
        state.direct.insert("direct.example".to_string());
        state.manual_review.insert("review.example".to_string());
        assert!(state.is_finalized("blocked.example"));
        assert!(state.is_finalized("direct.example"));
        assert!(!state.is_finalized("review.example"));
    }
}
