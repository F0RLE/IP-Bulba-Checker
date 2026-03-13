use prost::Message;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Domain matching type for `V2Ray` routing
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum DomainType {
    /// The value is used as is
    Plain = 0,
    /// The value is used as a regular expression
    Regex = 1,
    /// The value is a root domain (matches subdomains)
    Domain = 2,
    /// The value is a full domain (exact match)
    Full = 3,
}

/// Domain entry in a `GeoSite`
#[derive(Clone, PartialEq, Message)]
pub struct Domain {
    /// Matching type
    #[prost(enumeration = "DomainType", tag = "1")]
    pub r#type: i32,
    /// Domain value
    #[prost(string, tag = "2")]
    pub value: String,
}

/// A collection of domains identified by a category (`country_code`)
#[derive(Clone, PartialEq, Message)]
pub struct GeoSite {
    /// Category name (e.g., "blocked")
    #[prost(string, tag = "1")]
    pub country_code: String,
    /// List of domains
    #[prost(message, repeated, tag = "2")]
    pub domain: Vec<Domain>,
}

/// The root structure of a geosite.dat file
#[derive(Clone, PartialEq, Message)]
pub struct GeoSiteList {
    /// List of categories
    #[prost(message, repeated, tag = "1")]
    pub entry: Vec<GeoSite>,
}

use crate::scanner::DomainStatus;
use crate::scanner::RoutingDecision;
use crate::scanner::ScanResult;

/// Compiles a list of scan results into a multi-category binary geosite.dat file
pub fn compile(
    results: &[ScanResult],
    output_path: &Path,
    default_category: &str,
) -> anyhow::Result<()> {
    let mut categories: HashMap<String, Vec<String>> = HashMap::new();

    // 1. Group domains by category. Only proxy-required domains should end up
    // in routing rules; dead hosts and manual-review cases are not policy targets.
    for res in results {
        if res.status != DomainStatus::Blocked
            || res.routing_decision != RoutingDecision::ProxyRequired
        {
            continue;
        }

        let category = if let Some(bt) = res.block_type {
            bt.to_string().to_lowercase()
        } else {
            default_category.to_lowercase()
        };

        categories
            .entry(category)
            .or_default()
            .push(res.domain.clone());
    }

    compile_categories(categories, output_path)
}

/// Compiles a flat list of domains into a single-category binary geosite.dat file.
pub fn compile_domains(
    domains: &[String],
    output_path: &Path,
    category: &str,
) -> anyhow::Result<()> {
    let mut categories = HashMap::new();
    categories.insert(category.to_lowercase(), domains.to_vec());

    compile_categories(categories, output_path)
}

fn compile_categories(
    categories: HashMap<String, Vec<String>>,
    output_path: &Path,
) -> anyhow::Result<()> {
    let mut site_entries = Vec::new();

    for (cat_name, domains) in categories {
        // 2. Optimize domains per category
        let mut sorted = domains;
        sorted.sort_by_key(|d| d.split('.').count());

        let mut optimized = Vec::new();
        let mut base_domains: HashSet<String> = HashSet::new();

        for domain in sorted {
            let domain_low = domain.trim().to_lowercase();
            if domain_low.is_empty() {
                continue;
            }

            let mut is_covered = false;
            let mut search_start = 0;
            while let Some(dot_idx) = domain_low[search_start..].find('.') {
                search_start += dot_idx + 1;
                let parent = &domain_low[search_start..];
                if base_domains.contains(parent) {
                    is_covered = true;
                    break;
                }
            }

            if !is_covered {
                base_domains.insert(domain_low.clone());
                optimized.push(Domain {
                    r#type: DomainType::Domain as i32,
                    value: domain_low,
                });
            }
        }

        site_entries.push(GeoSite {
            country_code: cat_name.to_uppercase(),
            domain: optimized,
        });
    }

    let list = GeoSiteList {
        entry: site_entries,
    };
    let mut buf = Vec::new();
    list.encode(&mut buf)?;
    std::fs::write(output_path, buf)?;

    Ok(())
}

/// Decode a binary `geosite.dat` file and return all domain values for the
/// requested category.
///
/// - `category` is matched case-insensitively (e.g. `"blocked"` matches `"BLOCKED"`).
/// - Returns an error if the file cannot be read or the category is not found.
pub fn decode_domains(geosite_path: &Path, category: &str) -> anyhow::Result<Vec<String>> {
    let bytes = std::fs::read(geosite_path)
        .map_err(|e| anyhow::anyhow!("Cannot read {}: {e}", geosite_path.display()))?;

    let list = GeoSiteList::decode(bytes.as_slice())
        .map_err(|e| anyhow::anyhow!("Failed to decode geosite.dat: {e}"))?;

    let target = category.to_uppercase();

    // Support importing everything at once
    if target == "ALL" {
        return Ok(list
            .entry
            .into_iter()
            .flat_map(|e| e.domain)
            .map(|d| d.value)
            .collect());
    }

    let entry = list
        .entry
        .into_iter()
        .find(|e| e.country_code == target)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Category '{}' not found in {}",
                category,
                geosite_path.display()
            )
        })?;

    Ok(entry.domain.into_iter().map(|d| d.value).collect())
}

/// List all category names present in a `geosite.dat` file.
pub fn list_categories(geosite_path: &Path) -> anyhow::Result<Vec<String>> {
    let bytes = std::fs::read(geosite_path)
        .map_err(|e| anyhow::anyhow!("Cannot read {}: {e}", geosite_path.display()))?;

    let list = GeoSiteList::decode(bytes.as_slice())
        .map_err(|e| anyhow::anyhow!("Failed to decode geosite.dat: {e}"))?;

    Ok(list
        .entry
        .into_iter()
        .map(|e| e.country_code.to_lowercase())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::compile;
    use super::compile_domains;
    use crate::scanner::types::{EvidenceBundle, NetworkEvidence, Verdict};
    use crate::scanner::{DomainStatus, RoutingDecision, ScanResult};
    use crate::signatures::BlockType;

    #[test]
    fn geosite_ignores_dead_domains() {
        let tmp = std::env::temp_dir().join(format!("bulba-geosite-{}.dat", std::process::id()));
        let results = vec![
            ScanResult {
                domain: "blocked.example".into(),
                service: None,
                service_role: None,
                evidence: EvidenceBundle::default(),
                network_evidence: NetworkEvidence::default(),
                status: DomainStatus::Blocked,
                verdict: Verdict::GeoBlocked,
                routing_decision: RoutingDecision::ProxyRequired,
                confidence: 95,
                http_status: Some(451),
                reason: "HTTP 451".into(),
                block_type: Some(BlockType::Geo),
            },
            ScanResult {
                domain: "dead.example".into(),
                service: None,
                service_role: None,
                evidence: EvidenceBundle::default(),
                network_evidence: NetworkEvidence::default(),
                status: DomainStatus::Dead,
                verdict: Verdict::Unreachable,
                routing_decision: RoutingDecision::ManualReview,
                confidence: 55,
                http_status: None,
                reason: "dns failure".into(),
                block_type: None,
            },
        ];

        compile(&results, &tmp, "blocked").unwrap();
        let bytes = std::fs::read(&tmp).unwrap();
        let _ = std::fs::remove_file(&tmp);

        let payload = String::from_utf8_lossy(&bytes);
        assert!(payload.contains("blocked.example"));
        assert!(!payload.contains("dead.example"));
    }

    #[test]
    fn geosite_can_compile_explicit_domains() {
        let tmp =
            std::env::temp_dir().join(format!("bulba-geosite-explicit-{}.dat", std::process::id()));
        let domains = vec!["claude.ai".to_string(), "console.anthropic.com".to_string()];

        compile_domains(&domains, &tmp, "confirmed").unwrap();
        let bytes = std::fs::read(&tmp).unwrap();
        let _ = std::fs::remove_file(&tmp);

        let payload = String::from_utf8_lossy(&bytes);
        assert!(payload.contains("claude.ai"));
        assert!(payload.contains("CONFIRMED"));
    }
}
