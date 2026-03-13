use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt::Write as _;
use std::path::Path;

use serde::Serialize;

use crate::scanner::types::{
    ComparisonDecision, ComparisonResult, ServiceGeoDecision, ServiceGeoSummary,
};
use crate::scanner::{RoutingDecision, ScanResult};
use crate::service_profiles;

const SING_BOX_RULE_SET_VERSION: u8 = 4;
const SING_BOX_TAG: &str = "bulba-proxy-required";
const SING_BOX_RULE_SET_FILE: &str = "sing-box-rule-set.json";
const SING_BOX_ROUTE_FILE: &str = "sing-box-route-snippet.json";
const XRAY_ROUTE_FILE: &str = "xray-routing-rule.json";
const OPENWRT_PBR_FILE: &str = "openwrt-pbr-domains.txt";
const OPENWRT_DNSMASQ_IPSET_FILE: &str = "openwrt-dnsmasq-ipset.conf";
const STRICT_SING_BOX_TAG: &str = "bulba-confirmed-proxy-required";
const STRICT_SING_BOX_RULE_SET_FILE: &str = "strict-sing-box-rule-set.json";
const STRICT_SING_BOX_ROUTE_FILE: &str = "strict-sing-box-route-snippet.json";
const STRICT_XRAY_ROUTE_FILE: &str = "strict-xray-routing-rule.json";
const STRICT_OPENWRT_PBR_FILE: &str = "strict-openwrt-pbr-domains.txt";
const STRICT_OPENWRT_DNSMASQ_IPSET_FILE: &str = "strict-openwrt-dnsmasq-ipset.conf";
const SERVICE_BUNDLE_SING_BOX_TAG: &str = "bulba-known-service-bundles";
const SERVICE_BUNDLE_SING_BOX_RULE_SET_FILE: &str = "known-service-bundle-rule-set.json";
const SERVICE_BUNDLE_SING_BOX_ROUTE_FILE: &str = "known-service-bundle-route-snippet.json";
const SERVICE_BUNDLE_XRAY_ROUTE_FILE: &str = "known-service-bundle-xray-routing-rule.json";
const SERVICE_BUNDLE_OPENWRT_PBR_FILE: &str = "known-service-bundle-openwrt-pbr-domains.txt";
const SERVICE_BUNDLE_OPENWRT_DNSMASQ_FILE: &str = "known-service-bundle-dnsmasq-ipset.conf";
const GENERIC_APEX_SING_BOX_TAG: &str = "bulba-generic-apex-bypass";
const GENERIC_APEX_SING_BOX_RULE_SET_FILE: &str = "generic-apex-bypass-rule-set.json";
const GENERIC_APEX_SING_BOX_ROUTE_FILE: &str = "generic-apex-bypass-route-snippet.json";
const GENERIC_APEX_XRAY_ROUTE_FILE: &str = "generic-apex-bypass-xray-routing-rule.json";
const GENERIC_APEX_OPENWRT_PBR_FILE: &str = "generic-apex-bypass-domains.txt";
const GENERIC_APEX_OPENWRT_DNSMASQ_FILE: &str = "generic-apex-bypass-dnsmasq-ipset.conf";
const OPENWRT_IPSET_NAME: &str = "bulba_proxy";

#[derive(Serialize)]
struct SingBoxRuleSet {
    version: u8,
    rules: Vec<SingBoxHeadlessRule>,
}

#[derive(Serialize)]
struct SingBoxHeadlessRule {
    domain: Vec<String>,
}

#[derive(Serialize)]
struct SingBoxRouteSnippet {
    route: SingBoxRoute,
}

#[derive(Serialize)]
struct SingBoxRoute {
    rule_set: Vec<SingBoxRuleSetRef>,
    rules: Vec<SingBoxRouteRule>,
}

#[derive(Serialize)]
struct SingBoxRuleSetRef {
    tag: String,
    #[serde(rename = "type")]
    kind: String,
    format: String,
    path: String,
}

#[derive(Serialize)]
struct SingBoxRouteRule {
    rule_set: String,
    action: String,
    outbound: String,
}

#[derive(Serialize)]
struct XrayRoutingSnippet {
    routing: XrayRouting,
}

#[derive(Serialize)]
struct XrayRouting {
    #[serde(rename = "domainStrategy")]
    domain_strategy: String,
    rules: Vec<XrayRule>,
}

#[derive(Serialize)]
struct XrayRule {
    #[serde(rename = "type")]
    kind: String,
    domain: Vec<String>,
    #[serde(rename = "outboundTag")]
    outbound_tag: String,
    #[serde(rename = "ruleTag")]
    rule_tag: String,
}

#[derive(Clone, Copy)]
struct RouterExportSpec<'a> {
    sing_box_tag: &'a str,
    sing_box_rule_set_file: &'a str,
    sing_box_route_file: &'a str,
    xray_route_file: &'a str,
    openwrt_pbr_file: &'a str,
    openwrt_dnsmasq_file: &'a str,
    xray_rule_tag: &'a str,
}

pub fn write_router_exports(
    results: &[ScanResult],
    output_dir: &Path,
) -> anyhow::Result<Vec<String>> {
    let domains = proxy_required_domains(results);
    write_router_exports_for_domains(
        &domains,
        output_dir,
        RouterExportSpec {
            sing_box_tag: SING_BOX_TAG,
            sing_box_rule_set_file: SING_BOX_RULE_SET_FILE,
            sing_box_route_file: SING_BOX_ROUTE_FILE,
            xray_route_file: XRAY_ROUTE_FILE,
            openwrt_pbr_file: OPENWRT_PBR_FILE,
            openwrt_dnsmasq_file: OPENWRT_DNSMASQ_IPSET_FILE,
            xray_rule_tag: "bulbascan-proxy-required",
        },
    )
}

pub fn write_strict_router_exports(
    comparisons: &[ComparisonResult],
    output_dir: &Path,
) -> anyhow::Result<Vec<String>> {
    let domains = confirmed_proxy_required_domains(comparisons);
    write_router_exports_for_domains(
        &domains,
        output_dir,
        RouterExportSpec {
            sing_box_tag: STRICT_SING_BOX_TAG,
            sing_box_rule_set_file: STRICT_SING_BOX_RULE_SET_FILE,
            sing_box_route_file: STRICT_SING_BOX_ROUTE_FILE,
            xray_route_file: STRICT_XRAY_ROUTE_FILE,
            openwrt_pbr_file: STRICT_OPENWRT_PBR_FILE,
            openwrt_dnsmasq_file: STRICT_OPENWRT_DNSMASQ_IPSET_FILE,
            xray_rule_tag: "bulbascan-confirmed-proxy-required",
        },
    )
}

pub fn write_generic_apex_exports(
    results: &[ScanResult],
    output_dir: &Path,
) -> anyhow::Result<Vec<String>> {
    let domains = generic_apex_domains_from_results(results);
    write_router_exports_for_domains(
        &domains,
        output_dir,
        RouterExportSpec {
            sing_box_tag: GENERIC_APEX_SING_BOX_TAG,
            sing_box_rule_set_file: GENERIC_APEX_SING_BOX_RULE_SET_FILE,
            sing_box_route_file: GENERIC_APEX_SING_BOX_ROUTE_FILE,
            xray_route_file: GENERIC_APEX_XRAY_ROUTE_FILE,
            openwrt_pbr_file: GENERIC_APEX_OPENWRT_PBR_FILE,
            openwrt_dnsmasq_file: GENERIC_APEX_OPENWRT_DNSMASQ_FILE,
            xray_rule_tag: "bulbascan-generic-apex-bypass",
        },
    )
}

pub fn write_split_router_exports(
    comparisons: &[ComparisonResult],
    service_geo: &[ServiceGeoSummary],
    output_dir: &Path,
) -> anyhow::Result<Vec<String>> {
    let mut written = Vec::new();

    let service_domains = known_service_bundle_domains(comparisons, service_geo);
    written.extend(write_router_exports_for_domains(
        &service_domains,
        output_dir,
        RouterExportSpec {
            sing_box_tag: SERVICE_BUNDLE_SING_BOX_TAG,
            sing_box_rule_set_file: SERVICE_BUNDLE_SING_BOX_RULE_SET_FILE,
            sing_box_route_file: SERVICE_BUNDLE_SING_BOX_ROUTE_FILE,
            xray_route_file: SERVICE_BUNDLE_XRAY_ROUTE_FILE,
            openwrt_pbr_file: SERVICE_BUNDLE_OPENWRT_PBR_FILE,
            openwrt_dnsmasq_file: SERVICE_BUNDLE_OPENWRT_DNSMASQ_FILE,
            xray_rule_tag: "bulbascan-known-service-bundles",
        },
    )?);

    let generic_domains = generic_apex_domains_from_comparisons(comparisons);
    written.extend(write_router_exports_for_domains(
        &generic_domains,
        output_dir,
        RouterExportSpec {
            sing_box_tag: GENERIC_APEX_SING_BOX_TAG,
            sing_box_rule_set_file: GENERIC_APEX_SING_BOX_RULE_SET_FILE,
            sing_box_route_file: GENERIC_APEX_SING_BOX_ROUTE_FILE,
            xray_route_file: GENERIC_APEX_XRAY_ROUTE_FILE,
            openwrt_pbr_file: GENERIC_APEX_OPENWRT_PBR_FILE,
            openwrt_dnsmasq_file: GENERIC_APEX_OPENWRT_DNSMASQ_FILE,
            xray_rule_tag: "bulbascan-generic-apex-bypass",
        },
    )?);

    Ok(written)
}

fn proxy_required_domains(results: &[ScanResult]) -> Vec<String> {
    let mut domains = results
        .iter()
        .filter(|result| result.routing_decision == RoutingDecision::ProxyRequired)
        .map(|result| result.domain.clone())
        .collect::<Vec<_>>();
    domains.sort();
    domains.dedup();
    domains
}

fn confirmed_proxy_required_domains(comparisons: &[ComparisonResult]) -> Vec<String> {
    let mut domains = comparisons
        .iter()
        .filter(|comparison| comparison.decision == ComparisonDecision::ConfirmedProxyRequired)
        .map(|comparison| comparison.domain.clone())
        .collect::<Vec<_>>();
    domains.sort();
    domains.dedup();
    domains
}

fn generic_apex_domains_from_results(results: &[ScanResult]) -> Vec<String> {
    let mut domains = results
        .iter()
        .filter(|result| {
            result.service.is_none() && result.routing_decision == RoutingDecision::ProxyRequired
        })
        .map(|result| result.domain.clone())
        .collect::<Vec<_>>();
    domains.sort();
    domains.dedup();
    domains
}

fn generic_apex_domains_from_comparisons(comparisons: &[ComparisonResult]) -> Vec<String> {
    let mut domains = comparisons
        .iter()
        .filter(|comparison| {
            comparison.service.is_none()
                && matches!(
                    comparison.decision,
                    ComparisonDecision::ConfirmedProxyRequired
                        | ComparisonDecision::CandidateProxyRequired
                )
        })
        .map(|comparison| comparison.domain.clone())
        .collect::<Vec<_>>();
    domains.sort();
    domains.dedup();
    domains
}

fn known_service_bundle_domains(
    comparisons: &[ComparisonResult],
    service_geo: &[ServiceGeoSummary],
) -> Vec<String> {
    let comparisons_by_service = comparisons
        .iter()
        .filter_map(|comparison| {
            comparison
                .service
                .as_deref()
                .map(|service| (service, comparison))
        })
        .fold(
            HashMap::<&str, Vec<&ComparisonResult>>::new(),
            |mut grouped, (service, comparison)| {
                grouped.entry(service).or_default().push(comparison);
                grouped
            },
        );

    let mut selected = BTreeSet::new();
    for summary in service_geo.iter().filter(|summary| {
        matches!(
            summary.decision,
            ServiceGeoDecision::ConfirmedGeoBlocked | ServiceGeoDecision::LikelyGeoBlocked
        )
    }) {
        let Some(service_comparisons) = comparisons_by_service.get(summary.service.as_str()) else {
            continue;
        };

        selected.extend(minimal_service_bundle_domains(summary, service_comparisons));
    }

    selected.into_iter().collect()
}

fn minimal_service_bundle_domains(
    summary: &ServiceGeoSummary,
    comparisons: &[&ComparisonResult],
) -> BTreeSet<String> {
    let mut selected = BTreeSet::new();
    let mut covered_roles = HashSet::new();
    let priority_hosts = summary
        .confirmed_hosts
        .iter()
        .chain(summary.candidate_hosts.iter())
        .chain(summary.review_assisted_hosts.iter())
        .collect::<Vec<_>>();

    for host in priority_hosts {
        if let Some(comparison) = comparisons
            .iter()
            .find(|comparison| comparison.domain == *host)
        {
            selected.insert(comparison.domain.clone());
            if let Some(role) = comparison.service_role.as_deref() {
                covered_roles.insert(role.to_string());
            }
        }
    }

    let critical_roles = service_profiles::critical_roles_for_service(&summary.service);
    for role in &critical_roles {
        if covered_roles.contains(role.as_str()) {
            continue;
        }

        if let Some(comparison) = comparisons.iter().find(|comparison| {
            comparison
                .service_role
                .as_deref()
                .is_some_and(|candidate_role| candidate_role == role.as_str())
                && matches!(
                    comparison.decision,
                    ComparisonDecision::ConfirmedProxyRequired
                        | ComparisonDecision::CandidateProxyRequired
                )
        }) {
            selected.insert(comparison.domain.clone());
            covered_roles.insert(role.clone());
            continue;
        }

        if let Some(direct_host) = summary.direct_hosts.iter().find_map(|host| {
            comparisons.iter().find(|comparison| {
                comparison.domain == *host
                    && comparison
                        .service_role
                        .as_deref()
                        .is_some_and(|candidate_role| candidate_role == role.as_str())
            })
        }) {
            selected.insert(direct_host.domain.clone());
            covered_roles.insert(role.clone());
            continue;
        }

        if let Some(comparison) = comparisons.iter().find(|comparison| {
            comparison
                .service_role
                .as_deref()
                .is_some_and(|candidate_role| candidate_role == role.as_str())
                && comparison.decision == ComparisonDecision::ConsistentDirect
        }) {
            selected.insert(comparison.domain.clone());
            covered_roles.insert(role.clone());
        }
    }

    selected
}

fn write_router_exports_for_domains(
    domains: &[String],
    output_dir: &Path,
    spec: RouterExportSpec<'_>,
) -> anyhow::Result<Vec<String>> {
    let sing_box_rule_set_path = output_dir.join(spec.sing_box_rule_set_file);
    let sing_box_route_path = output_dir.join(spec.sing_box_route_file);
    let xray_route_path = output_dir.join(spec.xray_route_file);
    let openwrt_pbr_path = output_dir.join(spec.openwrt_pbr_file);
    let openwrt_dnsmasq_path = output_dir.join(spec.openwrt_dnsmasq_file);

    write_sing_box_rule_set(domains, &sing_box_rule_set_path)?;
    write_sing_box_route_snippet(
        &sing_box_rule_set_path,
        &sing_box_route_path,
        spec.sing_box_tag,
    )?;
    write_xray_route_snippet(domains, &xray_route_path, spec.xray_rule_tag)?;
    write_openwrt_pbr_domains(domains, &openwrt_pbr_path)?;
    write_openwrt_dnsmasq_ipset(domains, &openwrt_dnsmasq_path)?;

    Ok(vec![
        sing_box_rule_set_path.display().to_string(),
        sing_box_route_path.display().to_string(),
        xray_route_path.display().to_string(),
        openwrt_pbr_path.display().to_string(),
        openwrt_dnsmasq_path.display().to_string(),
    ])
}

fn write_sing_box_rule_set(domains: &[String], output_path: &Path) -> anyhow::Result<()> {
    let rules = if domains.is_empty() {
        Vec::new()
    } else {
        vec![SingBoxHeadlessRule {
            domain: domains.to_vec(),
        }]
    };
    let payload = SingBoxRuleSet {
        version: SING_BOX_RULE_SET_VERSION,
        rules,
    };
    std::fs::write(output_path, serde_json::to_vec_pretty(&payload)?)?;
    Ok(())
}

fn write_sing_box_route_snippet(
    rule_set_path: &Path,
    output_path: &Path,
    rule_set_tag: &str,
) -> anyhow::Result<()> {
    let rule_set_filename = rule_set_path.file_name().map_or_else(
        || SING_BOX_RULE_SET_FILE.to_string(),
        |name| name.to_string_lossy().into_owned(),
    );
    let payload = SingBoxRouteSnippet {
        route: SingBoxRoute {
            rule_set: vec![SingBoxRuleSetRef {
                tag: rule_set_tag.to_string(),
                kind: "local".to_string(),
                format: "source".to_string(),
                path: rule_set_filename,
            }],
            rules: vec![SingBoxRouteRule {
                rule_set: rule_set_tag.to_string(),
                action: "route".to_string(),
                outbound: "proxy".to_string(),
            }],
        },
    };
    std::fs::write(output_path, serde_json::to_vec_pretty(&payload)?)?;
    Ok(())
}

fn write_xray_route_snippet(
    domains: &[String],
    output_path: &Path,
    rule_tag: &str,
) -> anyhow::Result<()> {
    let payload = XrayRoutingSnippet {
        routing: XrayRouting {
            domain_strategy: "AsIs".to_string(),
            rules: vec![XrayRule {
                kind: "field".to_string(),
                domain: domains
                    .iter()
                    .map(|domain| format!("full:{domain}"))
                    .collect(),
                outbound_tag: "proxy".to_string(),
                rule_tag: rule_tag.to_string(),
            }],
        },
    };
    std::fs::write(output_path, serde_json::to_vec_pretty(&payload)?)?;
    Ok(())
}

fn write_openwrt_pbr_domains(domains: &[String], output_path: &Path) -> anyhow::Result<()> {
    let mut content = String::from(
        "# Confirmed by Bulbascan for OpenWrt pbr domain policies.\n\
# One exact domain per line.\n",
    );
    for domain in domains {
        content.push_str(domain);
        content.push('\n');
    }
    std::fs::write(output_path, content)?;
    Ok(())
}

fn write_openwrt_dnsmasq_ipset(domains: &[String], output_path: &Path) -> anyhow::Result<()> {
    let mut content = format!(
        "# dnsmasq-full snippet generated by Bulbascan\n\
# Exact domains only. Adjust ipset name if your router uses a different set.\n\
# Expected set name: {OPENWRT_IPSET_NAME}\n"
    );
    for domain in domains {
        writeln!(content, "ipset=/{domain}/{OPENWRT_IPSET_NAME}")?;
    }
    std::fs::write(output_path, content)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        write_generic_apex_exports, write_router_exports, write_split_router_exports,
        write_strict_router_exports,
    };
    use crate::scanner::types::{
        ComparisonDecision, ComparisonResult, EvidenceBundle, NetworkEvidence, ServiceGeoDecision,
        ServiceGeoSummary, Verdict,
    };
    use crate::scanner::{DomainStatus, RoutingDecision, ScanResult};

    #[test]
    fn writes_exact_match_router_exports_for_proxy_required_domains() {
        let dir = std::env::temp_dir().join(format!("bulba-router-exports-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let results = vec![
            ScanResult {
                domain: "claude.ai".into(),
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
                block_type: None,
            },
            ScanResult {
                domain: "direct.example".into(),
                service: None,
                service_role: None,
                evidence: EvidenceBundle::default(),
                network_evidence: NetworkEvidence::default(),
                status: DomainStatus::Ok,
                verdict: Verdict::Accessible,
                routing_decision: RoutingDecision::DirectOk,
                confidence: 85,
                http_status: Some(200),
                reason: "OK".into(),
                block_type: None,
            },
        ];

        let written = write_router_exports(&results, &dir).unwrap();
        assert_eq!(written.len(), 5);

        let sing_box = std::fs::read_to_string(dir.join("sing-box-rule-set.json")).unwrap();
        assert!(sing_box.contains("\"version\": 4"));
        assert!(sing_box.contains("\"claude.ai\""));
        assert!(!sing_box.contains("direct.example"));

        let sing_box_route =
            std::fs::read_to_string(dir.join("sing-box-route-snippet.json")).unwrap();
        assert!(sing_box_route.contains("\"action\": \"route\""));
        assert!(sing_box_route.contains("\"rule_set\": \"bulba-proxy-required\""));

        let xray = std::fs::read_to_string(dir.join("xray-routing-rule.json")).unwrap();
        assert!(xray.contains("\"full:claude.ai\""));
        assert!(!xray.contains("direct.example"));

        let openwrt_pbr = std::fs::read_to_string(dir.join("openwrt-pbr-domains.txt")).unwrap();
        assert!(openwrt_pbr.contains("claude.ai"));
        assert!(!openwrt_pbr.contains("direct.example"));

        let dnsmasq = std::fs::read_to_string(dir.join("openwrt-dnsmasq-ipset.conf")).unwrap();
        assert!(dnsmasq.contains("ipset=/claude.ai/bulba_proxy"));
        assert!(!dnsmasq.contains("direct.example"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn writes_strict_router_exports_for_confirmed_proxy_required_domains() {
        let dir = std::env::temp_dir().join(format!(
            "bulba-strict-router-exports-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let comparisons = vec![
            ComparisonResult {
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
            },
            ComparisonResult {
                domain: "review.example".into(),
                service: Some("Example".into()),
                service_role: Some("web".into()),
                local_verdict: Verdict::UnexpectedStatus,
                local_routing_decision: RoutingDecision::ManualReview,
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

        let written = write_strict_router_exports(&comparisons, &dir).unwrap();
        assert_eq!(written.len(), 5);

        let sing_box = std::fs::read_to_string(dir.join("strict-sing-box-rule-set.json")).unwrap();
        assert!(sing_box.contains("\"claude.ai\""));
        assert!(!sing_box.contains("review.example"));

        let sing_box_route =
            std::fs::read_to_string(dir.join("strict-sing-box-route-snippet.json")).unwrap();
        assert!(sing_box_route.contains("\"bulba-confirmed-proxy-required\""));

        let xray = std::fs::read_to_string(dir.join("strict-xray-routing-rule.json")).unwrap();
        assert!(xray.contains("\"full:claude.ai\""));
        assert!(xray.contains("bulbascan-confirmed-proxy-required"));
        assert!(!xray.contains("review.example"));

        let openwrt_pbr =
            std::fs::read_to_string(dir.join("strict-openwrt-pbr-domains.txt")).unwrap();
        assert!(openwrt_pbr.contains("claude.ai"));
        assert!(!openwrt_pbr.contains("review.example"));

        let dnsmasq =
            std::fs::read_to_string(dir.join("strict-openwrt-dnsmasq-ipset.conf")).unwrap();
        assert!(dnsmasq.contains("ipset=/claude.ai/bulba_proxy"));
        assert!(!dnsmasq.contains("review.example"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn writes_generic_apex_exports_only_for_unmapped_proxy_required_domains() {
        let dir =
            std::env::temp_dir().join(format!("bulba-generic-apex-exports-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let results = vec![
            ScanResult {
                domain: "unknown.example".into(),
                service: None,
                service_role: None,
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
        ];

        let written = write_generic_apex_exports(&results, &dir).unwrap();
        assert_eq!(written.len(), 5);

        let sing_box =
            std::fs::read_to_string(dir.join("generic-apex-bypass-rule-set.json")).unwrap();
        assert!(sing_box.contains("\"unknown.example\""));
        assert!(!sing_box.contains("claude.ai"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn writes_known_service_bundles_separately_from_generic_apex() {
        let dir =
            std::env::temp_dir().join(format!("bulba-split-router-exports-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let comparisons = vec![
            ComparisonResult {
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
            },
            ComparisonResult {
                domain: "console.anthropic.com".into(),
                service: Some("Anthropic".into()),
                service_role: Some("console".into()),
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
            },
            ComparisonResult {
                domain: "api.anthropic.com".into(),
                service: Some("Anthropic".into()),
                service_role: Some("api".into()),
                local_verdict: Verdict::Accessible,
                local_routing_decision: RoutingDecision::DirectOk,
                local_evidence: EvidenceBundle::default(),
                control_verdict: Verdict::Accessible,
                control_routing_decision: RoutingDecision::DirectOk,
                control_evidence: EvidenceBundle::default(),
                decision: ComparisonDecision::ConsistentDirect,
                local_network_evidence: NetworkEvidence::default(),
                control_network_evidence: NetworkEvidence::default(),
                network_notes: Vec::new(),
                reason: "direct".into(),
            },
            ComparisonResult {
                domain: "unknown.example".into(),
                service: None,
                service_role: None,
                local_verdict: Verdict::GeoBlocked,
                local_routing_decision: RoutingDecision::ProxyRequired,
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
        let service_geo = vec![ServiceGeoSummary {
            service: "Anthropic".into(),
            decision: ServiceGeoDecision::LikelyGeoBlocked,
            confidence: 88,
            observed_roles: vec!["web".into(), "console".into()],
            missing_critical_roles: vec!["api".into()],
            confirmed_hosts: vec!["claude.ai".into()],
            candidate_hosts: Vec::new(),
            review_assisted_hosts: Vec::new(),
            direct_hosts: Vec::new(),
            reason: "likely".into(),
        }];

        let written = write_split_router_exports(&comparisons, &service_geo, &dir).unwrap();
        assert_eq!(written.len(), 10);

        let service_bundle =
            std::fs::read_to_string(dir.join("known-service-bundle-rule-set.json")).unwrap();
        assert!(service_bundle.contains("\"claude.ai\""));
        assert!(service_bundle.contains("\"console.anthropic.com\""));
        assert!(service_bundle.contains("\"api.anthropic.com\""));
        assert!(!service_bundle.contains("unknown.example"));

        let generic =
            std::fs::read_to_string(dir.join("generic-apex-bypass-rule-set.json")).unwrap();
        assert!(generic.contains("\"unknown.example\""));
        assert!(!generic.contains("claude.ai"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
