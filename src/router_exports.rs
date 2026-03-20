use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;

use crate::scanner::types::{
    ComparisonDecision, ComparisonResult, ServiceGeoDecision, ServiceGeoSummary,
};
use crate::scanner::{RoutingDecision, ScanResult};
use crate::service_profiles;

const TXT_DIR: &str = "txt";
const JSON_DIR: &str = "json";
const YAML_DIR: &str = "yaml";
const BIN_DIR: &str = "bin";
const SING_BOX_RULE_SET_VERSION: u8 = 4;
const SING_BOX_TAG: &str = "bulba-proxy-required";
const SING_BOX_RULE_SET_FILE: &str = "sing-box.json";
const SING_BOX_BINARY_RULE_SET_FILE: &str = "sing-box.srs";
const SING_BOX_ROUTE_FILE: &str = "sing-box-route.json";
const SING_BOX_BINARY_ROUTE_FILE: &str = "sing-box-binary-route.json";
const XRAY_ROUTE_FILE: &str = "xray.json";
const MIHOMO_RULE_SET_FILE: &str = "mihomo.txt";
const MIHOMO_BINARY_RULE_SET_FILE: &str = "mihomo.mrs";
const MIHOMO_PROVIDER_FILE: &str = "mihomo.yaml";
const MIHOMO_BINARY_PROVIDER_FILE: &str = "mihomo-binary.yaml";
const OPENWRT_PBR_FILE: &str = "openwrt.txt";
const OPENWRT_DNSMASQ_IPSET_FILE: &str = "dnsmasq.conf";
const STRICT_SING_BOX_TAG: &str = "bulba-confirmed-proxy-required";
const STRICT_SING_BOX_RULE_SET_FILE: &str = "strict.json";
const STRICT_SING_BOX_BINARY_RULE_SET_FILE: &str = "strict.srs";
const STRICT_SING_BOX_ROUTE_FILE: &str = "strict-route.json";
const STRICT_SING_BOX_BINARY_ROUTE_FILE: &str = "strict-binary-route.json";
const STRICT_XRAY_ROUTE_FILE: &str = "strict-xray.json";
const STRICT_MIHOMO_RULE_SET_FILE: &str = "strict.txt";
const STRICT_MIHOMO_BINARY_RULE_SET_FILE: &str = "strict.mrs";
const STRICT_MIHOMO_PROVIDER_FILE: &str = "strict.yaml";
const STRICT_MIHOMO_BINARY_PROVIDER_FILE: &str = "strict-binary.yaml";
const STRICT_OPENWRT_PBR_FILE: &str = "strict-openwrt.txt";
const STRICT_OPENWRT_DNSMASQ_IPSET_FILE: &str = "strict-dnsmasq.conf";
const SERVICE_BUNDLE_SING_BOX_TAG: &str = "bulba-known-service-bundles";
const SERVICE_BUNDLE_SING_BOX_RULE_SET_FILE: &str = "bundle.json";
const SERVICE_BUNDLE_SING_BOX_BINARY_RULE_SET_FILE: &str = "bundle.srs";
const SERVICE_BUNDLE_SING_BOX_ROUTE_FILE: &str = "bundle-route.json";
const SERVICE_BUNDLE_SING_BOX_BINARY_ROUTE_FILE: &str = "bundle-binary-route.json";
const SERVICE_BUNDLE_XRAY_ROUTE_FILE: &str = "bundle-xray.json";
const SERVICE_BUNDLE_MIHOMO_RULE_SET_FILE: &str = "bundle.txt";
const SERVICE_BUNDLE_MIHOMO_BINARY_RULE_SET_FILE: &str = "bundle.mrs";
const SERVICE_BUNDLE_MIHOMO_PROVIDER_FILE: &str = "bundle.yaml";
const SERVICE_BUNDLE_MIHOMO_BINARY_PROVIDER_FILE: &str = "bundle-binary.yaml";
const SERVICE_BUNDLE_OPENWRT_PBR_FILE: &str = "bundle-openwrt.txt";
const SERVICE_BUNDLE_OPENWRT_DNSMASQ_FILE: &str = "bundle-dnsmasq.conf";
const GENERIC_APEX_SING_BOX_TAG: &str = "bulba-generic-apex-bypass";
const GENERIC_APEX_SING_BOX_RULE_SET_FILE: &str = "apex.json";
const GENERIC_APEX_SING_BOX_BINARY_RULE_SET_FILE: &str = "apex.srs";
const GENERIC_APEX_SING_BOX_ROUTE_FILE: &str = "apex-route.json";
const GENERIC_APEX_SING_BOX_BINARY_ROUTE_FILE: &str = "apex-binary-route.json";
const GENERIC_APEX_XRAY_ROUTE_FILE: &str = "apex-xray.json";
const GENERIC_APEX_MIHOMO_RULE_SET_FILE: &str = "apex.txt";
const GENERIC_APEX_MIHOMO_BINARY_RULE_SET_FILE: &str = "apex.mrs";
const GENERIC_APEX_MIHOMO_PROVIDER_FILE: &str = "apex.yaml";
const GENERIC_APEX_MIHOMO_BINARY_PROVIDER_FILE: &str = "apex-binary.yaml";
const GENERIC_APEX_OPENWRT_PBR_FILE: &str = "apex-openwrt.txt";
const GENERIC_APEX_OPENWRT_DNSMASQ_FILE: &str = "apex-dnsmasq.conf";
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
    sing_box_binary_rule_set_file: &'a str,
    sing_box_route_file: &'a str,
    sing_box_binary_route_file: &'a str,
    xray_route_file: &'a str,
    mihomo_rule_set_file: &'a str,
    mihomo_binary_rule_set_file: &'a str,
    mihomo_provider_file: &'a str,
    mihomo_binary_provider_file: &'a str,
    openwrt_pbr_file: &'a str,
    openwrt_dnsmasq_file: &'a str,
    xray_rule_tag: &'a str,
}

#[derive(Clone, Copy)]
enum OutputBucket {
    Txt,
    Json,
    Yaml,
    Bin,
}

fn output_bucket_dir(output_dir: &Path, bucket: OutputBucket) -> PathBuf {
    match bucket {
        OutputBucket::Txt => output_dir.join(TXT_DIR),
        OutputBucket::Json => output_dir.join(JSON_DIR),
        OutputBucket::Yaml => output_dir.join(YAML_DIR),
        OutputBucket::Bin => output_dir.join(BIN_DIR),
    }
}

fn output_path(output_dir: &Path, bucket: OutputBucket, file: &str) -> PathBuf {
    output_bucket_dir(output_dir, bucket).join(file)
}

pub fn write_router_exports(
    results: &[ScanResult],
    output_dir: &Path,
) -> anyhow::Result<Vec<String>> {
    let domains = proxy_required_domains(results);
    write_router_exports_for_domain_list(&domains, output_dir)
}

pub fn write_router_exports_for_domain_list(
    domains: &[String],
    output_dir: &Path,
) -> anyhow::Result<Vec<String>> {
    write_router_exports_for_domains(
        domains,
        output_dir,
        RouterExportSpec {
            sing_box_tag: SING_BOX_TAG,
            sing_box_rule_set_file: SING_BOX_RULE_SET_FILE,
            sing_box_binary_rule_set_file: SING_BOX_BINARY_RULE_SET_FILE,
            sing_box_route_file: SING_BOX_ROUTE_FILE,
            sing_box_binary_route_file: SING_BOX_BINARY_ROUTE_FILE,
            xray_route_file: XRAY_ROUTE_FILE,
            mihomo_rule_set_file: MIHOMO_RULE_SET_FILE,
            mihomo_binary_rule_set_file: MIHOMO_BINARY_RULE_SET_FILE,
            mihomo_provider_file: MIHOMO_PROVIDER_FILE,
            mihomo_binary_provider_file: MIHOMO_BINARY_PROVIDER_FILE,
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
            sing_box_binary_rule_set_file: STRICT_SING_BOX_BINARY_RULE_SET_FILE,
            sing_box_route_file: STRICT_SING_BOX_ROUTE_FILE,
            sing_box_binary_route_file: STRICT_SING_BOX_BINARY_ROUTE_FILE,
            xray_route_file: STRICT_XRAY_ROUTE_FILE,
            mihomo_rule_set_file: STRICT_MIHOMO_RULE_SET_FILE,
            mihomo_binary_rule_set_file: STRICT_MIHOMO_BINARY_RULE_SET_FILE,
            mihomo_provider_file: STRICT_MIHOMO_PROVIDER_FILE,
            mihomo_binary_provider_file: STRICT_MIHOMO_BINARY_PROVIDER_FILE,
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
            sing_box_binary_rule_set_file: GENERIC_APEX_SING_BOX_BINARY_RULE_SET_FILE,
            sing_box_route_file: GENERIC_APEX_SING_BOX_ROUTE_FILE,
            sing_box_binary_route_file: GENERIC_APEX_SING_BOX_BINARY_ROUTE_FILE,
            xray_route_file: GENERIC_APEX_XRAY_ROUTE_FILE,
            mihomo_rule_set_file: GENERIC_APEX_MIHOMO_RULE_SET_FILE,
            mihomo_binary_rule_set_file: GENERIC_APEX_MIHOMO_BINARY_RULE_SET_FILE,
            mihomo_provider_file: GENERIC_APEX_MIHOMO_PROVIDER_FILE,
            mihomo_binary_provider_file: GENERIC_APEX_MIHOMO_BINARY_PROVIDER_FILE,
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
            sing_box_binary_rule_set_file: SERVICE_BUNDLE_SING_BOX_BINARY_RULE_SET_FILE,
            sing_box_route_file: SERVICE_BUNDLE_SING_BOX_ROUTE_FILE,
            sing_box_binary_route_file: SERVICE_BUNDLE_SING_BOX_BINARY_ROUTE_FILE,
            xray_route_file: SERVICE_BUNDLE_XRAY_ROUTE_FILE,
            mihomo_rule_set_file: SERVICE_BUNDLE_MIHOMO_RULE_SET_FILE,
            mihomo_binary_rule_set_file: SERVICE_BUNDLE_MIHOMO_BINARY_RULE_SET_FILE,
            mihomo_provider_file: SERVICE_BUNDLE_MIHOMO_PROVIDER_FILE,
            mihomo_binary_provider_file: SERVICE_BUNDLE_MIHOMO_BINARY_PROVIDER_FILE,
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
            sing_box_binary_rule_set_file: GENERIC_APEX_SING_BOX_BINARY_RULE_SET_FILE,
            sing_box_route_file: GENERIC_APEX_SING_BOX_ROUTE_FILE,
            sing_box_binary_route_file: GENERIC_APEX_SING_BOX_BINARY_ROUTE_FILE,
            xray_route_file: GENERIC_APEX_XRAY_ROUTE_FILE,
            mihomo_rule_set_file: GENERIC_APEX_MIHOMO_RULE_SET_FILE,
            mihomo_binary_rule_set_file: GENERIC_APEX_MIHOMO_BINARY_RULE_SET_FILE,
            mihomo_provider_file: GENERIC_APEX_MIHOMO_PROVIDER_FILE,
            mihomo_binary_provider_file: GENERIC_APEX_MIHOMO_BINARY_PROVIDER_FILE,
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
                && comparison.decision == ComparisonDecision::ConfirmedProxyRequired
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
    for summary in service_geo
        .iter()
        .filter(|summary| summary.decision == ServiceGeoDecision::ConfirmedGeoBlocked)
    {
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
    for bucket in [
        OutputBucket::Txt,
        OutputBucket::Json,
        OutputBucket::Yaml,
        OutputBucket::Bin,
    ] {
        std::fs::create_dir_all(output_bucket_dir(output_dir, bucket))?;
    }

    let sing_box_rule_set_path =
        output_path(output_dir, OutputBucket::Json, spec.sing_box_rule_set_file);
    let sing_box_binary_rule_set_path = output_path(
        output_dir,
        OutputBucket::Bin,
        spec.sing_box_binary_rule_set_file,
    );
    let sing_box_route_path = output_path(output_dir, OutputBucket::Json, spec.sing_box_route_file);
    let sing_box_binary_route_path = output_path(
        output_dir,
        OutputBucket::Json,
        spec.sing_box_binary_route_file,
    );
    let xray_route_path = output_path(output_dir, OutputBucket::Json, spec.xray_route_file);
    let mihomo_rule_set_path =
        output_path(output_dir, OutputBucket::Txt, spec.mihomo_rule_set_file);
    let mihomo_binary_rule_set_path = output_path(
        output_dir,
        OutputBucket::Bin,
        spec.mihomo_binary_rule_set_file,
    );
    let mihomo_provider_path =
        output_path(output_dir, OutputBucket::Yaml, spec.mihomo_provider_file);
    let mihomo_binary_provider_path = output_path(
        output_dir,
        OutputBucket::Yaml,
        spec.mihomo_binary_provider_file,
    );
    let openwrt_pbr_path = output_path(output_dir, OutputBucket::Txt, spec.openwrt_pbr_file);
    let openwrt_dnsmasq_path =
        output_path(output_dir, OutputBucket::Txt, spec.openwrt_dnsmasq_file);

    write_sing_box_rule_set(domains, &sing_box_rule_set_path)?;
    write_sing_box_route_snippet(
        &sing_box_rule_set_path,
        &sing_box_route_path,
        spec.sing_box_tag,
        "source",
    )?;
    let binary_written = maybe_compile_sing_box_binary_rule_set(
        &sing_box_rule_set_path,
        &sing_box_binary_rule_set_path,
    )?;
    if binary_written {
        write_sing_box_route_snippet(
            &sing_box_binary_rule_set_path,
            &sing_box_binary_route_path,
            spec.sing_box_tag,
            "binary",
        )?;
    } else if sing_box_binary_rule_set_path.exists() {
        let _ = std::fs::remove_file(&sing_box_binary_rule_set_path);
    }
    write_xray_route_snippet(domains, &xray_route_path, spec.xray_rule_tag)?;
    write_mihomo_rule_set(domains, &mihomo_rule_set_path)?;
    write_mihomo_provider_snippet(&mihomo_rule_set_path, &mihomo_provider_path, "text")?;
    let mihomo_binary_written =
        maybe_compile_mihomo_binary_rule_set(&mihomo_rule_set_path, &mihomo_binary_rule_set_path)?;
    if mihomo_binary_written {
        write_mihomo_provider_snippet(
            &mihomo_binary_rule_set_path,
            &mihomo_binary_provider_path,
            "mrs",
        )?;
    } else {
        if mihomo_binary_rule_set_path.exists() {
            let _ = std::fs::remove_file(&mihomo_binary_rule_set_path);
        }
        if mihomo_binary_provider_path.exists() {
            let _ = std::fs::remove_file(&mihomo_binary_provider_path);
        }
    }
    write_openwrt_pbr_domains(domains, &openwrt_pbr_path)?;
    write_openwrt_dnsmasq_ipset(domains, &openwrt_dnsmasq_path)?;

    let mut written = vec![
        sing_box_rule_set_path.display().to_string(),
        sing_box_route_path.display().to_string(),
        xray_route_path.display().to_string(),
        mihomo_rule_set_path.display().to_string(),
        mihomo_provider_path.display().to_string(),
        openwrt_pbr_path.display().to_string(),
        openwrt_dnsmasq_path.display().to_string(),
    ];
    if binary_written {
        written.push(sing_box_binary_rule_set_path.display().to_string());
        written.push(sing_box_binary_route_path.display().to_string());
    }
    if mihomo_binary_written {
        written.push(mihomo_binary_rule_set_path.display().to_string());
        written.push(mihomo_binary_provider_path.display().to_string());
    }
    Ok(written)
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
    format: &str,
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
                format: format.to_string(),
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

fn maybe_compile_sing_box_binary_rule_set(
    source_path: &Path,
    output_path: &Path,
) -> anyhow::Result<bool> {
    let Some(binary) = find_sing_box_binary() else {
        return Ok(false);
    };

    let status = Command::new(binary)
        .arg("rule-set")
        .arg("compile")
        .arg(source_path)
        .arg("-o")
        .arg(output_path)
        .status()?;

    if status.success() {
        Ok(true)
    } else {
        if output_path.exists() {
            let _ = std::fs::remove_file(output_path);
        }
        Ok(false)
    }
}

fn find_sing_box_binary() -> Option<PathBuf> {
    for candidate in [
        std::env::var_os("BULBASCAN_SING_BOX"),
        std::env::var_os("SING_BOX"),
    ]
    .into_iter()
    .flatten()
    {
        let path = PathBuf::from(candidate);
        if path.is_file() {
            return Some(path);
        }
    }

    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        for name in ["sing-box", "sing-box.exe"] {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    None
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

fn write_mihomo_rule_set(domains: &[String], output_path: &Path) -> anyhow::Result<()> {
    let mut content = String::new();
    for domain in domains {
        content.push_str(domain);
        content.push('\n');
    }
    std::fs::write(output_path, content)?;
    Ok(())
}

fn write_mihomo_provider_snippet(
    rule_set_path: &Path,
    output_path: &Path,
    format: &str,
) -> anyhow::Result<()> {
    let rule_set_filename = rule_set_path.file_name().map_or_else(
        || MIHOMO_RULE_SET_FILE.to_string(),
        |name| name.to_string_lossy().into_owned(),
    );
    let payload = format!(
        "payload:\n  - type: file\n    behavior: domain\n    format: {format}\n    path: {rule_set_filename}\n"
    );
    std::fs::write(output_path, payload)?;
    Ok(())
}

fn maybe_compile_mihomo_binary_rule_set(
    source_path: &Path,
    output_path: &Path,
) -> anyhow::Result<bool> {
    let Some(binary) = find_mihomo_binary() else {
        return Ok(false);
    };

    let status = Command::new(binary)
        .arg("convert-ruleset")
        .arg("domain")
        .arg("text")
        .arg(source_path)
        .arg(output_path)
        .status()?;

    if status.success() {
        Ok(true)
    } else {
        if output_path.exists() {
            let _ = std::fs::remove_file(output_path);
        }
        Ok(false)
    }
}

fn find_mihomo_binary() -> Option<PathBuf> {
    for candidate in [
        std::env::var_os("BULBASCAN_MIHOMO"),
        std::env::var_os("MIHOMO"),
    ]
    .into_iter()
    .flatten()
    {
        let path = PathBuf::from(candidate);
        if path.is_file() {
            return Some(path);
        }
    }

    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        for name in ["mihomo", "mihomo.exe", "clash-meta", "clash-meta.exe"] {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    None
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
        write_generic_apex_exports, write_mihomo_provider_snippet, write_router_exports,
        write_sing_box_route_snippet, write_split_router_exports, write_strict_router_exports,
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
        assert_eq!(written.len(), 7);

        let sing_box = std::fs::read_to_string(dir.join("json").join("sing-box.json")).unwrap();
        assert!(sing_box.contains("\"version\": 4"));
        assert!(sing_box.contains("\"claude.ai\""));
        assert!(!sing_box.contains("direct.example"));

        let sing_box_route =
            std::fs::read_to_string(dir.join("json").join("sing-box-route.json")).unwrap();
        assert!(sing_box_route.contains("\"action\": \"route\""));
        assert!(sing_box_route.contains("\"rule_set\": \"bulba-proxy-required\""));

        let xray = std::fs::read_to_string(dir.join("json").join("xray.json")).unwrap();
        assert!(xray.contains("\"full:claude.ai\""));
        assert!(!xray.contains("direct.example"));

        let mihomo = std::fs::read_to_string(dir.join("txt").join("mihomo.txt")).unwrap();
        assert!(mihomo.contains("claude.ai"));
        assert!(!mihomo.contains("direct.example"));

        let mihomo_provider =
            std::fs::read_to_string(dir.join("yaml").join("mihomo.yaml")).unwrap();
        assert!(mihomo_provider.contains("behavior: domain"));
        assert!(mihomo_provider.contains("format: text"));
        assert!(mihomo_provider.contains("path: mihomo.txt"));

        let openwrt_pbr = std::fs::read_to_string(dir.join("txt").join("openwrt.txt")).unwrap();
        assert!(openwrt_pbr.contains("claude.ai"));
        assert!(!openwrt_pbr.contains("direct.example"));

        let dnsmasq = std::fs::read_to_string(dir.join("txt").join("dnsmasq.conf")).unwrap();
        assert!(dnsmasq.contains("ipset=/claude.ai/bulba_proxy"));
        assert!(!dnsmasq.contains("direct.example"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn writes_binary_sing_box_route_snippet_when_requested() {
        let dir =
            std::env::temp_dir().join(format!("bulba-binary-route-snippet-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let rule_set_path = dir.join("test-rule-set.srs");
        std::fs::write(&rule_set_path, b"test").unwrap();
        let route_path = dir.join("test-route.json");

        write_sing_box_route_snippet(&rule_set_path, &route_path, "bulba-test", "binary").unwrap();

        let route = std::fs::read_to_string(&route_path).unwrap();
        assert!(route.contains("\"format\": \"binary\""));
        assert!(route.contains("\"path\": \"test-rule-set.srs\""));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn writes_mihomo_binary_provider_when_requested() {
        let dir =
            std::env::temp_dir().join(format!("bulba-mihomo-provider-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let rule_set_path = dir.join("test-rule-set.mrs");
        std::fs::write(&rule_set_path, b"test").unwrap();
        let provider_path = dir.join("test-provider.yaml");

        write_mihomo_provider_snippet(&rule_set_path, &provider_path, "mrs").unwrap();

        let provider = std::fs::read_to_string(&provider_path).unwrap();
        assert!(provider.contains("behavior: domain"));
        assert!(provider.contains("format: mrs"));
        assert!(provider.contains("path: test-rule-set.mrs"));

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
                local_confidence: 90,
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
                local_confidence: 65,
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
        assert_eq!(written.len(), 7);

        let sing_box = std::fs::read_to_string(dir.join("json").join("strict.json")).unwrap();
        assert!(sing_box.contains("\"claude.ai\""));
        assert!(!sing_box.contains("review.example"));

        let sing_box_route =
            std::fs::read_to_string(dir.join("json").join("strict-route.json")).unwrap();
        assert!(sing_box_route.contains("\"bulba-confirmed-proxy-required\""));

        let xray = std::fs::read_to_string(dir.join("json").join("strict-xray.json")).unwrap();
        assert!(xray.contains("\"full:claude.ai\""));
        assert!(xray.contains("bulbascan-confirmed-proxy-required"));
        assert!(!xray.contains("review.example"));

        let mihomo = std::fs::read_to_string(dir.join("txt").join("strict.txt")).unwrap();
        assert!(mihomo.contains("claude.ai"));
        assert!(!mihomo.contains("review.example"));

        let mihomo_provider =
            std::fs::read_to_string(dir.join("yaml").join("strict.yaml")).unwrap();
        assert!(mihomo_provider.contains("format: text"));
        assert!(mihomo_provider.contains("path: strict.txt"));

        let openwrt_pbr =
            std::fs::read_to_string(dir.join("txt").join("strict-openwrt.txt")).unwrap();
        assert!(openwrt_pbr.contains("claude.ai"));
        assert!(!openwrt_pbr.contains("review.example"));

        let dnsmasq = std::fs::read_to_string(dir.join("txt").join("strict-dnsmasq.conf")).unwrap();
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
        assert_eq!(written.len(), 7);

        let sing_box = std::fs::read_to_string(dir.join("json").join("apex.json")).unwrap();
        assert!(sing_box.contains("\"unknown.example\""));
        assert!(!sing_box.contains("claude.ai"));

        let mihomo = std::fs::read_to_string(dir.join("txt").join("apex.txt")).unwrap();
        assert!(mihomo.contains("unknown.example"));
        assert!(!mihomo.contains("claude.ai"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
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
                local_confidence: 90,
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
                local_confidence: 90,
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
                local_confidence: 95,
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
                local_confidence: 90,
                local_evidence: EvidenceBundle::default(),
                control_verdict: Verdict::Accessible,
                control_routing_decision: RoutingDecision::DirectOk,
                control_evidence: EvidenceBundle::default(),
                decision: ComparisonDecision::ConfirmedProxyRequired,
                local_network_evidence: NetworkEvidence::default(),
                control_network_evidence: NetworkEvidence::default(),
                network_notes: vec!["confirmed unmapped separation".into()],
                reason: "confirmed".into(),
            },
        ];
        let service_geo = vec![ServiceGeoSummary {
            service: "Anthropic".into(),
            decision: ServiceGeoDecision::ConfirmedGeoBlocked,
            confidence: 98,
            observed_roles: vec!["web".into(), "console".into(), "api".into()],
            missing_critical_roles: Vec::new(),
            confirmed_hosts: vec!["claude.ai".into(), "console.anthropic.com".into()],
            candidate_hosts: Vec::new(),
            review_assisted_hosts: Vec::new(),
            direct_hosts: vec!["api.anthropic.com".into()],
            reason: "confirmed".into(),
        }];

        let written = write_split_router_exports(&comparisons, &service_geo, &dir).unwrap();
        assert_eq!(written.len(), 14);

        let service_bundle = std::fs::read_to_string(dir.join("json").join("bundle.json")).unwrap();
        assert!(service_bundle.contains("\"claude.ai\""));
        assert!(service_bundle.contains("\"console.anthropic.com\""));
        assert!(service_bundle.contains("\"api.anthropic.com\""));
        assert!(!service_bundle.contains("unknown.example"));

        let generic = std::fs::read_to_string(dir.join("json").join("apex.json")).unwrap();
        assert!(generic.contains("\"unknown.example\""));
        assert!(!generic.contains("claude.ai"));

        let service_bundle_mihomo =
            std::fs::read_to_string(dir.join("txt").join("bundle.txt")).unwrap();
        assert!(service_bundle_mihomo.contains("claude.ai"));
        assert!(service_bundle_mihomo.contains("console.anthropic.com"));
        assert!(service_bundle_mihomo.contains("api.anthropic.com"));
        assert!(!service_bundle_mihomo.contains("unknown.example"));

        let generic_mihomo = std::fs::read_to_string(dir.join("txt").join("apex.txt")).unwrap();
        assert!(generic_mihomo.contains("unknown.example"));
        assert!(!generic_mihomo.contains("claude.ai"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn likely_service_summary_does_not_emit_bundle_exports() {
        let dir = std::env::temp_dir().join(format!(
            "bulba-likely-service-bundle-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let comparisons = vec![ComparisonResult {
            domain: "claude.ai".into(),
            service: Some("Anthropic".into()),
            service_role: Some("web".into()),
            local_verdict: Verdict::GeoBlocked,
            local_routing_decision: RoutingDecision::ProxyRequired,
            local_confidence: 90,
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
            decision: ServiceGeoDecision::LikelyGeoBlocked,
            confidence: 88,
            observed_roles: vec!["web".into()],
            missing_critical_roles: vec!["console".into(), "api".into()],
            confirmed_hosts: vec!["claude.ai".into()],
            candidate_hosts: Vec::new(),
            review_assisted_hosts: Vec::new(),
            direct_hosts: Vec::new(),
            reason: "likely".into(),
        }];

        let written = write_split_router_exports(&comparisons, &service_geo, &dir).unwrap();
        assert_eq!(written.len(), 14);

        let service_bundle = std::fs::read_to_string(dir.join("json").join("bundle.json")).unwrap();
        assert!(!service_bundle.contains("\"claude.ai\""));

        let service_bundle_mihomo =
            std::fs::read_to_string(dir.join("txt").join("bundle.txt")).unwrap();
        assert!(!service_bundle_mihomo.contains("claude.ai"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn apex_exports_exclude_unconfirmed_candidates_after_comparison() {
        let dir =
            std::env::temp_dir().join(format!("bulba-apex-confirmed-only-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let comparisons = vec![ComparisonResult {
            domain: "candidate-only.example".into(),
            service: None,
            service_role: None,
            local_verdict: Verdict::GeoBlocked,
            local_routing_decision: RoutingDecision::ProxyRequired,
            local_confidence: 82,
            local_evidence: EvidenceBundle::default(),
            control_verdict: Verdict::Accessible,
            control_routing_decision: RoutingDecision::DirectOk,
            control_evidence: EvidenceBundle::default(),
            decision: ComparisonDecision::CandidateProxyRequired,
            local_network_evidence: NetworkEvidence::default(),
            control_network_evidence: NetworkEvidence::default(),
            network_notes: Vec::new(),
            reason: "candidate".into(),
        }];
        let service_geo = Vec::new();

        write_split_router_exports(&comparisons, &service_geo, &dir).unwrap();

        let generic = std::fs::read_to_string(dir.join("json").join("apex.json")).unwrap();
        assert!(!generic.contains("candidate-only.example"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
