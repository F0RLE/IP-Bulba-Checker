use serde::Serialize;
use url::Url;

use crate::service_profiles;
use crate::signatures;

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainStatus {
    Ok,
    Blocked,
    Dead,
}

#[derive(Serialize, Clone)]
pub struct ScanResult {
    pub domain: String,
    pub service: Option<String>,
    pub service_role: Option<String>,
    pub evidence: EvidenceBundle,
    pub network_evidence: NetworkEvidence,
    pub status: DomainStatus,
    pub verdict: Verdict,
    pub routing_decision: RoutingDecision,
    pub confidence: u8,
    pub http_status: Option<u16>,
    pub reason: String,
    pub block_type: Option<signatures::BlockType>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanProfile {
    Safe,
    Aggressive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanPolicy {
    pub profile: ScanProfile,
    pub max_secondary_probes: usize,
    pub max_browser_probe_paths: usize,
    pub allow_control_browser_verify: bool,
    pub retest_attempts: usize,
    pub retest_backoff_ms: u64,
}

impl ScanPolicy {
    pub const fn safe() -> Self {
        Self {
            profile: ScanProfile::Safe,
            max_secondary_probes: 1,
            max_browser_probe_paths: 1,
            allow_control_browser_verify: false,
            retest_attempts: 1,
            retest_backoff_ms: 350,
        }
    }

    pub const fn aggressive() -> Self {
        Self {
            profile: ScanProfile::Aggressive,
            max_secondary_probes: usize::MAX,
            max_browser_probe_paths: usize::MAX,
            allow_control_browser_verify: true,
            retest_attempts: 2,
            retest_backoff_ms: 250,
        }
    }
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Accessible,
    GeoBlocked,
    WafBlocked,
    Captcha,
    RateLimited,
    ApiBlocked,
    NetworkBlocked,
    UnexpectedStatus,
    TlsFailure,
    Unreachable,
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RoutingDecision {
    ProxyRequired,
    DirectOk,
    ManualReview,
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonDecision {
    ConfirmedProxyRequired,
    CandidateProxyRequired,
    ConsistentBlocked,
    ConsistentDirect,
    NeedsReview,
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    Ok,
    Failed,
    Skipped,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct ProbeEvidence {
    pub status: ProbeStatus,
    pub detail: Option<String>,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct NetworkEvidence {
    pub dns: ProbeEvidence,
    pub path_dns: ProbeEvidence,
    pub tcp_443: ProbeEvidence,
    pub tls_443: ProbeEvidence,
    pub tcp_80: ProbeEvidence,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct EvidenceBundle {
    pub source: Option<String>,
    pub path: Option<String>,
    pub final_url: Option<String>,
    pub title: Option<String>,
    pub signal: Option<String>,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct ComparisonResult {
    pub domain: String,
    pub service: Option<String>,
    pub service_role: Option<String>,
    pub local_verdict: Verdict,
    pub local_routing_decision: RoutingDecision,
    pub local_evidence: EvidenceBundle,
    pub control_verdict: Verdict,
    pub control_routing_decision: RoutingDecision,
    pub control_evidence: EvidenceBundle,
    pub decision: ComparisonDecision,
    pub local_network_evidence: NetworkEvidence,
    pub control_network_evidence: NetworkEvidence,
    pub network_notes: Vec<String>,
    pub reason: String,
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServiceGeoDecision {
    ConfirmedGeoBlocked,
    LikelyGeoBlocked,
    DirectOk,
    Inconclusive,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct ServiceGeoSummary {
    pub service: String,
    pub decision: ServiceGeoDecision,
    pub confidence: u8,
    pub observed_roles: Vec<String>,
    pub missing_critical_roles: Vec<String>,
    pub confirmed_hosts: Vec<String>,
    pub candidate_hosts: Vec<String>,
    pub review_assisted_hosts: Vec<String>,
    pub direct_hosts: Vec<String>,
    pub reason: String,
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ControlProxyFailureKind {
    Ok,
    AuthFailed,
    ConnectFailed,
    Timeout,
    HttpOnly,
    UnknownFailure,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct ControlProxyCheck {
    pub target: String,
    pub kind: ControlProxyFailureKind,
    pub detail: String,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct ControlProxyHealth {
    pub proxy_url: String,
    pub healthy: bool,
    pub http_ok: bool,
    pub https_connect_ok: bool,
    pub http_check: ControlProxyCheck,
    pub https_example_check: ControlProxyCheck,
    pub https_trace_check: ControlProxyCheck,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Evidence {
    pub(crate) verdict: Verdict,
    pub(crate) reason: String,
    pub(crate) block_type: Option<signatures::BlockType>,
    pub(crate) confidence: u8,
}

impl ProbeEvidence {
    pub(crate) fn ok(detail: impl Into<String>) -> Self {
        Self {
            status: ProbeStatus::Ok,
            detail: Some(detail.into()),
        }
    }

    pub(crate) fn failed(detail: impl Into<String>) -> Self {
        Self {
            status: ProbeStatus::Failed,
            detail: Some(detail.into()),
        }
    }

    pub(crate) fn skipped(detail: impl Into<String>) -> Self {
        Self {
            status: ProbeStatus::Skipped,
            detail: Some(detail.into()),
        }
    }
}

impl Default for NetworkEvidence {
    fn default() -> Self {
        Self {
            dns: ProbeEvidence {
                status: ProbeStatus::Skipped,
                detail: None,
            },
            path_dns: ProbeEvidence {
                status: ProbeStatus::Skipped,
                detail: None,
            },
            tcp_443: ProbeEvidence {
                status: ProbeStatus::Skipped,
                detail: None,
            },
            tls_443: ProbeEvidence {
                status: ProbeStatus::Skipped,
                detail: None,
            },
            tcp_80: ProbeEvidence {
                status: ProbeStatus::Skipped,
                detail: None,
            },
        }
    }
}

pub(crate) fn verdict_label(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Accessible => "accessible",
        Verdict::GeoBlocked => "geo_blocked",
        Verdict::WafBlocked => "waf_blocked",
        Verdict::Captcha => "captcha",
        Verdict::RateLimited => "rate_limited",
        Verdict::ApiBlocked => "api_blocked",
        Verdict::NetworkBlocked => "network_blocked",
        Verdict::UnexpectedStatus => "unexpected_status",
        Verdict::TlsFailure => "tls_failure",
        Verdict::Unreachable => "unreachable",
    }
}

pub(crate) fn routing_decision_label(decision: RoutingDecision) -> &'static str {
    match decision {
        RoutingDecision::ProxyRequired => "proxy_required",
        RoutingDecision::DirectOk => "direct_ok",
        RoutingDecision::ManualReview => "manual_review",
    }
}

pub(crate) fn comparison_decision_label(decision: ComparisonDecision) -> &'static str {
    match decision {
        ComparisonDecision::ConfirmedProxyRequired => "confirmed_proxy_required",
        ComparisonDecision::CandidateProxyRequired => "candidate_proxy_required",
        ComparisonDecision::ConsistentBlocked => "consistent_blocked",
        ComparisonDecision::ConsistentDirect => "consistent_direct",
        ComparisonDecision::NeedsReview => "needs_review",
    }
}

pub(crate) fn service_geo_decision_label(decision: ServiceGeoDecision) -> &'static str {
    match decision {
        ServiceGeoDecision::ConfirmedGeoBlocked => "confirmed_geo_blocked",
        ServiceGeoDecision::LikelyGeoBlocked => "likely_geo_blocked",
        ServiceGeoDecision::DirectOk => "direct_ok",
        ServiceGeoDecision::Inconclusive => "inconclusive",
    }
}

pub(crate) fn control_proxy_failure_label(kind: ControlProxyFailureKind) -> &'static str {
    match kind {
        ControlProxyFailureKind::Ok => "ok",
        ControlProxyFailureKind::AuthFailed => "auth_failed",
        ControlProxyFailureKind::ConnectFailed => "connect_failed",
        ControlProxyFailureKind::Timeout => "timeout",
        ControlProxyFailureKind::HttpOnly => "http_only",
        ControlProxyFailureKind::UnknownFailure => "unknown_failure",
    }
}

pub(crate) fn probe_status_label(status: ProbeStatus) -> &'static str {
    match status {
        ProbeStatus::Ok => "ok",
        ProbeStatus::Failed => "failed",
        ProbeStatus::Skipped => "skipped",
    }
}

pub(crate) fn service_name_label(result: &ScanResult) -> String {
    result
        .service
        .clone()
        .unwrap_or_else(|| "unmapped".to_string())
}

pub(crate) fn service_context_label(result: &ScanResult) -> String {
    match (&result.service, &result.service_role) {
        (Some(service), Some(role)) => format!("{service}/{role}"),
        (Some(service), None) => service.clone(),
        _ => "unmapped".to_string(),
    }
}

pub(crate) fn network_summary(evidence: &NetworkEvidence) -> String {
    format!(
        "dns={} pathdns={} tcp443={} tls443={} tcp80={}",
        probe_status_label(evidence.dns.status),
        probe_status_label(evidence.path_dns.status),
        probe_status_label(evidence.tcp_443.status),
        probe_status_label(evidence.tls_443.status),
        probe_status_label(evidence.tcp_80.status)
    )
}

pub(crate) fn routing_decision_for(verdict: Verdict, confidence: u8) -> RoutingDecision {
    match verdict {
        Verdict::Accessible => RoutingDecision::DirectOk,
        Verdict::GeoBlocked | Verdict::ApiBlocked | Verdict::NetworkBlocked if confidence >= 80 => {
            RoutingDecision::ProxyRequired
        }
        Verdict::GeoBlocked
        | Verdict::ApiBlocked
        | Verdict::NetworkBlocked
        | Verdict::WafBlocked
        | Verdict::Captcha
        | Verdict::RateLimited
        | Verdict::UnexpectedStatus
        | Verdict::TlsFailure
        | Verdict::Unreachable => RoutingDecision::ManualReview,
    }
}

pub(crate) fn build_scan_result(
    domain: String,
    status: DomainStatus,
    verdict: Verdict,
    confidence: u8,
    http_status: Option<u16>,
    reason: String,
    block_type: Option<signatures::BlockType>,
) -> ScanResult {
    let service_match = service_profiles::match_target(&domain);
    ScanResult {
        domain,
        service: service_match.as_ref().map(|m| m.service_name.clone()),
        service_role: service_match.as_ref().map(|m| m.host_role.clone()),
        evidence: EvidenceBundle::default(),
        network_evidence: NetworkEvidence::default(),
        status,
        verdict,
        routing_decision: routing_decision_for(verdict, confidence),
        confidence,
        http_status,
        reason,
        block_type,
    }
}

pub(crate) fn with_evidence(mut result: ScanResult, evidence: EvidenceBundle) -> ScanResult {
    result.evidence = evidence;
    result
}

pub(crate) fn path_from_url_like(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    let path = parsed.path();
    if path.is_empty() || path == "/" {
        return Some("/".to_string());
    }
    Some(path.to_string())
}

pub(crate) fn evidence_summary(evidence: &EvidenceBundle) -> String {
    let mut parts = Vec::new();
    if let Some(source) = evidence.source.as_deref() {
        parts.push(format!("src={source}"));
    }
    if let Some(path) = evidence.path.as_deref() {
        parts.push(format!("path={path}"));
    }
    if let Some(signal) = evidence.signal.as_deref() {
        parts.push(format!("signal={signal}"));
    }
    if let Some(title) = evidence.title.as_deref() {
        parts.push(format!("title={title}"));
    }
    if let Some(final_url) = evidence.final_url.as_deref() {
        parts.push(format!("url={final_url}"));
    }
    parts.join(" | ")
}
