use super::analysis::{
    apply_dns_evidence_adjustment, choose_better_signal, classify_redirect, classify_status_code,
    classify_transport_error, is_block_status, is_transient_error, same_measurement,
    stabilize_scan_attempts,
    status_from_verdict,
};
use super::browser::browser_proxy_server_arg;
use super::comparison::{compare_result_pair, compare_with_control, summarize_service_geo};
use super::reports::{write_human_report, write_manual_review_hotspot_report};
use super::transport::{
    classify_control_proxy_error, evaluate_control_proxy_health, host_for_target,
};
use super::types::{
    ComparisonDecision, ComparisonResult, ControlProxyCheck, ControlProxyFailureKind,
    ControlProxyHealth, Evidence, EvidenceBundle, NetworkEvidence, ProbeEvidence, ProbeStatus,
    ScanProfile, ServiceGeoDecision, Verdict, routing_decision_for,
};
use super::{
    DomainStatus, RoutingDecision, ScanPolicy, ScanResult, TransportErrorKind, network_summary,
    should_run_control_comparison,
};
use crate::scanner::types::evidence_summary;
use crate::signatures::BlockType;
#[test]
fn classifies_connection_reset_as_network_block() {
    assert_eq!(
        classify_transport_error("Connection reset by peer"),
        TransportErrorKind::BlockedByNetwork
    );
}

#[test]
fn classifies_tls_failure_as_dead_not_blocked() {
    assert_eq!(
        classify_transport_error("TLS handshake failed"),
        TransportErrorKind::TlsFailure
    );
}

#[test]
fn only_high_signal_statuses_are_treated_as_blocked() {
    assert!(is_block_status(403));
    assert!(is_block_status(451));
    assert!(!is_block_status(401));
    assert!(!is_block_status(503));
}

#[test]
fn retries_only_transient_errors() {
    assert!(is_transient_error("operation timed out"));
    assert!(is_transient_error("dns lookup failed"));
    assert!(!is_transient_error("tls handshake failed"));
}

#[test]
fn picks_higher_confidence_signal() {
    let mut best = Some(Evidence {
        verdict: Verdict::WafBlocked,
        reason: "Header: sucuri".into(),
        block_type: Some(BlockType::Waf),
        confidence: 84,
    });

    choose_better_signal(
        &mut best,
        Evidence {
            verdict: Verdict::GeoBlocked,
            reason: "Match: not available in your region".into(),
            block_type: Some(BlockType::Geo),
            confidence: 93,
        },
    );

    assert_eq!(best.unwrap().verdict, Verdict::GeoBlocked);
}

#[test]
fn classifies_redirect_as_geo_or_captcha() {
    assert_eq!(
        classify_redirect("https://example.com/not-available")
            .unwrap()
            .verdict,
        Verdict::GeoBlocked
    );
    assert_eq!(
        classify_redirect("https://example.com/challenge")
            .unwrap()
            .verdict,
        Verdict::Captcha
    );
}

#[test]
fn classifies_high_signal_status_codes() {
    assert_eq!(
        classify_status_code(451).unwrap().verdict,
        Verdict::GeoBlocked
    );
    assert_eq!(
        classify_status_code(429).unwrap().verdict,
        Verdict::RateLimited
    );
    assert_eq!(classify_status_code(200), None);
}

#[test]
fn unexpected_status_is_not_marked_accessible() {
    assert_eq!(
        status_from_verdict(Verdict::UnexpectedStatus),
        DomainStatus::Blocked
    );
}

#[test]
fn geo_blocks_become_proxy_required() {
    assert_eq!(
        routing_decision_for(Verdict::GeoBlocked, 95),
        RoutingDecision::ProxyRequired
    );
}

#[test]
fn accessible_domains_stay_direct() {
    assert_eq!(
        routing_decision_for(Verdict::Accessible, 85),
        RoutingDecision::DirectOk
    );
}

#[test]
fn waf_blocks_require_manual_review() {
    assert_eq!(
        routing_decision_for(Verdict::WafBlocked, 97),
        RoutingDecision::ManualReview
    );
}

#[test]
fn extracts_host_from_url_target() {
    assert_eq!(
        host_for_target("https://platform.openai.com/login?x=1"),
        Some("platform.openai.com".to_string())
    );
}

#[test]
fn network_summary_formats_probe_states() {
    let evidence = NetworkEvidence {
        dns: ProbeEvidence::ok("1.1.1.1"),
        path_dns: ProbeEvidence::ok("1.1.1.1"),
        tcp_443: ProbeEvidence::ok("1.1.1.1:443"),
        tls_443: ProbeEvidence::failed("handshake"),
        tcp_80: ProbeEvidence {
            status: ProbeStatus::Skipped,
            detail: Some("not needed".to_string()),
        },
    };

    assert_eq!(
        network_summary(&evidence),
        "dns=ok pathdns=ok tcp443=ok tls443=failed tcp80=skipped"
    );
}

#[test]
fn evidence_summary_formats_human_readable_context() {
    let evidence = EvidenceBundle {
        source: Some("browser_dom".into()),
        path: Some("/login".into()),
        final_url: Some("https://example.com/login".into()),
        title: Some("App unavailable in region".into()),
        signal: Some("Browser DOM title".into()),
    };

    let summary = evidence_summary(&evidence);
    assert!(summary.contains("src=browser_dom"));
    assert!(summary.contains("path=/login"));
    assert!(summary.contains("title=App unavailable in region"));
}

#[test]
fn human_report_includes_manual_review_hotspot_summary() {
    let results = vec![
        ScanResult {
            domain: "challenge.example".into(),
            service: None,
            service_role: None,
            evidence: EvidenceBundle {
                source: Some("browser_dom".into()),
                path: Some("/".into()),
                final_url: None,
                title: Some("Just a moment".into()),
                signal: Some("Browser DOM: challenge page".into()),
            },
            network_evidence: NetworkEvidence::default(),
            status: DomainStatus::Blocked,
            verdict: Verdict::WafBlocked,
            routing_decision: RoutingDecision::ManualReview,
            confidence: 97,
            http_status: Some(403),
            reason: "Browser /: Browser DOM: challenge page".into(),
            block_type: Some(BlockType::Waf),
        },
        ScanResult {
            domain: "ok.example".into(),
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

    let report_path = std::env::temp_dir().join("bulbascan-human-report-hotspots-test.txt");
    write_human_report(&results, &report_path).unwrap();
    let report = std::fs::read_to_string(&report_path).unwrap();
    let _ = std::fs::remove_file(report_path);

    assert!(report.contains("Manual Review hotspots"));
    assert!(report.contains("captcha_or_challenge: 1"));
}

#[test]
fn manual_review_hotspot_report_distinguishes_control_ambiguity_and_transport_noise() {
    let results = vec![
        ScanResult {
            domain: "weak-control.example".into(),
            service: None,
            service_role: None,
            evidence: EvidenceBundle::default(),
            network_evidence: NetworkEvidence::default(),
            status: DomainStatus::Blocked,
            verdict: Verdict::GeoBlocked,
            routing_decision: RoutingDecision::ManualReview,
            confidence: 78,
            http_status: Some(451),
            reason: "geo blocked".into(),
            block_type: Some(BlockType::Geo),
        },
        ScanResult {
            domain: "worker-error.example".into(),
            service: None,
            service_role: None,
            evidence: EvidenceBundle {
                source: Some("scanner".into()),
                path: Some("/".into()),
                final_url: None,
                title: None,
                signal: Some("worker error".into()),
            },
            network_evidence: NetworkEvidence {
                dns: ProbeEvidence::failed("lookup failed"),
                ..NetworkEvidence::default()
            },
            status: DomainStatus::Dead,
            verdict: Verdict::Unreachable,
            routing_decision: RoutingDecision::ManualReview,
            confidence: 40,
            http_status: None,
            reason: "Error: worker error".into(),
            block_type: None,
        },
    ];

    let comparisons = vec![ComparisonResult {
        domain: "weak-control.example".into(),
        service: None,
        service_role: None,
        local_verdict: Verdict::GeoBlocked,
        local_routing_decision: RoutingDecision::ManualReview,
        local_confidence: 78,
        local_evidence: EvidenceBundle::default(),
        control_verdict: Verdict::Accessible,
        control_routing_decision: RoutingDecision::DirectOk,
        control_evidence: EvidenceBundle::default(),
        decision: ComparisonDecision::NeedsReview,
        local_network_evidence: NetworkEvidence::default(),
        control_network_evidence: NetworkEvidence::default(),
        network_notes: vec!["control direct signal is weak: verdict=accessible confidence=65".into()],
        reason: "local route=manual_review but control direct evidence is too weak to promote confidently".into(),
    }];

    let report_path = std::env::temp_dir().join("bulbascan-manual-review-hotspots-test.txt");
    write_manual_review_hotspot_report(&results, Some(&comparisons), None, &report_path).unwrap();
    let report = std::fs::read_to_string(&report_path).unwrap();
    let _ = std::fs::remove_file(report_path);

    assert!(report.contains("control_path_ambiguity: 1"));
    assert!(report.contains("transport_failure: 1"));
}

#[test]
fn control_accessible_confirms_proxy_required() {
    let local = ScanResult {
        domain: "example.com".into(),
        service: Some("Example".into()),
        service_role: Some("web".into()),
        evidence: EvidenceBundle::default(),
        network_evidence: NetworkEvidence::default(),
        status: DomainStatus::Blocked,
        verdict: Verdict::GeoBlocked,
        routing_decision: RoutingDecision::ProxyRequired,
        confidence: 95,
        http_status: Some(451),
        reason: "HTTP 451".into(),
        block_type: Some(BlockType::Geo),
    };
    let control = ScanResult {
        domain: "example.com".into(),
        service: Some("Example".into()),
        service_role: Some("web".into()),
        evidence: EvidenceBundle::default(),
        network_evidence: NetworkEvidence::default(),
        status: DomainStatus::Ok,
        verdict: Verdict::Accessible,
        routing_decision: RoutingDecision::DirectOk,
        confidence: 85,
        http_status: Some(200),
        reason: "OK".into(),
        block_type: None,
    };

    let comparisons = compare_with_control(&[local], &[control]);
    assert_eq!(
        comparisons[0].decision,
        ComparisonDecision::ConfirmedProxyRequired
    );
    assert_eq!(comparisons[0].local_evidence, EvidenceBundle::default());
    assert_eq!(comparisons[0].control_evidence, EvidenceBundle::default());
}

#[test]
fn both_direct_paths_are_consistent_direct() {
    let local = ScanResult {
        domain: "example.com".into(),
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
    };
    let control = ScanResult {
        domain: "example.com".into(),
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
    };

    let comparisons = compare_with_control(&[local], &[control]);
    assert_eq!(
        comparisons[0].decision,
        ComparisonDecision::ConsistentDirect
    );
}

#[test]
fn weak_control_direct_signal_stays_needs_review() {
    let local = ScanResult {
        domain: "example.com".into(),
        service: None,
        service_role: None,
        evidence: EvidenceBundle::default(),
        network_evidence: NetworkEvidence::default(),
        status: DomainStatus::Blocked,
        verdict: Verdict::GeoBlocked,
        routing_decision: RoutingDecision::ProxyRequired,
        confidence: 95,
        http_status: Some(451),
        reason: "blocked".into(),
        block_type: Some(BlockType::Geo),
    };
    let control = ScanResult {
        domain: "example.com".into(),
        service: None,
        service_role: None,
        evidence: EvidenceBundle::default(),
        network_evidence: NetworkEvidence::default(),
        status: DomainStatus::Ok,
        verdict: Verdict::Accessible,
        routing_decision: RoutingDecision::DirectOk,
        confidence: 65,
        http_status: Some(200),
        reason: "weak ok".into(),
        block_type: None,
    };

    let comparison = compare_result_pair(&local, &control);
    assert_eq!(comparison.decision, ComparisonDecision::NeedsReview);
    assert!(comparison
        .reason
        .contains("control direct evidence is too weak"));
    assert!(comparison
        .network_notes
        .iter()
        .any(|note| note.contains("control direct signal is weak")));
}

#[test]
fn weak_control_blocked_signal_does_not_force_consistent_blocked() {
    let local = ScanResult {
        domain: "example.com".into(),
        service: None,
        service_role: None,
        evidence: EvidenceBundle::default(),
        network_evidence: NetworkEvidence::default(),
        status: DomainStatus::Blocked,
        verdict: Verdict::NetworkBlocked,
        routing_decision: RoutingDecision::ProxyRequired,
        confidence: 93,
        http_status: None,
        reason: "network".into(),
        block_type: None,
    };
    let control = ScanResult {
        domain: "example.com".into(),
        service: None,
        service_role: None,
        evidence: EvidenceBundle::default(),
        network_evidence: NetworkEvidence::default(),
        status: DomainStatus::Blocked,
        verdict: Verdict::Captcha,
        routing_decision: RoutingDecision::ManualReview,
        confidence: 92,
        http_status: Some(403),
        reason: "captcha".into(),
        block_type: None,
    };

    let comparison = compare_result_pair(&local, &control);
    assert_eq!(comparison.decision, ComparisonDecision::NeedsReview);
    assert!(comparison
        .reason
        .contains("control is too weak to confirm a shared blocked outcome"));
    assert!(comparison
        .network_notes
        .iter()
        .any(|note| note.contains("control path is too weak")));
}

#[test]
fn strong_control_blocked_signal_can_stay_consistent_blocked() {
    let local = ScanResult {
        domain: "example.com".into(),
        service: None,
        service_role: None,
        evidence: EvidenceBundle::default(),
        network_evidence: NetworkEvidence {
            dns: ProbeEvidence::ok("203.0.113.10"),
            path_dns: ProbeEvidence::ok("203.0.113.10"),
            tcp_443: ProbeEvidence::failed("connect failed"),
            tls_443: ProbeEvidence::skipped("tcp/443 failed"),
            tcp_80: ProbeEvidence::failed("connect failed"),
        },
        status: DomainStatus::Dead,
        verdict: Verdict::NetworkBlocked,
        routing_decision: RoutingDecision::ProxyRequired,
        confidence: 93,
        http_status: None,
        reason: "network".into(),
        block_type: None,
    };
    let control = ScanResult {
        domain: "example.com".into(),
        service: None,
        service_role: None,
        evidence: EvidenceBundle::default(),
        network_evidence: NetworkEvidence {
            dns: ProbeEvidence::skipped("proxy mode"),
            path_dns: ProbeEvidence::ok("198.51.100.10"),
            tcp_443: ProbeEvidence::failed("connect failed"),
            tls_443: ProbeEvidence::failed("handshake failed"),
            tcp_80: ProbeEvidence::failed("connect failed"),
        },
        status: DomainStatus::Dead,
        verdict: Verdict::NetworkBlocked,
        routing_decision: RoutingDecision::ProxyRequired,
        confidence: 90,
        http_status: None,
        reason: "network".into(),
        block_type: None,
    };

    let comparison = compare_result_pair(&local, &control);
    assert_eq!(comparison.decision, ComparisonDecision::ConsistentBlocked);
}

#[test]
fn comparison_captures_network_notes_when_control_path_resolves() {
    let local = ScanResult {
        domain: "example.com".into(),
        service: None,
        service_role: None,
        evidence: EvidenceBundle::default(),
        network_evidence: NetworkEvidence {
            dns: ProbeEvidence::failed("dns failed"),
            path_dns: ProbeEvidence::ok("198.51.100.10"),
            tcp_443: ProbeEvidence::skipped("dns failed"),
            tls_443: ProbeEvidence::skipped("dns failed"),
            tcp_80: ProbeEvidence::skipped("dns failed"),
        },
        status: DomainStatus::Dead,
        verdict: Verdict::Unreachable,
        routing_decision: RoutingDecision::ManualReview,
        confidence: 80,
        http_status: None,
        reason: "unreachable".into(),
        block_type: None,
    };
    let control = ScanResult {
        domain: "example.com".into(),
        service: None,
        service_role: None,
        evidence: EvidenceBundle::default(),
        network_evidence: NetworkEvidence {
            dns: ProbeEvidence::skipped("proxy mode"),
            path_dns: ProbeEvidence::ok("203.0.113.20"),
            tcp_443: ProbeEvidence::skipped("proxy mode"),
            tls_443: ProbeEvidence::skipped("proxy mode"),
            tcp_80: ProbeEvidence::skipped("proxy mode"),
        },
        status: DomainStatus::Ok,
        verdict: Verdict::Accessible,
        routing_decision: RoutingDecision::DirectOk,
        confidence: 85,
        http_status: Some(200),
        reason: "OK".into(),
        block_type: None,
    };

    let comparison = compare_result_pair(&local, &control);
    assert!(
        comparison
            .network_notes
            .iter()
            .any(|note| note.contains("local system DNS failed") || note.contains("local DNS manipulation suspected"))
    );
    assert!(
        comparison
            .network_notes
            .iter()
            .any(|note| note.contains("DNS mismatch"))
    );
}

#[test]
fn comparison_distinguishes_dns_manipulation_from_unhealthy_resolver() {
    let base_control = ScanResult {
        domain: "example.com".into(),
        service: None,
        service_role: None,
        evidence: EvidenceBundle::default(),
        network_evidence: NetworkEvidence {
            dns: ProbeEvidence::skipped("proxy mode"),
            path_dns: ProbeEvidence::ok("198.51.100.20"),
            tcp_443: ProbeEvidence::skipped("proxy mode"),
            tls_443: ProbeEvidence::skipped("proxy mode"),
            tcp_80: ProbeEvidence::skipped("proxy mode"),
        },
        status: DomainStatus::Ok,
        verdict: Verdict::Accessible,
        routing_decision: RoutingDecision::DirectOk,
        confidence: 85,
        http_status: Some(200),
        reason: "OK".into(),
        block_type: None,
    };

    let manipulation_local = ScanResult {
        domain: "example.com".into(),
        service: None,
        service_role: None,
        evidence: EvidenceBundle::default(),
        network_evidence: NetworkEvidence {
            dns: ProbeEvidence::failed("kind=nxdomain resolver_control_ok: no such domain"),
            path_dns: ProbeEvidence::ok("203.0.113.10"),
            tcp_443: ProbeEvidence::failed("connect failed"),
            tls_443: ProbeEvidence::skipped("tcp/443 failed"),
            tcp_80: ProbeEvidence::failed("connect failed"),
        },
        status: DomainStatus::Dead,
        verdict: Verdict::NetworkBlocked,
        routing_decision: RoutingDecision::ProxyRequired,
        confidence: 92,
        http_status: None,
        reason: "dns".into(),
        block_type: None,
    };

    let unhealthy_local = ScanResult {
        network_evidence: NetworkEvidence {
            dns: ProbeEvidence::failed("kind=servfail resolver_control_servfail: upstream failure"),
            ..manipulation_local.network_evidence.clone()
        },
        ..manipulation_local.clone()
    };

    let manipulation = compare_result_pair(&manipulation_local, &base_control);
    assert!(manipulation
        .network_notes
        .iter()
        .any(|note| note.contains("local DNS manipulation suspected")));

    let unhealthy = compare_result_pair(&unhealthy_local, &base_control);
    assert!(unhealthy
        .network_notes
        .iter()
        .any(|note| note.contains("local resolver appears unhealthy")));
}

#[test]
fn comparison_report_summarizes_dns_signal_buckets() {
    let comparisons = vec![ComparisonResult {
        domain: "example.com".into(),
        service: None,
        service_role: None,
        local_verdict: Verdict::NetworkBlocked,
        local_routing_decision: RoutingDecision::ProxyRequired,
        local_confidence: 92,
        local_evidence: EvidenceBundle::default(),
        control_verdict: Verdict::Accessible,
        control_routing_decision: RoutingDecision::DirectOk,
        control_evidence: EvidenceBundle::default(),
        decision: ComparisonDecision::ConfirmedProxyRequired,
        local_network_evidence: NetworkEvidence::default(),
        control_network_evidence: NetworkEvidence::default(),
        network_notes: vec![
            "local DNS manipulation suspected: system resolver returned nxdomain while control path DNS resolved".into(),
            "DNS mismatch confirmed by failed direct tcp/tls: local=203.0.113.10 control=198.51.100.20".into(),
        ],
        reason: "comparison".into(),
    }];

    let report_path = std::env::temp_dir().join("bulbascan-comparison-report-test.txt");
    super::comparison::write_control_comparison_report(&comparisons, &report_path).unwrap();
    let report = std::fs::read_to_string(&report_path).unwrap();
    let _ = std::fs::remove_file(report_path);

    assert!(report.contains("DNS signals"));
    assert!(report.contains("dns_manipulation_suspected: 1"));
    assert!(report.contains("dns_mismatch_confirmed: 1"));
}

#[test]
fn weak_control_needs_review_is_labeled_as_control_path_ambiguity() {
    let local = ScanResult {
        domain: "example.com".into(),
        service: None,
        service_role: None,
        evidence: EvidenceBundle::default(),
        network_evidence: NetworkEvidence::default(),
        status: DomainStatus::Blocked,
        verdict: Verdict::GeoBlocked,
        routing_decision: RoutingDecision::ProxyRequired,
        confidence: 94,
        http_status: Some(451),
        reason: "geo".into(),
        block_type: Some(BlockType::Geo),
    };
    let control = ScanResult {
        domain: "example.com".into(),
        service: None,
        service_role: None,
        evidence: EvidenceBundle::default(),
        network_evidence: NetworkEvidence::default(),
        status: DomainStatus::Ok,
        verdict: Verdict::Accessible,
        routing_decision: RoutingDecision::DirectOk,
        confidence: 65,
        http_status: Some(200),
        reason: "ok".into(),
        block_type: None,
    };

    let comparison = compare_result_pair(&local, &control);
    assert_eq!(comparison.decision, ComparisonDecision::NeedsReview);
    assert!(comparison.reason.starts_with("control-path ambiguity:"));
}

#[test]
fn worker_error_needs_review_is_labeled_as_transport_ambiguity() {
    let local = ScanResult {
        domain: "example.com".into(),
        service: None,
        service_role: None,
        evidence: EvidenceBundle {
            source: Some("scanner".into()),
            path: Some("/".into()),
            final_url: None,
            title: None,
            signal: Some("worker error".into()),
        },
        network_evidence: NetworkEvidence {
            dns: ProbeEvidence::failed("lookup failed"),
            path_dns: ProbeEvidence::failed("doh failed"),
            tcp_443: ProbeEvidence::skipped("dns failed"),
            tls_443: ProbeEvidence::skipped("dns failed"),
            tcp_80: ProbeEvidence::skipped("dns failed"),
        },
        status: DomainStatus::Dead,
        verdict: Verdict::Unreachable,
        routing_decision: RoutingDecision::ManualReview,
        confidence: 40,
        http_status: None,
        reason: "Error: worker error".into(),
        block_type: None,
    };
    let control = ScanResult {
        domain: "example.com".into(),
        service: None,
        service_role: None,
        evidence: EvidenceBundle {
            source: Some("transport".into()),
            path: Some("/".into()),
            final_url: None,
            title: None,
            signal: Some("timeout".into()),
        },
        network_evidence: NetworkEvidence {
            dns: ProbeEvidence::skipped("proxy mode"),
            path_dns: ProbeEvidence::failed("connect failed"),
            tcp_443: ProbeEvidence::skipped("proxy mode"),
            tls_443: ProbeEvidence::skipped("proxy mode"),
            tcp_80: ProbeEvidence::skipped("proxy mode"),
        },
        status: DomainStatus::Dead,
        verdict: Verdict::Unreachable,
        routing_decision: RoutingDecision::ManualReview,
        confidence: 58,
        http_status: None,
        reason: "timeout".into(),
        block_type: None,
    };

    let comparison = compare_result_pair(&local, &control);
    assert_eq!(comparison.decision, ComparisonDecision::NeedsReview);
    assert!(comparison.reason.starts_with("transport ambiguity:"));
}

#[test]
fn comparison_report_summarizes_needs_review_breakdown() {
    let comparisons = vec![
        ComparisonResult {
            domain: "control.example".into(),
            service: None,
            service_role: None,
            local_verdict: Verdict::GeoBlocked,
            local_routing_decision: RoutingDecision::ManualReview,
            local_confidence: 75,
            local_evidence: EvidenceBundle::default(),
            control_verdict: Verdict::Accessible,
            control_routing_decision: RoutingDecision::DirectOk,
            control_evidence: EvidenceBundle::default(),
            decision: ComparisonDecision::NeedsReview,
            local_network_evidence: NetworkEvidence::default(),
            control_network_evidence: NetworkEvidence::default(),
            network_notes: vec!["control direct signal is weak: verdict=accessible confidence=65".into()],
            reason: "control-path ambiguity: control side is too weak to separate local blocking from broader failure".into(),
        },
        ComparisonResult {
            domain: "transport.example".into(),
            service: None,
            service_role: None,
            local_verdict: Verdict::Unreachable,
            local_routing_decision: RoutingDecision::ManualReview,
            local_confidence: 40,
            local_evidence: EvidenceBundle::default(),
            control_verdict: Verdict::Unreachable,
            control_routing_decision: RoutingDecision::ManualReview,
            control_evidence: EvidenceBundle::default(),
            decision: ComparisonDecision::NeedsReview,
            local_network_evidence: NetworkEvidence::default(),
            control_network_evidence: NetworkEvidence::default(),
            network_notes: Vec::new(),
            reason: "transport ambiguity: both local and control paths are too noisy to classify confidently".into(),
        },
    ];

    let report_path = std::env::temp_dir().join("bulbascan-comparison-needs-review-breakdown.txt");
    super::comparison::write_control_comparison_report(&comparisons, &report_path).unwrap();
    let report = std::fs::read_to_string(&report_path).unwrap();
    let _ = std::fs::remove_file(report_path);

    assert!(report.contains("Needs review breakdown"));
    assert!(report.contains("control_path_ambiguity: 1"));
    assert!(report.contains("transport_ambiguity: 1"));
}

#[test]
fn comparison_preserves_side_specific_evidence() {
    let local = ScanResult {
        domain: "example.com".into(),
        service: Some("Example".into()),
        service_role: Some("web".into()),
        evidence: EvidenceBundle {
            source: Some("browser_dom".into()),
            path: Some("/login".into()),
            final_url: Some("https://example.com/login".into()),
            title: Some("Blocked".into()),
            signal: Some("DOM title".into()),
        },
        network_evidence: NetworkEvidence::default(),
        status: DomainStatus::Blocked,
        verdict: Verdict::GeoBlocked,
        routing_decision: RoutingDecision::ProxyRequired,
        confidence: 95,
        http_status: Some(451),
        reason: "blocked".into(),
        block_type: Some(BlockType::Geo),
    };
    let control = ScanResult {
        domain: "example.com".into(),
        service: Some("Example".into()),
        service_role: Some("web".into()),
        evidence: EvidenceBundle {
            source: Some("http_body".into()),
            path: Some("/".into()),
            final_url: Some("https://example.com/".into()),
            title: None,
            signal: Some("No block marker".into()),
        },
        network_evidence: NetworkEvidence::default(),
        status: DomainStatus::Ok,
        verdict: Verdict::Accessible,
        routing_decision: RoutingDecision::DirectOk,
        confidence: 85,
        http_status: Some(200),
        reason: "ok".into(),
        block_type: None,
    };

    let comparison = compare_result_pair(&local, &control);
    assert_eq!(
        comparison.local_evidence.source.as_deref(),
        Some("browser_dom")
    );
    assert_eq!(comparison.local_evidence.path.as_deref(), Some("/login"));
    assert_eq!(
        comparison.control_evidence.source.as_deref(),
        Some("http_body")
    );
    assert_eq!(comparison.control_evidence.path.as_deref(), Some("/"));
}

#[test]
fn dns_failure_with_working_doh_escalates_to_network_blocked() {
    let result = ScanResult {
        domain: "example.com".into(),
        service: None,
        service_role: None,
        evidence: EvidenceBundle::default(),
        network_evidence: NetworkEvidence::default(),
        status: DomainStatus::Dead,
        verdict: Verdict::Unreachable,
        routing_decision: RoutingDecision::ManualReview,
        confidence: 55,
        http_status: None,
        reason: "dns lookup failed".into(),
        block_type: None,
    };

    let adjusted = apply_dns_evidence_adjustment(
        result,
        &NetworkEvidence {
            dns: ProbeEvidence::failed("kind=nxdomain resolver_control_ok: no such domain"),
            path_dns: ProbeEvidence::ok("1.1.1.1, 1.0.0.1"),
            tcp_443: ProbeEvidence::skipped("dns failed"),
            tls_443: ProbeEvidence::skipped("dns failed"),
            tcp_80: ProbeEvidence::skipped("dns failed"),
        },
    );

    assert_eq!(adjusted.verdict, Verdict::NetworkBlocked);
    assert_eq!(adjusted.routing_decision, RoutingDecision::ProxyRequired);
    assert!(adjusted.reason.contains("system DNS nxdomain while DoH resolved"));
}

#[test]
fn dns_mismatch_is_recorded_without_overriding_accessible_result() {
    let result = ScanResult {
        domain: "example.com".into(),
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
    };

    let adjusted = apply_dns_evidence_adjustment(
        result,
        &NetworkEvidence {
            dns: ProbeEvidence::ok("203.0.113.10, 203.0.113.11"),
            path_dns: ProbeEvidence::ok("198.51.100.10, 198.51.100.11"),
            tcp_443: ProbeEvidence::ok("203.0.113.10:443"),
            tls_443: ProbeEvidence::ok("203.0.113.10:443 cert=abcd"),
            tcp_80: ProbeEvidence::ok("203.0.113.10:80"),
        },
    );

    assert_eq!(adjusted.verdict, Verdict::Accessible);
    assert_eq!(adjusted.routing_decision, RoutingDecision::DirectOk);
    assert!(adjusted.reason.contains("system DNS differs from DoH"));
}

#[test]
fn dns_mismatch_with_failed_direct_tcp_tls_escalates_to_network_blocked() {
    let result = ScanResult {
        domain: "example.com".into(),
        service: None,
        service_role: None,
        evidence: EvidenceBundle::default(),
        network_evidence: NetworkEvidence::default(),
        status: DomainStatus::Dead,
        verdict: Verdict::Unreachable,
        routing_decision: RoutingDecision::ManualReview,
        confidence: 55,
        http_status: None,
        reason: "connect failed".into(),
        block_type: None,
    };

    let adjusted = apply_dns_evidence_adjustment(
        result,
        &NetworkEvidence {
            dns: ProbeEvidence::ok("203.0.113.10, 203.0.113.11"),
            path_dns: ProbeEvidence::ok("198.51.100.10, 198.51.100.11"),
            tcp_443: ProbeEvidence::failed("connect failed"),
            tls_443: ProbeEvidence::skipped("tcp/443 failed"),
            tcp_80: ProbeEvidence::failed("connect failed"),
        },
    );

    assert_eq!(adjusted.verdict, Verdict::NetworkBlocked);
    assert_eq!(adjusted.routing_decision, RoutingDecision::ProxyRequired);
    assert!(adjusted.reason.contains("system DNS differs from DoH"));
    assert!(adjusted.reason.contains("failed on direct TCP/TLS probes"));
}

#[test]
fn stable_retest_keeps_verdict_and_marks_reason() {
    let first = ScanResult {
        domain: "example.com".into(),
        service: None,
        service_role: None,
        evidence: EvidenceBundle::default(),
        network_evidence: NetworkEvidence::default(),
        status: DomainStatus::Blocked,
        verdict: Verdict::GeoBlocked,
        routing_decision: RoutingDecision::ProxyRequired,
        confidence: 90,
        http_status: Some(451),
        reason: "HTTP 451".into(),
        block_type: Some(BlockType::Geo),
    };
    let mut second = first.clone();
    second.confidence = 92;

    assert!(same_measurement(&first, &second));
    let stabilized = stabilize_scan_attempts(vec![first, second]);
    assert_eq!(stabilized.verdict, Verdict::GeoBlocked);
    assert_eq!(stabilized.routing_decision, RoutingDecision::ProxyRequired);
    assert!(stabilized.reason.contains("retest=stable"));
    assert!(stabilized.confidence >= 95);
}

#[test]
fn unstable_retest_downgrades_to_manual_review() {
    let blocked = ScanResult {
        domain: "example.com".into(),
        service: None,
        service_role: None,
        evidence: EvidenceBundle::default(),
        network_evidence: NetworkEvidence::default(),
        status: DomainStatus::Blocked,
        verdict: Verdict::GeoBlocked,
        routing_decision: RoutingDecision::ProxyRequired,
        confidence: 94,
        http_status: Some(451),
        reason: "HTTP 451".into(),
        block_type: Some(BlockType::Geo),
    };
    let accessible = ScanResult {
        domain: "example.com".into(),
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
    };

    let stabilized = stabilize_scan_attempts(vec![blocked, accessible]);
    assert_eq!(stabilized.verdict, Verdict::GeoBlocked);
    assert_eq!(stabilized.routing_decision, RoutingDecision::ManualReview);
    assert!(stabilized.reason.contains("retest=unstable"));
}

#[test]
fn healthy_control_proxy_requires_http_and_https_connect() {
    let http = ControlProxyCheck {
        target: "http://example.com/".into(),
        kind: ControlProxyFailureKind::Ok,
        detail: "HTTP 200".into(),
    };
    let https_example = ControlProxyCheck {
        target: "https://example.com/".into(),
        kind: ControlProxyFailureKind::ConnectFailed,
        detail: "connect failed".into(),
    };
    let https_trace = ControlProxyCheck {
        target: "https://cloudflare.com/cdn-cgi/trace".into(),
        kind: ControlProxyFailureKind::Ok,
        detail: "HTTP 200".into(),
    };

    let (healthy, http_ok, https_connect_ok, _) =
        evaluate_control_proxy_health(&http, &https_example, &https_trace);
    assert!(healthy);
    assert!(http_ok);
    assert!(https_connect_ok);
}

#[test]
fn failed_https_connect_marks_proxy_unhealthy_even_if_http_works() {
    let http = ControlProxyCheck {
        target: "http://example.com/".into(),
        kind: ControlProxyFailureKind::Ok,
        detail: "HTTP 200".into(),
    };
    let https_example = ControlProxyCheck {
        target: "https://example.com/".into(),
        kind: ControlProxyFailureKind::HttpOnly,
        detail: "connect failed".into(),
    };
    let https_trace = ControlProxyCheck {
        target: "https://cloudflare.com/cdn-cgi/trace".into(),
        kind: ControlProxyFailureKind::ConnectFailed,
        detail: "connect failed".into(),
    };

    let (healthy, http_ok, https_connect_ok, _) =
        evaluate_control_proxy_health(&http, &https_example, &https_trace);
    assert!(!healthy);
    assert!(http_ok);
    assert!(!https_connect_ok);
}

#[test]
fn http_only_is_detected_for_https_after_plain_http_success() {
    assert_eq!(
        classify_control_proxy_error("proxy connect aborted", true, true),
        ControlProxyFailureKind::HttpOnly
    );
}

#[test]
fn unhealthy_control_proxy_suppresses_comparison_stage() {
    let health = ControlProxyHealth {
        proxy_url: "http://31.169.127.120:14010".into(),
        healthy: false,
        http_ok: true,
        https_connect_ok: false,
        http_check: ControlProxyCheck {
            target: "http://example.com/".into(),
            kind: ControlProxyFailureKind::Ok,
            detail: "HTTP 200".into(),
        },
        https_example_check: ControlProxyCheck {
            target: "https://example.com/".into(),
            kind: ControlProxyFailureKind::HttpOnly,
            detail: "connect failed".into(),
        },
        https_trace_check: ControlProxyCheck {
            target: "https://cloudflare.com/cdn-cgi/trace".into(),
            kind: ControlProxyFailureKind::ConnectFailed,
            detail: "connect failed".into(),
        },
        notes: vec!["HTTPS CONNECT preflight failed".into()],
    };

    assert!(!should_run_control_comparison(&health));
}

#[test]
fn multiple_confirmed_critical_hosts_confirm_service_geo_block() {
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
            reason: "local geo_blocked but control is direct_ok".into(),
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
            reason: "local geo_blocked but control is direct_ok".into(),
        },
    ];

    let summaries = summarize_service_geo(&comparisons);
    assert_eq!(summaries.len(), 1);
    assert_eq!(
        summaries[0].decision,
        ServiceGeoDecision::ConfirmedGeoBlocked
    );
}

#[test]
fn multiple_candidates_make_service_likely_geo_blocked() {
    let comparisons = vec![
        ComparisonResult {
            domain: "api.example.com".into(),
            service: Some("Example".into()),
            service_role: Some("api".into()),
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
        ComparisonResult {
            domain: "web.example.com".into(),
            service: Some("Example".into()),
            service_role: Some("auth".into()),
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

    let summaries = summarize_service_geo(&comparisons);
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].decision, ServiceGeoDecision::LikelyGeoBlocked);
}

#[test]
fn all_direct_hosts_keep_service_direct() {
    let comparisons = vec![
        ComparisonResult {
            domain: "chat.example.com".into(),
            service: Some("Example".into()),
            service_role: Some("web".into()),
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
            domain: "auth.example.com".into(),
            service: Some("Example".into()),
            service_role: Some("auth".into()),
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
    ];

    let summaries = summarize_service_geo(&comparisons);
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].decision, ServiceGeoDecision::DirectOk);
}

#[test]
fn known_service_with_missing_critical_roles_stays_inconclusive() {
    let comparisons = vec![ComparisonResult {
        domain: "chatgpt.com".into(),
        service: Some("OpenAI".into()),
        service_role: Some("web".into()),
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
    }];

    let summaries = summarize_service_geo(&comparisons);
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].decision, ServiceGeoDecision::Inconclusive);
    assert!(
        summaries[0]
            .missing_critical_roles
            .iter()
            .any(|role| role == "auth")
    );
}

#[test]
fn single_confirmed_known_role_is_only_likely_when_bundle_is_incomplete() {
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

    let summaries = summarize_service_geo(&comparisons);
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].decision, ServiceGeoDecision::LikelyGeoBlocked);
}

#[test]
fn review_assisted_critical_role_can_make_service_likely_geo_blocked() {
    let comparisons = vec![
        ComparisonResult {
            domain: "listen.tidal.com".into(),
            service: Some("TIDAL".into()),
            service_role: Some("player".into()),
            local_verdict: Verdict::WafBlocked,
            local_routing_decision: RoutingDecision::ManualReview,
            local_evidence: EvidenceBundle::default(),
            control_verdict: Verdict::Accessible,
            control_routing_decision: RoutingDecision::DirectOk,
            control_evidence: EvidenceBundle::default(),
            decision: ComparisonDecision::NeedsReview,
            local_network_evidence: NetworkEvidence::default(),
            control_network_evidence: NetworkEvidence::default(),
            network_notes: Vec::new(),
            reason: "review-assisted".into(),
        },
        ComparisonResult {
            domain: "tidal.com".into(),
            service: Some("TIDAL".into()),
            service_role: Some("web".into()),
            local_verdict: Verdict::WafBlocked,
            local_routing_decision: RoutingDecision::ManualReview,
            local_evidence: EvidenceBundle::default(),
            control_verdict: Verdict::WafBlocked,
            control_routing_decision: RoutingDecision::ManualReview,
            control_evidence: EvidenceBundle::default(),
            decision: ComparisonDecision::ConsistentBlocked,
            local_network_evidence: NetworkEvidence::default(),
            control_network_evidence: NetworkEvidence::default(),
            network_notes: Vec::new(),
            reason: "blocked".into(),
        },
    ];

    let summaries = summarize_service_geo(&comparisons);
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].decision, ServiceGeoDecision::LikelyGeoBlocked);
    assert_eq!(summaries[0].review_assisted_hosts, vec!["listen.tidal.com"]);
}

#[test]
fn mixed_critical_roles_can_make_service_likely_geo_blocked() {
    let comparisons = vec![
        ComparisonResult {
            domain: "gemini.google.com".into(),
            service: Some("Gemini".into()),
            service_role: Some("app".into()),
            local_verdict: Verdict::GeoBlocked,
            local_routing_decision: RoutingDecision::ProxyRequired,
            local_evidence: EvidenceBundle::default(),
            control_verdict: Verdict::GeoBlocked,
            control_routing_decision: RoutingDecision::ProxyRequired,
            control_evidence: EvidenceBundle::default(),
            decision: ComparisonDecision::ConsistentBlocked,
            local_network_evidence: NetworkEvidence::default(),
            control_network_evidence: NetworkEvidence::default(),
            network_notes: Vec::new(),
            reason: "blocked".into(),
        },
        ComparisonResult {
            domain: "aistudio.google.com".into(),
            service: Some("Gemini".into()),
            service_role: Some("console".into()),
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
    ];

    let summaries = summarize_service_geo(&comparisons);
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].decision, ServiceGeoDecision::LikelyGeoBlocked);
}

#[test]
fn all_direct_critical_roles_can_keep_service_direct_even_with_noncritical_noise() {
    let comparisons = vec![
        ComparisonResult {
            domain: "tiktok.com".into(),
            service: Some("TikTok".into()),
            service_role: Some("web".into()),
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
            domain: "www.tiktok.com".into(),
            service: Some("TikTok".into()),
            service_role: Some("app".into()),
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
            domain: "tiktokcdn.com".into(),
            service: Some("TikTok".into()),
            service_role: Some("assets".into()),
            local_verdict: Verdict::Unreachable,
            local_routing_decision: RoutingDecision::ManualReview,
            local_evidence: EvidenceBundle::default(),
            control_verdict: Verdict::Unreachable,
            control_routing_decision: RoutingDecision::ManualReview,
            control_evidence: EvidenceBundle::default(),
            decision: ComparisonDecision::ConsistentBlocked,
            local_network_evidence: NetworkEvidence::default(),
            control_network_evidence: NetworkEvidence::default(),
            network_notes: Vec::new(),
            reason: "blocked".into(),
        },
    ];

    let summaries = summarize_service_geo(&comparisons);
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].decision, ServiceGeoDecision::DirectOk);
}

#[test]
fn multi_role_host_can_satisfy_missing_critical_service_roles() {
    let comparisons = vec![ComparisonResult {
        domain: "disneyplus.com".into(),
        service: Some("Disney+".into()),
        service_role: Some("storefront".into()),
        local_verdict: Verdict::GeoBlocked,
        local_routing_decision: RoutingDecision::ProxyRequired,
        local_confidence: 99,
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

    let summaries = summarize_service_geo(&comparisons);
    assert_eq!(summaries.len(), 1);
    assert_eq!(
        summaries[0].decision,
        ServiceGeoDecision::ConfirmedGeoBlocked
    );
    assert!(
        summaries[0].missing_critical_roles.is_empty(),
        "expected multi-role host coverage to satisfy playback"
    );
}

#[test]
fn all_non_direct_critical_roles_with_geo_marker_can_still_be_likely_geo_blocked() {
    let comparisons = vec![
        ComparisonResult {
            domain: "strava.com".into(),
            service: Some("Strava".into()),
            service_role: Some("web".into()),
            local_verdict: Verdict::WafBlocked,
            local_routing_decision: RoutingDecision::ManualReview,
            local_evidence: EvidenceBundle::default(),
            control_verdict: Verdict::GeoBlocked,
            control_routing_decision: RoutingDecision::ProxyRequired,
            control_evidence: EvidenceBundle::default(),
            decision: ComparisonDecision::ConsistentBlocked,
            local_network_evidence: NetworkEvidence::default(),
            control_network_evidence: NetworkEvidence::default(),
            network_notes: Vec::new(),
            reason: "blocked".into(),
        },
        ComparisonResult {
            domain: "www.strava.com".into(),
            service: Some("Strava".into()),
            service_role: Some("auth".into()),
            local_verdict: Verdict::GeoBlocked,
            local_routing_decision: RoutingDecision::ProxyRequired,
            local_evidence: EvidenceBundle::default(),
            control_verdict: Verdict::GeoBlocked,
            control_routing_decision: RoutingDecision::ProxyRequired,
            control_evidence: EvidenceBundle::default(),
            decision: ComparisonDecision::ConsistentBlocked,
            local_network_evidence: NetworkEvidence::default(),
            control_network_evidence: NetworkEvidence::default(),
            network_notes: Vec::new(),
            reason: "blocked".into(),
        },
    ];

    let summaries = summarize_service_geo(&comparisons);
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].decision, ServiceGeoDecision::LikelyGeoBlocked);
}

#[test]
fn browser_proxy_supports_socks_control_path() {
    assert_eq!(
        browser_proxy_server_arg("socks5h://127.0.0.1:1080"),
        Some("socks5://127.0.0.1:1080".to_string())
    );
}

#[test]
fn browser_proxy_rejects_authenticated_http_proxy() {
    assert_eq!(
        browser_proxy_server_arg("http://user:pass@31.169.127.120:14010"),
        None
    );
}

#[test]
fn safe_policy_limits_probe_budget() {
    let policy = ScanPolicy::safe();
    assert_eq!(policy.profile, ScanProfile::Safe);
    assert_eq!(policy.max_secondary_probes, 1);
    assert_eq!(policy.max_browser_probe_paths, 1);
    assert!(!policy.allow_control_browser_verify);
    assert_eq!(policy.retest_attempts, 1);
    assert_eq!(policy.retest_backoff_ms, 350);
}

#[test]
fn aggressive_policy_unlocks_full_probe_budget() {
    let policy = ScanPolicy::aggressive();
    assert_eq!(policy.profile, ScanProfile::Aggressive);
    assert_eq!(policy.max_secondary_probes, usize::MAX);
    assert_eq!(policy.max_browser_probe_paths, usize::MAX);
    assert!(policy.allow_control_browser_verify);
    assert_eq!(policy.retest_attempts, 2);
    assert_eq!(policy.retest_backoff_ms, 250);
}
