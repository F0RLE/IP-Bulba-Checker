use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

use super::types::{
    ProbeStatus, RoutingDecision, ScanResult, Verdict, evidence_summary, network_summary,
    routing_decision_label, service_context_label, service_name_label, verdict_label,
};

#[allow(clippy::too_many_lines)]
pub(crate) fn write_human_report(results: &[ScanResult], output_path: &Path) -> anyhow::Result<()> {
    let mut counts = BTreeMap::<&str, usize>::new();
    let mut routing_counts = BTreeMap::<&str, usize>::new();
    let mut service_counts = BTreeMap::<String, usize>::new();
    let mut network_counts = BTreeMap::<&str, usize>::new();
    for result in results {
        *counts.entry(verdict_label(result.verdict)).or_default() += 1;
        *routing_counts
            .entry(routing_decision_label(result.routing_decision))
            .or_default() += 1;
        *service_counts
            .entry(service_name_label(result))
            .or_default() += 1;
        if result.network_evidence.dns.status == ProbeStatus::Failed {
            *network_counts.entry("dns_failed").or_default() += 1;
        }
        if result.network_evidence.tcp_443.status == ProbeStatus::Failed {
            *network_counts.entry("tcp_443_failed").or_default() += 1;
        }
        if result.network_evidence.tls_443.status == ProbeStatus::Failed {
            *network_counts.entry("tls_443_failed").or_default() += 1;
        }
        if result.network_evidence.tcp_80.status == ProbeStatus::Failed {
            *network_counts.entry("tcp_80_failed").or_default() += 1;
        }
    }

    let mut report = String::new();
    writeln!(&mut report, "Bulbascan report")?;
    writeln!(&mut report, "======================")?;
    writeln!(&mut report)?;
    writeln!(&mut report, "Routing summary")?;
    for (decision, count) in routing_counts {
        writeln!(&mut report, "- {decision}: {count}")?;
    }
    writeln!(&mut report)?;
    writeln!(&mut report, "Verdict summary")?;
    for (verdict, count) in counts {
        writeln!(&mut report, "- {verdict}: {count}")?;
    }
    writeln!(&mut report)?;
    writeln!(&mut report, "Service summary")?;
    for (service, count) in service_counts {
        writeln!(&mut report, "- {service}: {count}")?;
    }
    writeln!(&mut report)?;
    writeln!(&mut report, "Network summary")?;
    if network_counts.is_empty() {
        writeln!(&mut report, "- no network probe failures")?;
    } else {
        for (label, count) in network_counts {
            writeln!(&mut report, "- {label}: {count}")?;
        }
    }

    let routing_sections = [
        ("Proxy Required", RoutingDecision::ProxyRequired),
        ("Manual Review", RoutingDecision::ManualReview),
        ("Direct OK", RoutingDecision::DirectOk),
    ];

    for (title, decision) in routing_sections {
        writeln!(&mut report)?;
        writeln!(&mut report, "{title}")?;
        writeln!(&mut report, "{}", "-".repeat(title.len()))?;

        let mut section_items = results
            .iter()
            .filter(|result| result.routing_decision == decision)
            .collect::<Vec<_>>();
        section_items.sort_by(|a, b| {
            b.confidence
                .cmp(&a.confidence)
                .then_with(|| a.domain.cmp(&b.domain))
        });

        if section_items.is_empty() {
            writeln!(&mut report, "none")?;
            continue;
        }

        for item in section_items {
            writeln!(
                &mut report,
                "- {} [{}%] {} ({}, {}, {}, evidence={})",
                item.domain,
                item.confidence,
                item.reason,
                verdict_label(item.verdict),
                service_context_label(item),
                network_summary(&item.network_evidence),
                evidence_summary(&item.evidence)
            )?;
        }
    }

    let sections = [
        ("Geo Blocked", Verdict::GeoBlocked),
        ("WAF Blocked", Verdict::WafBlocked),
        ("Rate Limited", Verdict::RateLimited),
        ("Unexpected Status", Verdict::UnexpectedStatus),
        ("Unreachable", Verdict::Unreachable),
        ("Accessible", Verdict::Accessible),
    ];

    for (title, verdict) in sections {
        writeln!(&mut report)?;
        writeln!(&mut report, "{title}")?;
        writeln!(&mut report, "{}", "-".repeat(title.len()))?;

        let mut section_items = results
            .iter()
            .filter(|result| result.verdict == verdict)
            .collect::<Vec<_>>();
        section_items.sort_by(|a, b| {
            b.confidence
                .cmp(&a.confidence)
                .then_with(|| a.domain.cmp(&b.domain))
        });

        if section_items.is_empty() {
            writeln!(&mut report, "none")?;
            continue;
        }

        for item in section_items {
            writeln!(
                &mut report,
                "- {} [{}%] {} ({}, {}, evidence={})",
                item.domain,
                item.confidence,
                item.reason,
                service_context_label(item),
                network_summary(&item.network_evidence),
                evidence_summary(&item.evidence)
            )?;
        }
    }

    // ── v1.3: Confidence histogram ──────────────────────────────────────────
    let bands = [
        ("90-100", 90u8, 100u8),
        ("80-89 ", 80, 89),
        ("70-79 ", 70, 79),
        ("<70   ", 0, 69),
    ];
    writeln!(&mut report)?;
    writeln!(&mut report, "Confidence distribution")?;
    writeln!(&mut report, "-----------------------")?;
    let max_bar = 30usize;
    let total = results.len().max(1);
    for (label, lo, hi) in bands {
        let count = results
            .iter()
            .filter(|r| r.confidence >= lo && r.confidence <= hi)
            .count();
        let bar_len = (count * max_bar) / total;
        let bar = "█".repeat(bar_len);
        writeln!(&mut report, "{label} {bar:<30} [{count}]")?;
    }

    // ── v1.3: Non-technical per-service summary ─────────────────────────────
    {
        let mut svc_map: BTreeMap<String, (usize, usize, usize)> = BTreeMap::new();
        for r in results {
            let svc = service_name_label(r);
            let entry = svc_map.entry(svc).or_default();
            match r.routing_decision {
                RoutingDecision::ProxyRequired => entry.0 += 1,
                RoutingDecision::DirectOk => entry.1 += 1,
                RoutingDecision::ManualReview => entry.2 += 1,
            }
        }
        if !svc_map.is_empty() {
            writeln!(&mut report)?;
            writeln!(&mut report, "Service summary (plain)")?;
            writeln!(&mut report, "-----------------------")?;
            for (svc, (proxy, direct, review)) in &svc_map {
                let svc_label = if *proxy > 0 && *direct == 0 && *review == 0 {
                    format!("BLOCKED ({}%)", proxy * 100 / (*proxy + direct + review))
                } else if *direct > 0 && *proxy == 0 && *review == 0 {
                    "OK — accessible directly".to_string()
                } else if *proxy == 0 && *direct == 0 {
                    "INCONCLUSIVE".to_string()
                } else {
                    format!("PARTIAL — {proxy} blocked / {direct} direct / {review} review")
                };
                writeln!(&mut report, "{svc:<30} {svc_label}")?;
            }
        }
    }

    std::fs::write(output_path, report)?;
    Ok(())
}

pub(crate) fn write_service_report(
    results: &[ScanResult],
    output_path: &Path,
) -> anyhow::Result<()> {
    let mut grouped = BTreeMap::<String, Vec<&ScanResult>>::new();
    for result in results {
        grouped
            .entry(service_name_label(result))
            .or_default()
            .push(result);
    }

    let mut report = String::new();
    writeln!(&mut report, "Bulbascan service report")?;
    writeln!(&mut report, "=============================")?;

    for (service, mut items) in grouped {
        items.sort_by(|a, b| a.domain.cmp(&b.domain));

        let proxy_required = items
            .iter()
            .filter(|item| item.routing_decision == RoutingDecision::ProxyRequired)
            .count();
        let direct_ok = items
            .iter()
            .filter(|item| item.routing_decision == RoutingDecision::DirectOk)
            .count();
        let manual_review = items
            .iter()
            .filter(|item| item.routing_decision == RoutingDecision::ManualReview)
            .count();

        writeln!(&mut report)?;
        writeln!(&mut report, "{service}")?;
        writeln!(&mut report, "{}", "-".repeat(service.len()))?;
        writeln!(
            &mut report,
            "proxy_required={proxy_required} direct_ok={direct_ok} manual_review={manual_review}"
        )?;

        for item in items {
            let role = item.service_role.as_deref().unwrap_or("unknown");
            writeln!(
                &mut report,
                "- {} role={} route={} verdict={} confidence={}% network={} evidence={} {}",
                item.domain,
                role,
                routing_decision_label(item.routing_decision),
                verdict_label(item.verdict),
                item.confidence,
                network_summary(&item.network_evidence),
                evidence_summary(&item.evidence),
                item.reason
            )?;
        }
    }

    std::fs::write(output_path, report)?;
    Ok(())
}

pub(crate) fn write_routing_lists(results: &[ScanResult], output_dir: &Path) -> anyhow::Result<()> {
    let mut proxy_required = results
        .iter()
        .filter(|result| result.routing_decision == RoutingDecision::ProxyRequired)
        .map(|result| result.domain.clone())
        .collect::<Vec<_>>();
    proxy_required.sort();
    proxy_required.dedup();

    let mut direct_ok = results
        .iter()
        .filter(|result| result.routing_decision == RoutingDecision::DirectOk)
        .map(|result| result.domain.clone())
        .collect::<Vec<_>>();
    direct_ok.sort();
    direct_ok.dedup();

    let mut manual_review = results
        .iter()
        .filter(|result| result.routing_decision == RoutingDecision::ManualReview)
        .map(|result| result.domain.clone())
        .collect::<Vec<_>>();
    manual_review.sort();
    manual_review.dedup();

    let write_list = |path: &Path, items: &[String]| -> anyhow::Result<()> {
        let mut content = items.join("\n");
        if !content.is_empty() {
            content.push('\n');
        }
        std::fs::write(path, content)?;
        Ok(())
    };

    write_list(&output_dir.join("proxy_required.txt"), &proxy_required)?;
    write_list(&output_dir.join("direct_ok.txt"), &direct_ok)?;
    write_list(&output_dir.join("manual_review.txt"), &manual_review)?;
    Ok(())
}
