//! Bulbascan is a selective-proxy scanner for router-oriented block analysis.
//! It classifies geo and WAF behavior, then turns observations into routing
//! decisions that help proxy only the domains that need it.

#![warn(missing_docs)]
#![warn(clippy::pedantic)]

use clap::Parser;
use std::collections::{HashMap, HashSet};
use std::io::IsTerminal;
use tokio::io::AsyncBufReadExt;

mod cli;
mod geosite;
mod pipeline;
mod progress;
mod radar;
mod router_exports;
mod scanner;
mod service_profiles;
mod signatures;
mod state;
mod validation;
mod xray;

use cli::{Args, ExportProfileArg, default_results_dir_for_input, parse_annotated_domain_line};
use pipeline::{
    blocked_domains_from_comparisons, blocked_domains_from_results, filter_pending_domains,
    merge_blocked_domains_into_list, write_blocked_domain_list,
};

// ── Worker count persistence ───────────────────────────────────────────────
// Saved to .bulbascan_workers in CWD; overridden if --concurrency is explicit.
const WORKERS_FILE: &str = ".bulbascan_workers";
const DEFAULT_WORKERS: usize = 50;

fn load_workers(path: &str) -> Option<usize> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .filter(|&n: &usize| (1..=1000).contains(&n))
}

fn save_workers(path: &str, n: usize) {
    let _ = std::fs::write(path, n.to_string());
}

#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() -> anyhow::Result<()> {
    let mut args = Args::parse();
    let version = env!("CARGO_PKG_VERSION");

    // Resolve concurrency: CLI flag wins, else last-saved value, else default.
    let concurrency: usize = args
        .concurrency
        .unwrap_or_else(|| load_workers(WORKERS_FILE).unwrap_or(DEFAULT_WORKERS))
        .clamp(1, 1000);

    let using_default_results_dir = args.results_dir == std::path::Path::new("results");

    let term = console::Term::stderr();
    let style_header = console::Style::new().cyan().bold();
    let style_dim = console::Style::new().dim();
    let style_value = console::Style::new().yellow();
    let style_ok = console::Style::new().green().bold();

    let _ = term.write_line("");

    // Big block-letter ASCII art — left-aligned, 2-space margin
    let ascii_name: &[&str] = &[
        "██████╗ ██╗   ██╗██╗     ██████╗   █████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗",
        "██╔══██╗██║   ██║██║     ██╔══██╗ ██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║",
        "██████╔╝██║   ██║██║     ██████╔╝ ███████║███████╗██║     ███████║██╔██╗ ██║",
        "██╔══██╗██║   ██║██║     ██╔══██╗ ██╔══██║╚════██║██║     ██╔══██║██║╚██╗██║",
        "██████╔╝╚██████╔╝███████╗██████╔╝ ██║  ██║███████║╚██████╗██║  ██║██║ ╚████║",
    ];

    let name_style = console::Style::new().green().bold();

    if args.ascii_only {
        let _ = term.write_line("  BULBASCAN");
    } else {
        for line in ascii_name {
            let _ = term.write_line(&format!("  {}", name_style.apply_to(line)));
        }
    }

    let _ = term.write_line(&format!(
        "  {} 🥔   {}",
        style_dim.apply_to(format!("v{version}")),
        style_dim.apply_to("← → adjust workers  q quit"),
    ));
    // Blank line = profile slot. LiveBar will overwrite it on the first tick.
    let _ = term.write_line("");

    if !args.format.eq_ignore_ascii_case("text") && !args.format.eq_ignore_ascii_case("json") {
        anyhow::bail!(
            "Unsupported output format '{}'. Use 'text' or 'json'.",
            args.format
        );
    }

    if let Some(config_path) = args.emit_xray_socks_config.as_ref() {
        let control_link = args
            .control_link
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--control-link is required"))?;
        let generated =
            xray::generate_xray_socks_client_config(control_link, &args.xray_socks_listen)?;
        if let Some(parent) = config_path.parent()
            && !parent.as_os_str().is_empty()
        {
            tokio::fs::create_dir_all(parent).await?;
        }
        let payload = serde_json::to_vec_pretty(&generated.config)?;
        tokio::fs::write(config_path, payload).await?;
        println!(
            "Xray SOCKS client config saved to {}.",
            config_path.display()
        );
        println!(
            "Start Xray with that file, then use --control-proxy {}",
            generated.socks_proxy_url
        );
        return Ok(());
    }

    // --list-geosite-categories: print all categories and exit
    if let Some(ref dat_path) = args.list_geosite_categories {
        match geosite::list_categories(dat_path) {
            Ok(cats) => {
                println!("Categories in {}:", dat_path.display());
                for cat in cats {
                    println!("  {cat}");
                }
            }
            Err(e) => anyhow::bail!("Error: {e}"),
        }
        return Ok(());
    }

    if using_default_results_dir && args.fetch_radar == 0 {
        if let Some(first) = args.files.first() {
            args.results_dir = default_results_dir_for_input(first);
        } else if let Some(dat) = args.import_geosite.as_ref() {
            args.results_dir = default_results_dir_for_input(dat);
        }
    }

    // Create results directory
    if !args.results_dir.exists() {
        tokio::fs::create_dir_all(&args.results_dir).await?;
    }

    // Prepare paths
    let out_ok = args.results_dir.join(&args.out_ok);
    let out_blocked = args.results_dir.join(&args.out_blocked);
    let out_ok_cleanup_path = out_ok.clone();
    let geosite_path = args.results_dir.join(&args.geosite);
    let report_path = args.results_dir.join("report.txt");
    let services_report_path = args.results_dir.join("services_report.txt");
    let proxy_required_path = args.results_dir.join("proxy_required.txt");
    let direct_ok_path = args.results_dir.join("direct_ok.txt");
    let manual_review_path = args.results_dir.join("manual_review.txt");
    let blocked_domains_path = args.results_dir.join(&args.blocked_list);
    let comparison_report_path = args.results_dir.join("comparison_report.txt");
    let confirmed_proxy_required_path = args.results_dir.join("confirmed_proxy_required.txt");
    let control_proxy_health_path = args.results_dir.join("control_proxy_health.txt");
    let service_geo_report_path = args.results_dir.join("service_geo_report.txt");
    let validation_report_path = args.results_dir.join("validation_report.txt");
    let strict_sing_box_rule_set_path = args.results_dir.join("strict-sing-box-rule-set.json");
    let strict_sing_box_route_path = args.results_dir.join("strict-sing-box-route-snippet.json");
    let strict_xray_route_path = args.results_dir.join("strict-xray-routing-rule.json");
    let strict_openwrt_pbr_path = args.results_dir.join("strict-openwrt-pbr-domains.txt");
    let strict_openwrt_dnsmasq_path = args.results_dir.join("strict-openwrt-dnsmasq-ipset.conf");
    let output_format = args.format.clone();
    let signatures_file = args.signatures.clone();
    let scan_policy = args.profile.as_scanner_policy();
    let state_dir = args.state_dir.clone();

    let state_enabled = state_dir.is_some();

    let mut local_state = if let Some(dir) = state_dir.as_ref() {
        match state::LocalState::load(dir) {
            Ok(existing) => existing,
            Err(err) => {
                anyhow::bail!(
                    "State directory {} is corrupted or unreadable: {err}\n\
                     Fix or remove the directory, or omit --state-dir.",
                    dir.display()
                );
            }
        }
    } else {
        state::LocalState::default()
    };

    // Read or fetch domains
    let mut domains = Vec::new();
    let mut seen = HashSet::new();
    let mut expected_outcomes = HashMap::new();

    if args.fetch_radar > 0 {
        println!(
            "Fetching top {} domains from Cloudflare Radar...",
            args.fetch_radar
        );
        let radar = radar::RadarClient::new(args.radar_token);
        match radar.fetch_top_domains(args.fetch_radar).await {
            Ok(fetched) => {
                println!("Successfully fetched {} domains.", fetched.len());
                domains = fetched;
            }
            Err(e) => anyhow::bail!("Error fetching from Radar: {e}"),
        }
    } else {
        // Load from one or more files.
        // .dat → binary geosite.dat using --import-geosite-category
        // anything else → plain domain list text file
        let files = args.files;
        let geosite_category = &args.import_geosite_category;

        // Also honour the legacy --import-geosite explicit flag if set
        if let Some(ref dat_path) = args.import_geosite
            && !files.iter().any(|f| f == dat_path)
        {
            match geosite::decode_domains(dat_path, geosite_category) {
                Ok(imported) => {
                    for domain in imported {
                        if seen.insert(domain.clone()) {
                            domains.push(domain);
                        }
                    }
                }
                Err(e) => anyhow::bail!("Error: {e}"),
            }
        }

        for path in files {
            let is_dat = path.extension().and_then(|e| e.to_str()) == Some("dat");

            if is_dat {
                if let Ok(imported) = geosite::decode_domains(&path, geosite_category) {
                    let before = domains.len();
                    for domain in imported {
                        if seen.insert(domain.clone()) {
                            domains.push(domain);
                        }
                    }
                    println!(
                        "  → {} domains imported from {}.",
                        domains.len() - before,
                        path.display()
                    );
                } else {
                    // Category not found — show available ones and ask interactively.
                    let available = geosite::list_categories(&path).unwrap_or_default();
                    println!(
                        "\nCategory '{}' not found in {}.",
                        geosite_category,
                        path.display()
                    );
                    if available.is_empty() {
                        eprintln!(
                            "Error: Could not read any categories from the file. Is it a valid geosite.dat?"
                        );
                        eprintln!("Press Enter to exit.");
                        let mut buf = String::new();
                        let _ = std::io::stdin().read_line(&mut buf);
                        anyhow::bail!("Exiting due to invalid geosite.dat");
                    }

                    if !std::io::stdin().is_terminal() {
                        anyhow::bail!(
                            "Category '{}' not found in {}. Available: {}",
                            geosite_category,
                            path.display(),
                            available.join(", ")
                        );
                    }
                    println!("Available categories:");
                    for cat in &available {
                        println!("  - {}", cat.to_lowercase());
                    }
                    print!("\nType a category name (or 'all') and press Enter: ");
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input).ok();
                    let chosen = input.trim().to_string();

                    // Clear the screen so the massive list of categories goes away
                    print!("\x1B[2J\x1B[1;1H");
                    let _ = std::io::Write::flush(&mut std::io::stdout());

                    if chosen.is_empty() {
                        anyhow::bail!("No category entered. Exiting.");
                    }
                    match geosite::decode_domains(&path, &chosen) {
                        Ok(imported) => {
                            let before = domains.len();
                            for domain in imported {
                                if seen.insert(domain.clone()) {
                                    domains.push(domain);
                                }
                            }
                            println!(
                                "  → {} domains imported from {} (category: {}).",
                                domains.len() - before,
                                path.display(),
                                chosen
                            );
                        }
                        Err(e) => {
                            eprintln!("Error: {e}");
                            eprintln!("Press Enter to exit.");
                            let mut buf = String::new();
                            let _ = std::io::stdin().read_line(&mut buf);
                            anyhow::bail!("Exiting due to missing/invalid category");
                        }
                    }
                }
            } else {
                if !path.exists() || !path.is_file() {
                    if path == std::path::Path::new("targets.txt") {
                        // silently skip the default placeholder when not present
                        continue;
                    }
                    anyhow::bail!("Error: Input file '{}' not found.", path.display());
                }

                let file = tokio::fs::File::open(&path).await?;
                let mut reader = tokio::io::BufReader::new(file);
                let mut line = String::new();
                let before = domains.len();

                while reader.read_line(&mut line).await? > 0 {
                    if let Some((domain, expected)) = parse_annotated_domain_line(&line)
                        && seen.insert(domain.clone())
                    {
                        if let Some(expected) = expected {
                            expected_outcomes.insert(domain.clone(), expected);
                        }
                        domains.push(domain);
                    }
                    line.clear();
                }

                if domains.len() - before > 0 {
                    println!(
                        "  → {} domains loaded from {}.",
                        domains.len() - before,
                        path.display()
                    );
                }
            }
        }
    }

    if state_enabled {
        let (pending, skipped) = filter_pending_domains(
            domains,
            &mut expected_outcomes,
            &local_state,
            args.refresh_known,
        );
        domains = pending;
        if skipped > 0 {
            println!("State cache skipped {skipped} already-known domains (blocked/direct).");
        }
    }

    let _ = term.write_line("");

    // Run the scanner process
    let mut proxies = Vec::new();

    if let Some(p) = args.proxy.clone() {
        proxies.push(p);
    }

    if let Some(path) = args.proxies {
        if path.exists() && path.is_file() {
            let content = tokio::fs::read_to_string(&path).await?;

            for line in content.lines() {
                let clean = line.trim();
                if !clean.is_empty() && !clean.starts_with('#') {
                    proxies.push(clean.to_string());
                }
            }
        } else {
            anyhow::bail!("Error: Proxies file '{}' not found.", path.display());
        }
    }

    if !proxies.is_empty() {
        println!("Loaded {} proxies for rotation.", proxies.len());
    }

    // Output path string passed to LiveBar for the dynamic profile header.
    let output_display = args.results_dir.display().to_string();

    let scan_results = if domains.is_empty() {
        Vec::new()
    } else {
        let Some((results, final_workers)) = scanner::run_scan(
            domains.clone(),
            proxies,
            concurrency,
            out_ok,
            out_blocked,
            args.timeout,
            args.max_redirects,
            args.global_timeout,
            args.verbose,
            output_format.clone(),
            scan_policy,
            args.sni_fragment,
            signatures_file.clone(),
            args.max_body_size,
            args.potato,
            args.browser.as_deref(),
            output_display.clone(),
        )
        .await?
        else {
            // User cancelled the scan via 'q'
            return Ok(());
        };
        // Persist the live-adjusted worker count for next run.
        save_workers(WORKERS_FILE, final_workers);
        results
    };

    if state_enabled {
        local_state.ingest_scan_results(&scan_results);
    }

    if args.export_profile == ExportProfileArg::Simple && out_ok_cleanup_path.exists() {
        let _ = std::fs::remove_file(&out_ok_cleanup_path);
    }

    let mut blocked_domains_for_outputs = if state_dir.is_some() {
        local_state.blocked_domains()
    } else {
        blocked_domains_from_results(&scan_results)
    };
    match write_blocked_domain_list(
        &blocked_domains_for_outputs,
        &blocked_domains_path,
        args.blocked_list_format,
    ) {
        Ok(()) => println!(
            "Blocked domain list saved to {}.",
            blocked_domains_path.display()
        ),
        Err(e) => eprintln!("Error writing blocked domain list: {e}"),
    }
    if let Some(merge_path) = args.merge_into_list.as_ref() {
        match merge_blocked_domains_into_list(
            merge_path,
            &blocked_domains_for_outputs,
            args.blocked_list_format,
        )
        .await
        {
            Ok(merged_count) => println!(
                "Merged blocked domains into {} ({} total domains).",
                merge_path.display(),
                merged_count
            ),
            Err(e) => eprintln!(
                "Error merging blocked domains into {}: {e}",
                merge_path.display()
            ),
        }
    }

    if matches!(
        args.export_profile,
        ExportProfileArg::Router | ExportProfileArg::Full
    ) {
        match scanner::write_human_report(&scan_results, &report_path) {
            Ok(()) => println!("Human-readable report saved to {}.", report_path.display()),
            Err(e) => eprintln!("Error writing report: {e}"),
        }
        match scanner::write_service_report(&scan_results, &services_report_path) {
            Ok(()) => println!(
                "Service report saved to {}.",
                services_report_path.display()
            ),
            Err(e) => eprintln!("Error writing service report: {e}"),
        }
        match scanner::write_routing_lists(&scan_results, &args.results_dir) {
            Ok(()) => {
                println!(
                    "Routing lists saved to {}, {}, and {}.",
                    proxy_required_path.display(),
                    direct_ok_path.display(),
                    manual_review_path.display()
                );
            }
            Err(e) => eprintln!("Error writing routing lists: {e}"),
        }
        match router_exports::write_router_exports(&scan_results, &args.results_dir) {
            Ok(paths) => println!("Router-native exports saved to {}.", paths.join(", ")),
            Err(e) => eprintln!("Error writing router-native exports: {e}"),
        }
        match router_exports::write_generic_apex_exports(&scan_results, &args.results_dir) {
            Ok(paths) => println!("Generic apex exports saved to {}.", paths.join(", ")),
            Err(e) => eprintln!("Error writing generic apex exports: {e}"),
        }
    }
    if args.export_profile == ExportProfileArg::Full {
        match validation::write_validation_report(
            &scan_results,
            None,
            None,
            (!expected_outcomes.is_empty()).then_some(&expected_outcomes),
            &validation_report_path,
        ) {
            Ok(()) => println!(
                "Validation report saved to {}.",
                validation_report_path.display()
            ),
            Err(e) => eprintln!("Error writing validation report: {e}"),
        }
    }

    let mut geosite_domains = blocked_domains_for_outputs.clone();
    let mut geosite_use_scan_results = true;

    if let Some(control_proxy) = args.control_proxy.clone() {
        println!("Checking control proxy health...");

        let control_health =
            scanner::preflight_control_proxy(&control_proxy, args.timeout, args.max_redirects)
                .await;
        match scanner::write_control_proxy_health(&control_health, &control_proxy_health_path) {
            Ok(()) => println!(
                "Control proxy health saved to {}.",
                control_proxy_health_path.display()
            ),
            Err(e) => eprintln!("Error writing control proxy health: {e}"),
        }

        if scanner::should_run_control_comparison(&control_health) {
            println!("Control proxy is healthy. Running comparison scan...");

            let Some((control_results, _)) = scanner::run_scan(
                domains,
                vec![control_proxy],
                concurrency,
                args.results_dir.join("control_ok.log"),
                args.results_dir.join("control_blocked.log"),
                args.timeout,
                args.max_redirects,
                args.global_timeout,
                args.verbose,
                output_format,
                scan_policy,
                args.sni_fragment,
                signatures_file,
                args.max_body_size,
                args.potato,
                args.browser.as_deref(),
                output_display,
            )
            .await?
            else {
                return Ok(());
            };

            let comparisons = scanner::compare_with_control(&scan_results, &control_results);
            let confirmed_proxy_required = blocked_domains_from_comparisons(&comparisons);
            if !confirmed_proxy_required.is_empty() {
                if state_dir.is_some() {
                    local_state.ingest_confirmed_blocked(&confirmed_proxy_required);
                    blocked_domains_for_outputs = local_state.blocked_domains();
                }
                geosite_domains = confirmed_proxy_required.clone();
                geosite_use_scan_results = false;
                let blocked_domains_ref = if state_dir.is_some() {
                    &blocked_domains_for_outputs
                } else {
                    &confirmed_proxy_required
                };
                match write_blocked_domain_list(
                    blocked_domains_ref,
                    &blocked_domains_path,
                    args.blocked_list_format,
                ) {
                    Ok(()) => println!(
                        "Blocked domain list refreshed from confirmed comparison at {}.",
                        blocked_domains_path.display()
                    ),
                    Err(e) => eprintln!("Error refreshing blocked domain list: {e}"),
                }
                if let Some(merge_path) = args.merge_into_list.as_ref() {
                    match merge_blocked_domains_into_list(
                        merge_path,
                        blocked_domains_ref,
                        args.blocked_list_format,
                    )
                    .await
                    {
                        Ok(merged_count) => println!(
                            "Merged confirmed blocked domains into {} ({} total domains).",
                            merge_path.display(),
                            merged_count
                        ),
                        Err(e) => eprintln!(
                            "Error merging confirmed blocked domains into {}: {e}",
                            merge_path.display()
                        ),
                    }
                }
            }
            if matches!(
                args.export_profile,
                ExportProfileArg::Router | ExportProfileArg::Full
            ) {
                match scanner::write_control_comparison_report(
                    &comparisons,
                    &comparison_report_path,
                ) {
                    Ok(()) => println!(
                        "Control comparison report saved to {}.",
                        comparison_report_path.display()
                    ),
                    Err(e) => eprintln!("Error writing control comparison report: {e}"),
                }
                match scanner::write_confirmed_proxy_required(
                    &comparisons,
                    &confirmed_proxy_required_path,
                ) {
                    Ok(()) => println!(
                        "Confirmed proxy-required list saved to {}.",
                        confirmed_proxy_required_path.display()
                    ),
                    Err(e) => eprintln!("Error writing confirmed proxy-required list: {e}"),
                }
            }
            let service_geo = scanner::summarize_service_geo(&comparisons);
            if matches!(
                args.export_profile,
                ExportProfileArg::Router | ExportProfileArg::Full
            ) {
                match scanner::write_service_geo_report(&service_geo, &service_geo_report_path) {
                    Ok(()) => println!(
                        "Service geo report saved to {}.",
                        service_geo_report_path.display()
                    ),
                    Err(e) => eprintln!("Error writing service geo report: {e}"),
                }
                match router_exports::write_strict_router_exports(&comparisons, &args.results_dir) {
                    Ok(paths) => println!(
                        "Strict router-native exports saved to {}.",
                        paths.join(", ")
                    ),
                    Err(e) => eprintln!("Error writing strict router-native exports: {e}"),
                }
                match router_exports::write_split_router_exports(
                    &comparisons,
                    &service_geo,
                    &args.results_dir,
                ) {
                    Ok(paths) => println!(
                        "Known-service and generic split exports saved to {}.",
                        paths.join(", ")
                    ),
                    Err(e) => eprintln!("Error writing split router exports: {e}"),
                }
            }
            if args.export_profile == ExportProfileArg::Full {
                match validation::write_validation_report(
                    &scan_results,
                    Some(&comparisons),
                    Some(&service_geo),
                    (!expected_outcomes.is_empty()).then_some(&expected_outcomes),
                    &validation_report_path,
                ) {
                    Ok(()) => println!(
                        "Validation report refreshed with dual-vantage evidence at {}.",
                        validation_report_path.display()
                    ),
                    Err(e) => eprintln!("Error refreshing validation report: {e}"),
                }
            }
        } else {
            println!("Control proxy health check failed. Skipping comparison scan.");
            for stale in [
                &comparison_report_path,
                &confirmed_proxy_required_path,
                &service_geo_report_path,
                &strict_sing_box_rule_set_path,
                &strict_sing_box_route_path,
                &strict_xray_route_path,
                &strict_openwrt_pbr_path,
                &strict_openwrt_dnsmasq_path,
                &args.results_dir.join("known-service-bundle-rule-set.json"),
                &args
                    .results_dir
                    .join("known-service-bundle-route-snippet.json"),
                &args
                    .results_dir
                    .join("known-service-bundle-xray-routing-rule.json"),
                &args
                    .results_dir
                    .join("known-service-bundle-openwrt-pbr-domains.txt"),
                &args
                    .results_dir
                    .join("known-service-bundle-dnsmasq-ipset.conf"),
                &args.results_dir.join("generic-apex-bypass-rule-set.json"),
                &args
                    .results_dir
                    .join("generic-apex-bypass-route-snippet.json"),
                &args
                    .results_dir
                    .join("generic-apex-bypass-xray-routing-rule.json"),
                &args.results_dir.join("generic-apex-bypass-domains.txt"),
                &args
                    .results_dir
                    .join("generic-apex-bypass-dnsmasq-ipset.conf"),
            ] {
                if stale.exists() {
                    let _ = std::fs::remove_file(stale);
                }
            }
        }
    }

    if !geosite_domains.is_empty() {
        let _ = term.write_line(&format!(
            "\n  {} Compiling {}...",
            style_header.apply_to("📦"),
            style_value.apply_to(geosite_path.display()),
        ));

        let geosite_result = if geosite_use_scan_results {
            if state_dir.is_some() {
                geosite::compile_domains(
                    &blocked_domains_for_outputs,
                    &geosite_path,
                    &args.geosite_category,
                )
            } else {
                geosite::compile(&scan_results, &geosite_path, &args.geosite_category)
            }
        } else {
            geosite::compile_domains(
                if state_dir.is_some() {
                    &blocked_domains_for_outputs
                } else {
                    &geosite_domains
                },
                &geosite_path,
                &args.geosite_category,
            )
        };

        match geosite_result {
            Ok(()) => {
                let _ = term.write_line(&format!(
                    "  {} geosite.dat generated successfully",
                    style_ok.apply_to("✔"),
                ));
            }
            Err(e) => eprintln!("Error generating geosite.dat: {e}"),
        }
    } else if geosite_path.exists() {
        let _ = std::fs::remove_file(&geosite_path);
    }

    if state_enabled && let Some(dir) = state_dir.as_ref() {
        match local_state.save(dir).await {
            Ok(()) => println!("Local state saved to {}.", dir.display()),
            Err(err) => eprintln!("Error saving state to {}: {err}", dir.display()),
        }
    }

    // If run by double-clicking on Windows (<= 2 args), pause before exit
    if cfg!(windows) && std::env::args().len() <= 2 {
        use std::io::IsTerminal;
        if std::io::stdin().is_terminal() && std::env::var("CI").is_err() {
            println!("\nPress Enter to exit...");
            let mut input = String::new();
            let _ = std::io::stdin().read_line(&mut input);
        }
    }

    Ok(())
}
