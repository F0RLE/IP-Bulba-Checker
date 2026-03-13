use console::Style;
use reqwest::Client as FallbackClient;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::fs::File;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector as RustlsTlsConnector;
use wreq::{Client, header, tls::TlsOptions};
use wreq_util::Emulation;

use crate::service_profiles;
use crate::signatures;
use serde::Deserialize;

mod analysis;
mod browser;
mod comparison;
mod network;
mod reports;
mod transport;
pub(crate) mod types;
use analysis::{
    analyze_http_observation, classify_browser_html, classify_transport_error,
    relax_infra_root_result, same_measurement, should_try_retest, stabilize_scan_attempts,
    status_from_verdict, verdict_rank,
};
use browser::{
    browser_proxy_server_arg, detect_browser_binary, run_browser_dom_dump,
    should_try_browser_verify,
};
pub(crate) use comparison::{
    compare_with_control, summarize_service_geo, write_confirmed_proxy_required,
    write_control_comparison_report, write_control_proxy_health, write_service_geo_report,
};
use network::collect_network_evidence;
pub(crate) use reports::{write_human_report, write_routing_lists, write_service_report};
use transport::{build_request, send_via_reqwest, send_with_retries};
pub(crate) use transport::{preflight_control_proxy, should_run_control_comparison};
#[allow(unused_imports)]
pub use types::{
    ComparisonDecision, ComparisonResult, DomainStatus, EvidenceBundle, NetworkEvidence,
    RoutingDecision, ScanPolicy, ScanResult, Verdict,
};
use types::{
    build_scan_result, network_summary, routing_decision_label, service_context_label,
    verdict_label, with_evidence,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransportErrorKind {
    Unreachable,
    TlsFailure,
}

const TRANSIENT_RETRY_ATTEMPTS: usize = 2;
const BROWSER_VERIFY_TIMEOUT_SECS: u64 = 25;
const NETWORK_PROBE_TIMEOUT_SECS: u64 = 4;

#[derive(Deserialize)]
struct DohResponse {
    #[serde(rename = "Status")]
    status: u32,
    #[serde(rename = "Answer", default)]
    answers: Vec<DohAnswer>,
    #[serde(rename = "Comment")]
    comment: Option<String>,
}

#[derive(Deserialize)]
struct DohAnswer {
    data: String,
    #[serde(rename = "type")]
    record_type: u16,
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
pub async fn run_scan(
    domains: Vec<String>,
    proxies: Vec<String>,
    concurrency: usize,
    out_ok: PathBuf,
    out_blocked: PathBuf,
    timeout_secs: u64,
    max_redirects: usize,
    global_timeout_secs: u64,
    verbose: bool,
    format: String,
    scan_policy: ScanPolicy,
    record_size_limit: Option<u16>,
    signatures_file: Option<PathBuf>,
    max_body_size: usize,
    potato: bool,
    browser_override: Option<&Path>,
    output_display: String,
) -> anyhow::Result<Option<(Vec<ScanResult>, usize)>> {
    // Must be first — before any `let` statements (clippy::items_after_statements).
    const MAX_WORKERS: usize = 1000;

    let worker_count = concurrency.max(1);
    // Queue must accommodate the full MAX_WORKERS that can become active via arrow keys.
    let queue_cap = MAX_WORKERS
        .saturating_mul(4)
        .max(worker_count.saturating_mul(4));

    // 1. Setup Base Client with Browser Evasion
    let accept_languages = [
        "en-US,en;q=0.9",
        "en-US,en;q=0.5",
        "en-GB,en;q=0.9,en-US;q=0.8",
        "en-US,en;q=0.9,ru;q=0.8",
    ];
    let accept_language = accept_languages[fastrand::usize(..accept_languages.len())];

    let mut headers = header::HeaderMap::new();
    headers.insert(
        header::ACCEPT_LANGUAGE,
        header::HeaderValue::from_str(accept_language).expect("valid accept-language"),
    );
    headers.insert("dnt", header::HeaderValue::from_static("1"));

    let mut tls_builder = TlsOptions::builder();
    tls_builder = tls_builder.enable_ech_grease(false);
    if let Some(limit) = record_size_limit {
        tls_builder = tls_builder.record_size_limit(limit);
    }

    let client = Client::builder()
        .emulation(Emulation::Chrome145)
        .default_headers(headers)
        .tls_options(tls_builder.build())
        .timeout(Duration::from_secs(timeout_secs))
        .redirect(wreq::redirect::Policy::limited(max_redirects))
        .build()?;

    let fallback_client = FallbackClient::builder()
        .brotli(true)
        .gzip(true)
        .zstd(true)
        .http2_adaptive_window(true)
        .redirect(reqwest::redirect::Policy::limited(max_redirects))
        .timeout(Duration::from_secs(timeout_secs))
        .build()?;

    let tls_connector = Arc::new(network::build_tls_connector());
    let browser_binary = Arc::new(
        browser_override
            .map(PathBuf::from)
            .or_else(detect_browser_binary),
    );
    let proxies = Arc::new(proxies);
    let matcher = Arc::new(signatures::BlockMatcher::new(signatures_file.as_deref())?);
    let proxy_index = Arc::new(AtomicUsize::new(0));
    let proxy_fails = Arc::new(
        (0..proxies.len())
            .map(|_| AtomicUsize::new(0))
            .collect::<Vec<_>>(),
    );

    let (work_tx, work_rx) = async_channel::bounded::<String>(queue_cap);
    let (logger_tx, mut logger_rx) = mpsc::channel::<ScanResult>(queue_cap);

    let cancel_token = tokio_util::sync::CancellationToken::new();

    let active_concurrency = Arc::new(AtomicUsize::new(worker_count));
    // 2. Setup Progress Bar
    let total_domains = domains.len();
    let bar = crate::progress::LiveBar::new(
        total_domains as u64,
        active_concurrency.clone(),
        potato,
        output_display,
    );
    let bar_clone = bar.clone();
    let draw_thread = bar.start_draw_thread();

    // 3. Spawn Logger
    let is_json = format.eq_ignore_ascii_case("json");
    let logger_handle = tokio::spawn(async move {
        let mut final_results = Vec::new();

        while let Some(res) = logger_rx.recv().await {
            match res.status {
                DomainStatus::Ok => bar_clone.ok.fetch_add(1, Ordering::Relaxed),
                DomainStatus::Blocked => bar_clone.blocked.fetch_add(1, Ordering::Relaxed),
                DomainStatus::Dead => bar_clone.dead.fetch_add(1, Ordering::Relaxed),
            };
            final_results.push(res);
            bar_clone.pos.fetch_add(1, Ordering::Relaxed);
        }

        // Sort results: OK first, then Blocked (by priority), then Dead.
        // Within each group, sort by domain name.
        final_results.sort_by(|a, b| {
            let status_order = |s: DomainStatus| match s {
                DomainStatus::Ok => 0,
                DomainStatus::Blocked => 1,
                DomainStatus::Dead => 2,
            };

            let s_a = status_order(a.status);
            let s_b = status_order(b.status);

            if s_a != s_b {
                return s_a.cmp(&s_b);
            }

            // If both blocked, sort by block type priority (descending)
            if a.status == DomainStatus::Blocked {
                let p_a = a
                    .block_type
                    .map_or(0, signatures::BlockType::report_priority);
                let p_b = b
                    .block_type
                    .map_or(0, signatures::BlockType::report_priority);
                if p_a != p_b {
                    return p_b.cmp(&p_a);
                }
            }

            a.domain.cmp(&b.domain)
        });

        let mut ok_file = BufWriter::new(File::create(out_ok).await?);
        let mut blocked_file = BufWriter::new(File::create(out_blocked).await?);

        for res in &final_results {
            let line = if is_json {
                serde_json::to_string(res)? + "\n"
            } else {
                let (icon, tag) = match res.status {
                    DomainStatus::Ok => ("✓", "OK".to_string()),
                    DomainStatus::Blocked => (
                        "✗",
                        res.block_type
                            .map_or_else(|| "BLOCKED".into(), |t| t.to_string()),
                    ),
                    DomainStatus::Dead => ("○", "DEAD".to_string()),
                };
                format!(
                    "{icon} [{tag:^7}] {:<40} │ {:<14} │ {:<14} │ {:>3}% │ {} │ {} │ {}\n",
                    res.domain,
                    verdict_label(res.verdict),
                    routing_decision_label(res.routing_decision),
                    res.confidence,
                    service_context_label(res),
                    network_summary(&res.network_evidence),
                    res.reason,
                )
            };

            if res.status == DomainStatus::Ok {
                ok_file.write_all(line.as_bytes()).await?;
            } else {
                blocked_file.write_all(line.as_bytes()).await?;
            }
        }

        ok_file.flush().await?;
        blocked_file.flush().await?;
        Ok::<_, anyhow::Error>(final_results)
    });

    // 4. Fill Work Queue
    let feeder_cancel = cancel_token.clone();
    let feeder_tx = work_tx.clone();
    let feeder_handle = tokio::spawn(async move {
        for domain in domains {
            tokio::select! {
                () = feeder_cancel.cancelled() => break,
                send_res = feeder_tx.send(domain) => {
                    if send_res.is_err() {
                        break;
                    }
                }
            }
        }
        feeder_tx.close();
    });
    drop(work_tx);

    // 5. Spawn Workers.
    // We always spawn MAX_WORKERS goroutines so that raising active_concurrency
    // via arrow keys immediately engages more workers without re-spawning.
    // Workers with worker_id >= active_concurrency spin-sleep; others process.
    let absolute_max_workers = MAX_WORKERS;
    let mut workers = Vec::with_capacity(absolute_max_workers);
    for worker_id in 0..absolute_max_workers {
        let client = client.clone();
        let matcher = matcher.clone();
        let fallback_client = fallback_client.clone();
        let tls_connector = tls_connector.clone();
        let browser_binary = browser_binary.clone();
        let logger_tx = logger_tx.clone();
        let work_rx = work_rx.clone();
        let proxies = proxies.clone();
        let proxy_index = proxy_index.clone();
        let proxy_fails = proxy_fails.clone();
        let ct = cancel_token.clone();
        let worker_scan_policy = scan_policy;
        let active = active_concurrency.clone();

        workers.push(tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = ct.cancelled() => break,
                    () = tokio::time::sleep(Duration::from_millis(200)), if worker_id >= active.load(Ordering::Relaxed) => {
                        if work_rx.is_closed() && work_rx.is_empty() {
                            break;
                        }
                    }
                    work = work_rx.recv(), if worker_id < active.load(Ordering::Relaxed) => {
                        match work {
                            Ok(domain) => {
                                let (proxy_idx, proxy) = if proxies.is_empty() {
                                    (None, None)
                                } else {
                                    let mut idx = proxy_index.fetch_add(1, Ordering::Relaxed) % proxies.len();
                                    for _ in 0..proxies.len() {
                                        if proxy_fails[idx].load(Ordering::Relaxed) < 5 {
                                            break;
                                        }
                                        idx = proxy_index.fetch_add(1, Ordering::Relaxed) % proxies.len();
                                    }
                                    (Some(idx), Some(proxies[idx].clone()))
                                };

                                let scan_fut = scan_domain(
                                    &client,
                                    &fallback_client,
                                    &tls_connector,
                                    browser_binary.as_deref(),
                                    domain.clone(),
                                    &matcher,
                                    proxy.as_ref(),
                                    timeout_secs,
                                    max_redirects,
                                    max_body_size,
                                    verbose,
                                    worker_scan_policy,
                                );
                                let res = tokio::select! {
                                    () = ct.cancelled() => break,
                                    r = scan_fut => r,
                                };
                                let res = match res {
                                    Ok(r) => r,
                                    Err(e) => with_evidence(
                                        build_scan_result(
                                            domain.clone(),
                                            DomainStatus::Dead,
                                            Verdict::Unreachable,
                                            40,
                                            None,
                                            format!("Error: {e}"),
                                            None,
                                        ),
                                        EvidenceBundle {
                                            source: Some("scanner".to_string()),
                                            path: Some("/".to_string()),
                                            final_url: None,
                                            title: None,
                                            signal: Some("worker error".to_string()),
                                        },
                                    ),
                                };

                                if let Some(idx) = proxy_idx {
                                    if matches!(res.verdict, Verdict::Unreachable | Verdict::TlsFailure | Verdict::NetworkBlocked) {
                                        proxy_fails[idx].fetch_add(1, Ordering::Relaxed);
                                    } else {
                                        proxy_fails[idx].store(0, Ordering::Relaxed);
                                    }
                                }

                                if logger_tx.send(res).await.is_err() { break; }
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
        }));
    }
    drop(logger_tx);

    // 5b. Arrow-key listener
    let ui_shutdown = tokio_util::sync::CancellationToken::new();
    let ui_shutdown_for_keys = ui_shutdown.clone();

    let ct_for_keys = cancel_token.clone();
    let bar_for_keys = bar.clone();
    let active_for_keys = active_concurrency.clone();

    let key_thread = std::thread::spawn(move || {
        use crossterm::event::{self, Event, KeyCode, KeyEventKind};
        use crossterm::terminal;

        // Tier start values — Left/Right jump between them.
        // Safe 1-50, Standard 51-100, Balanced 101-200 … Aggressive 901-1000.
        const TIERS: &[usize] = &[1, 51, 101, 201, 301, 401, 501, 601, 701, 801, 1000];

        if terminal::enable_raw_mode().is_err() {
            return;
        }

        loop {
            if ui_shutdown_for_keys.is_cancelled() || ct_for_keys.is_cancelled() {
                break;
            }

            if let Ok(true) = event::poll(std::time::Duration::from_millis(100)) {
                // Re-check shutdown after poll returns to avoid reading a stale event
                if ui_shutdown_for_keys.is_cancelled() || ct_for_keys.is_cancelled() {
                    break;
                }
                let Ok(ev) = event::read() else { break };

                // Resize is handled automatically: the next draw tick uses \r\x1b[J
                // which clears any ghost lines from the old terminal width.
                let Event::Key(key) = ev else {
                    continue;
                };

                if key.kind != KeyEventKind::Press {
                    continue;
                }

                let current = active_for_keys.load(Ordering::Relaxed);

                match key.code {
                    KeyCode::Right => {
                        // Jump to start of next tier above current.
                        let next = TIERS
                            .iter()
                            .find(|&&t| t > current)
                            .copied()
                            .unwrap_or(1000)
                            .min(1000);
                        active_for_keys.store(next, Ordering::Relaxed);
                    }
                    KeyCode::Left => {
                        // Jump to start of previous tier below current.
                        let next = TIERS
                            .iter()
                            .rev()
                            .find(|&&t| t < current)
                            .copied()
                            .unwrap_or(1)
                            .max(1);
                        active_for_keys.store(next, Ordering::Relaxed);
                    }
                    KeyCode::Up => {
                        let next = (current + 1).min(1000);
                        active_for_keys.store(next, Ordering::Relaxed);
                    }
                    KeyCode::Down => {
                        let next = current.saturating_sub(1).max(1);
                        active_for_keys.store(next, Ordering::Relaxed);
                    }
                    KeyCode::Char('q') | KeyCode::Esc => {
                        bar_for_keys.println("🥔 Cancelled by user (q)");
                        ct_for_keys.cancel();
                        break;
                    }
                    _ => {}
                }
            }
        }
        let _ = terminal::disable_raw_mode();
    });

    // 6. Monitor
    let mut worker_join = Box::pin(futures::future::join_all(workers));

    let cancelled_by_outer_signal = if global_timeout_secs > 0 {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                cancel_token.cancel();
                true
            }
            () = tokio::time::sleep(Duration::from_secs(global_timeout_secs)) => {
                cancel_token.cancel();
                true
            }
            _ = &mut worker_join => false,
        }
    } else {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                cancel_token.cancel();
                true
            }
            _ = &mut worker_join => false,
        }
    };

    if cancelled_by_outer_signal {
        let _ = worker_join.await;
    } else {
        let worker_results = worker_join.await;
        for result in worker_results {
            result?;
        }
    }

    if let Err(e) = feeder_handle.await {
        bar.println(format!("Feeder error: {e}"));
    }

    let all_results = logger_handle.await??;

    ui_shutdown.cancel();
    if let Err(e) = key_thread.join() {
        eprintln!("key listener thread panicked: {e:?}");
    }

    let was_cancelled = cancelled_by_outer_signal || cancel_token.is_cancelled();

    if was_cancelled {
        bar.finish(if potato {
            "⏹ The potato has been mashed (Cancelled)"
        } else {
            "⏹ Scan cancelled"
        });
        draw_thread.join().ok();
        return Ok(None);
    }

    let done_style = Style::new().green().bold();
    bar.finish(format!(
        "{}",
        done_style.apply_to(if potato {
            "✔ Potatoes harvested! (Scan complete)"
        } else {
            "✔ Scan complete"
        })
    ));
    draw_thread.join().ok();

    let final_workers = active_concurrency.load(Ordering::Relaxed);
    Ok(Some((all_results, final_workers)))
}

fn pick_preferred_result(initial: ScanResult, retry: ScanResult) -> ScanResult {
    let retry_wins = (matches!(retry.verdict, Verdict::Accessible)
        && matches!(initial.verdict, Verdict::WafBlocked | Verdict::Captcha))
        || verdict_rank(&retry) > verdict_rank(&initial)
        || (verdict_rank(&retry) == verdict_rank(&initial)
            && retry.confidence > initial.confidence);

    if retry_wins { retry } else { initial }
}

/// Read up to `max_body_size` bytes from any response type that exposes
/// `async fn chunk(&mut self) -> Result<Option<Bytes>>`. Using a macro
/// avoids duplicating identical logic across `wreq::Response` and
/// `reqwest::Response` which share the same API but have no common trait.
macro_rules! read_body_limited {
    ($response:expr, $max_body_size:expr) => {{
        let max = $max_body_size;
        let mut body = Vec::with_capacity(max.min(65_536));
        loop {
            match $response.chunk().await {
                Ok(Some(chunk)) => {
                    let remaining = max.saturating_sub(body.len());
                    if remaining == 0 {
                        break;
                    }
                    body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
                    if body.len() >= max {
                        break;
                    }
                }
                Ok(None) => break,
                Err(err) => return Err(err.into()),
            }
        }
        anyhow::Ok(body)
    }};
}

async fn read_wreq_body_limited(
    response: &mut wreq::Response,
    max_body_size: usize,
) -> anyhow::Result<Vec<u8>> {
    read_body_limited!(response, max_body_size)
}

async fn read_reqwest_body_limited(
    response: &mut reqwest::Response,
    max_body_size: usize,
) -> anyhow::Result<Vec<u8>> {
    read_body_limited!(response, max_body_size)
}

fn probe_paths_for_domain(domain: &str) -> Vec<String> {
    service_profiles::probe_paths(domain)
}

fn should_try_secondary_probes(result: &ScanResult, domain: &str) -> bool {
    probe_paths_for_domain(domain).len() > 1
        && !matches!(result.verdict, Verdict::GeoBlocked | Verdict::Captcha)
        && result.confidence < 95
}

fn is_meaningful_secondary_result(result: &ScanResult) -> bool {
    if matches!(result.verdict, Verdict::Accessible) {
        return false;
    }

    if matches!(result.verdict, Verdict::UnexpectedStatus)
        && matches!(result.http_status, Some(404 | 405 | 410))
    {
        return false;
    }

    true
}

#[allow(clippy::too_many_lines)]
#[allow(clippy::too_many_arguments)]
async fn scan_domain_once(
    client: &Client,
    fallback_client: &FallbackClient,
    tls_connector: &RustlsTlsConnector,
    browser_binary: Option<&Path>,
    domain: String,
    matcher: &signatures::BlockMatcher,
    proxy: Option<&String>,
    timeout_secs: u64,
    max_redirects: usize,
    max_body_size: usize,
    verbose: bool,
    scan_policy: ScanPolicy,
) -> anyhow::Result<ScanResult> {
    let network_evidence =
        collect_network_evidence(&domain, proxy, timeout_secs, tls_connector).await;
    let mut best_result = check_domain(
        client,
        fallback_client,
        domain.clone(),
        matcher,
        proxy,
        timeout_secs,
        max_redirects,
        max_body_size,
        verbose,
    )
    .await?;

    if should_try_secondary_probes(&best_result, &domain) {
        for path in probe_paths_for_domain(&domain)
            .iter()
            .skip(1)
            .take(scan_policy.max_secondary_probes)
        {
            let probe_url = format!("https://{domain}{path}");
            let mut probe_result = check_domain(
                client,
                fallback_client,
                probe_url,
                matcher,
                proxy,
                timeout_secs,
                max_redirects,
                max_body_size,
                verbose,
            )
            .await?;
            probe_result.domain.clone_from(&domain);
            probe_result.reason = format!("Probe {path}: {}", probe_result.reason);
            probe_result.evidence.path = Some(path.clone());
            probe_result.evidence.source = Some("secondary_http".to_string());

            if !is_meaningful_secondary_result(&probe_result) {
                continue;
            }

            if verdict_rank(&probe_result) > verdict_rank(&best_result) {
                best_result = probe_result;
            }

            if matches!(best_result.verdict, Verdict::GeoBlocked) && best_result.confidence >= 90 {
                break;
            }
        }
    }

    if let Some(browser_path) = browser_binary
        && should_try_browser_verify(&best_result, &domain)
        && (proxy.is_none()
            || (scan_policy.allow_control_browser_verify
                && proxy
                    .and_then(|proxy| browser_proxy_server_arg(proxy))
                    .is_some()))
    {
        for path in probe_paths_for_domain(&domain)
            .iter()
            .take(scan_policy.max_browser_probe_paths)
        {
            let probe_url = format!("https://{domain}{path}");
            let browser_dom = tokio::time::timeout(
                Duration::from_secs(BROWSER_VERIFY_TIMEOUT_SECS),
                run_browser_dom_dump(browser_path, &probe_url, proxy.map(String::as_str)),
            )
            .await;

            let Ok(Ok(html)) = browser_dom else {
                continue;
            };

            let Some(mut browser_result) = classify_browser_html(&domain, matcher, &html) else {
                continue;
            };

            browser_result.reason = format!("Browser {path}: {}", browser_result.reason);
            browser_result.evidence.path = Some(path.clone());
            browser_result.evidence.final_url = Some(probe_url.clone());

            if verdict_rank(&browser_result) > verdict_rank(&best_result) {
                best_result = browser_result;
            }

            if matches!(
                best_result.verdict,
                Verdict::GeoBlocked | Verdict::WafBlocked
            ) && best_result.confidence >= 97
            {
                break;
            }
        }
    }

    best_result.network_evidence = network_evidence;
    Ok(best_result)
}

#[allow(clippy::too_many_arguments)]
async fn scan_domain(
    client: &Client,
    fallback_client: &FallbackClient,
    tls_connector: &RustlsTlsConnector,
    browser_binary: Option<&Path>,
    domain: String,
    matcher: &signatures::BlockMatcher,
    proxy: Option<&String>,
    timeout_secs: u64,
    max_redirects: usize,
    max_body_size: usize,
    verbose: bool,
    scan_policy: ScanPolicy,
) -> anyhow::Result<ScanResult> {
    let mut attempts = vec![
        scan_domain_once(
            client,
            fallback_client,
            tls_connector,
            browser_binary,
            domain.clone(),
            matcher,
            proxy,
            timeout_secs,
            max_redirects,
            max_body_size,
            verbose,
            scan_policy,
        )
        .await?,
    ];

    if should_try_retest(&attempts[0], scan_policy) {
        for attempt_idx in 0..scan_policy.retest_attempts {
            // For 429 RateLimited: honour Retry-After header (clamped 1-30 s)
            // then add exponential backoff. For all other verdicts use the
            // profile's flat backoff multiplied by attempt index.
            let backoff_ms = if attempts[0].verdict == Verdict::RateLimited {
                let retry_after_secs: u64 = attempts[0]
                    .reason
                    .split('|')
                    .find_map(|part| {
                        let p = part.trim();
                        p.strip_prefix("retry-after=")
                            .and_then(|s| s.parse::<u64>().ok())
                    })
                    .unwrap_or(0);
                // clamp header value to [1, 30] seconds, then add jitter
                let base_secs = retry_after_secs.clamp(1, 30);
                let jitter_ms = fastrand::u64(0..500);
                base_secs * 1_000 + jitter_ms
            } else {
                scan_policy.retest_backoff_ms * (attempt_idx as u64 + 1)
            };
            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;

            let retry = scan_domain_once(
                client,
                fallback_client,
                tls_connector,
                browser_binary,
                domain.clone(),
                matcher,
                proxy,
                timeout_secs,
                max_redirects,
                max_body_size,
                verbose,
                scan_policy,
            )
            .await?;
            let stable_with_previous =
                same_measurement(attempts.last().expect("attempt exists"), &retry);
            attempts.push(retry);
            if stable_with_previous {
                break;
            }
        }
    }

    Ok(stabilize_scan_attempts(attempts))
}

#[allow(clippy::too_many_lines)]
#[allow(clippy::too_many_arguments)]
async fn check_domain(
    client: &Client,
    fallback_client: &FallbackClient,
    domain: String,
    matcher: &signatures::BlockMatcher,
    proxy: Option<&String>,
    timeout_secs: u64,
    _max_redirects: usize,
    max_body_size: usize,
    verbose: bool,
) -> anyhow::Result<ScanResult> {
    let raw_domain = domain
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/');

    let url = if domain.starts_with("http") {
        domain.clone()
    } else {
        format!("https://{domain}")
    };

    let ua = signatures::get_random_user_agent();
    let mut response_res = send_with_retries(client, &url, ua, proxy, timeout_secs).await;

    if let Err(ref e) = response_res
        && classify_transport_error(&e.to_string()) == TransportErrorKind::TlsFailure
        && !domain.starts_with("http://")
    {
        let http_url = format!("http://{raw_domain}");
        let fallback_timeout = timeout_secs.clamp(3, 10);
        response_res = send_with_retries(client, &http_url, ua, proxy, fallback_timeout).await;
    }

    match response_res {
        Ok(mut response) => {
            let status = response.status();
            let code = status.as_u16();
            let status_label = status.to_string();
            let final_url = response.uri().to_string();
            let headers = response
                .headers()
                .iter()
                .filter_map(|(k, v)| {
                    v.to_str()
                        .ok()
                        .map(|val| (k.as_str().to_string(), val.to_string()))
                })
                .collect::<Vec<_>>();

            let body_raw = read_wreq_body_limited(&mut response, max_body_size).await?;

            let initial_result = analyze_http_observation(
                domain.clone(),
                matcher,
                code,
                &status_label,
                &final_url,
                &headers,
                &body_raw,
                verbose,
            );

            let should_ua_retry = matches!(
                initial_result.verdict,
                Verdict::WafBlocked | Verdict::Captcha
            ) && initial_result.confidence < 95;

            if should_ua_retry {
                let retry_ua = (0..8)
                    .map(|_| signatures::get_random_user_agent())
                    .find(|&u| u != ua)
                    .unwrap_or_else(signatures::get_random_user_agent);

                let cookie_header: Option<String> = {
                    let cookies: Vec<&str> = headers
                        .iter()
                        .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
                        .filter_map(|(_, v)| v.split(';').next())
                        .collect();

                    if cookies.is_empty() {
                        None
                    } else {
                        Some(cookies.join("; "))
                    }
                };

                let mut retry_req = build_request(client, &url, retry_ua, proxy, timeout_secs)?;
                if let Some(cookie_val) = cookie_header {
                    retry_req = retry_req.header("Cookie", cookie_val);
                }

                if let Ok(mut retry_resp) = retry_req.send().await {
                    let r_status = retry_resp.status();
                    let r_code = r_status.as_u16();
                    let r_label = r_status.to_string();
                    let r_final_url = retry_resp.uri().to_string();
                    let r_headers: Vec<(String, String)> = retry_resp
                        .headers()
                        .iter()
                        .filter_map(|(k, v)| {
                            v.to_str()
                                .ok()
                                .map(|val| (k.as_str().to_string(), val.to_string()))
                        })
                        .collect();

                    let r_body = read_wreq_body_limited(&mut retry_resp, max_body_size).await?;

                    let retry_result = analyze_http_observation(
                        domain.clone(),
                        matcher,
                        r_code,
                        &r_label,
                        &r_final_url,
                        &r_headers,
                        &r_body,
                        verbose,
                    );

                    return Ok(pick_preferred_result(initial_result, retry_result));
                }
            }

            Ok(initial_result)
        }
        Err(e) => {
            let reason = e.to_string();
            let kind = classify_transport_error(&reason);

            if kind == TransportErrorKind::Unreachable {
                let fallback_response = send_via_reqwest(fallback_client, &url, ua).await;

                if let Ok(mut response) = fallback_response {
                    let status = response.status();
                    let code = status.as_u16();
                    let status_label = status.to_string();
                    let final_url = response.url().as_str().to_owned();
                    let headers = response
                        .headers()
                        .iter()
                        .filter_map(|(k, v)| {
                            v.to_str()
                                .ok()
                                .map(|val| (k.as_str().to_string(), val.to_string()))
                        })
                        .collect::<Vec<_>>();

                    let body_raw = read_reqwest_body_limited(&mut response, max_body_size).await?;

                    return Ok(analyze_http_observation(
                        domain,
                        matcher,
                        code,
                        &status_label,
                        &final_url,
                        &headers,
                        &body_raw,
                        verbose,
                    ));
                }
            }

            let (verdict, confidence, block_type) = match kind {
                TransportErrorKind::TlsFailure => (Verdict::TlsFailure, 70, None),
                TransportErrorKind::Unreachable => (Verdict::Unreachable, 55, None),
            };

            let status = status_from_verdict(verdict);
            Ok(relax_infra_root_result(with_evidence(
                build_scan_result(
                    domain,
                    status,
                    verdict,
                    confidence,
                    None,
                    reason.clone(),
                    block_type,
                ),
                EvidenceBundle {
                    source: Some("transport".to_string()),
                    path: Some("/".to_string()),
                    final_url: Some(url),
                    title: None,
                    signal: Some(reason),
                },
            )))
        }
    }
}
