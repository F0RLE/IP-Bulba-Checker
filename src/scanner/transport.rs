use std::time::Duration;

use reqwest::Client as FallbackClient;
use wreq::Client;

use crate::signatures;

use super::TRANSIENT_RETRY_ATTEMPTS;
use super::analysis::is_transient_error;
use super::types::{
    ControlProxyCheck, ControlProxyFailureKind, ControlProxyHealth, control_proxy_failure_label,
};

pub(crate) fn build_request(
    client: &Client,
    url: &str,
    user_agent: &str,
    proxy: Option<&String>,
    timeout_secs: u64,
) -> anyhow::Result<wreq::RequestBuilder> {
    let mut builder = client
        .get(url)
        .header("User-Agent", user_agent)
        .timeout(Duration::from_secs(timeout_secs));

    if let Some(p) = proxy {
        let proxy_obj =
            wreq::Proxy::all(p).map_err(|e| anyhow::anyhow!("invalid proxy '{p}': {e}"))?;
        builder = builder.proxy(proxy_obj);
    }

    Ok(builder)
}

pub(crate) async fn send_with_retries(
    client: &Client,
    url: &str,
    user_agent: &str,
    proxy: Option<&String>,
    timeout_secs: u64,
) -> anyhow::Result<wreq::Response> {
    let mut last_error = None;

    for attempt in 0..=TRANSIENT_RETRY_ATTEMPTS {
        let request = build_request(client, url, user_agent, proxy, timeout_secs)?;
        match request.send().await {
            Ok(response) => return Ok(response),
            Err(err) => {
                let error_text = err.to_string();
                let should_retry =
                    attempt < TRANSIENT_RETRY_ATTEMPTS && is_transient_error(&error_text);
                last_error = Some(err);

                if should_retry {
                    tokio::time::sleep(Duration::from_millis(150 * (attempt as u64 + 1))).await;
                    continue;
                }
                break;
            }
        }
    }

    Err(last_error
        .expect("retry loop must capture the last error")
        .into())
}

pub(crate) fn host_for_target(target: &str) -> Option<String> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return None;
    }

    let without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    let host = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .trim()
        .trim_end_matches('.');

    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

fn sanitize_proxy_url(proxy_url: &str) -> String {
    if let Some((scheme, rest)) = proxy_url.split_once("://")
        && let Some((_, host_part)) = rest.rsplit_once('@')
    {
        return format!("{scheme}://{host_part}");
    }

    proxy_url.to_string()
}

pub(crate) fn classify_control_proxy_error(
    error: &str,
    http_ok: bool,
    is_https: bool,
) -> ControlProxyFailureKind {
    let lower = error.to_ascii_lowercase();

    if lower.contains("407")
        || lower.contains("proxy authentication")
        || lower.contains("authentication required")
    {
        return ControlProxyFailureKind::AuthFailed;
    }
    if lower.contains("timed out") || lower.contains("timeout") {
        return ControlProxyFailureKind::Timeout;
    }
    if is_https && http_ok {
        return ControlProxyFailureKind::HttpOnly;
    }
    if lower.contains("connect")
        || lower.contains("tunnel")
        || lower.contains("connection")
        || lower.contains("proxy")
    {
        return ControlProxyFailureKind::ConnectFailed;
    }

    ControlProxyFailureKind::UnknownFailure
}

pub(crate) fn evaluate_control_proxy_health(
    http_check: &ControlProxyCheck,
    https_example_check: &ControlProxyCheck,
    https_trace_check: &ControlProxyCheck,
) -> (bool, bool, bool, Vec<String>) {
    let http_ok = http_check.kind == ControlProxyFailureKind::Ok;
    let https_connect_ok = https_example_check.kind == ControlProxyFailureKind::Ok
        || https_trace_check.kind == ControlProxyFailureKind::Ok;
    let healthy = http_ok && https_connect_ok;
    let mut notes = Vec::new();

    if !http_ok {
        notes.push(format!(
            "HTTP proxy preflight failed: {}",
            control_proxy_failure_label(http_check.kind)
        ));
    }
    if !https_connect_ok {
        notes.push(format!(
            "HTTPS CONNECT preflight failed: example={} trace={}",
            control_proxy_failure_label(https_example_check.kind),
            control_proxy_failure_label(https_trace_check.kind)
        ));
    }

    (healthy, http_ok, https_connect_ok, notes)
}

pub(crate) fn should_run_control_comparison(health: &ControlProxyHealth) -> bool {
    health.healthy
}

pub(crate) async fn send_via_reqwest(
    client: &FallbackClient,
    url: &str,
    user_agent: &str,
) -> anyhow::Result<reqwest::Response> {
    let response = client
        .get(url)
        .header("User-Agent", user_agent)
        .send()
        .await?;
    Ok(response)
}

pub(crate) fn build_fallback_client(
    proxy: Option<&str>,
    timeout_secs: u64,
    max_redirects: usize,
) -> anyhow::Result<FallbackClient> {
    let mut builder = FallbackClient::builder()
        .brotli(true)
        .gzip(true)
        .zstd(true)
        .http2_adaptive_window(true)
        .redirect(reqwest::redirect::Policy::limited(max_redirects))
        .timeout(Duration::from_secs(timeout_secs));

    if let Some(proxy_url) = proxy {
        builder =
            builder
                .proxy(reqwest::Proxy::all(proxy_url).map_err(|err| {
                    anyhow::anyhow!("invalid reqwest proxy '{proxy_url}': {err}")
                })?);
    }

    Ok(builder.build()?)
}

async fn run_control_proxy_check(
    target: &str,
    proxy_url: &str,
    timeout_secs: u64,
    max_redirects: usize,
) -> ControlProxyCheck {
    let user_agent = signatures::get_random_user_agent();
    let fallback_client = build_fallback_client(Some(proxy_url), timeout_secs, max_redirects)
        .expect("should build proxy client for probe");

    match send_via_reqwest(&fallback_client, target, user_agent).await {
        Ok(response) => {
            let status = response.status();
            let detail = format!("HTTP {}", status.as_u16());
            let kind = if status == reqwest::StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                ControlProxyFailureKind::AuthFailed
            } else if status.is_server_error() {
                ControlProxyFailureKind::UnknownFailure
            } else {
                ControlProxyFailureKind::Ok
            };

            ControlProxyCheck {
                target: target.to_string(),
                kind,
                detail,
            }
        }
        Err(err) => ControlProxyCheck {
            target: target.to_string(),
            kind: classify_control_proxy_error(
                &err.to_string(),
                false,
                target.starts_with("https://"),
            ),
            detail: err.to_string(),
        },
    }
}

pub(crate) async fn preflight_control_proxy(
    proxy_url: &str,
    timeout_secs: u64,
    max_redirects: usize,
) -> ControlProxyHealth {
    let sanitized = sanitize_proxy_url(proxy_url);
    let http_check = run_control_proxy_check(
        "http://example.com/",
        proxy_url,
        timeout_secs,
        max_redirects,
    )
    .await;
    let fallback_client = build_fallback_client(Some(proxy_url), timeout_secs, max_redirects)
        .expect("should build proxy client for probe");

    let https_example_check = match send_via_reqwest(
        &fallback_client,
        "https://example.com/",
        signatures::get_random_user_agent(),
    )
    .await
    {
        Ok(response) => ControlProxyCheck {
            target: "https://example.com/".to_string(),
            kind: if response.status() == reqwest::StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                ControlProxyFailureKind::AuthFailed
            } else if response.status().is_server_error() {
                ControlProxyFailureKind::UnknownFailure
            } else {
                ControlProxyFailureKind::Ok
            },
            detail: format!("HTTP {}", response.status().as_u16()),
        },
        Err(err) => ControlProxyCheck {
            target: "https://example.com/".to_string(),
            kind: classify_control_proxy_error(
                &err.to_string(),
                http_check.kind == ControlProxyFailureKind::Ok,
                true,
            ),
            detail: err.to_string(),
        },
    };
    let https_trace_check = match send_via_reqwest(
        &fallback_client,
        "https://cloudflare.com/cdn-cgi/trace",
        signatures::get_random_user_agent(),
    )
    .await
    {
        Ok(response) => ControlProxyCheck {
            target: "https://cloudflare.com/cdn-cgi/trace".to_string(),
            kind: if response.status() == reqwest::StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                ControlProxyFailureKind::AuthFailed
            } else if response.status().is_server_error() {
                ControlProxyFailureKind::UnknownFailure
            } else {
                ControlProxyFailureKind::Ok
            },
            detail: format!("HTTP {}", response.status().as_u16()),
        },
        Err(err) => ControlProxyCheck {
            target: "https://cloudflare.com/cdn-cgi/trace".to_string(),
            kind: classify_control_proxy_error(
                &err.to_string(),
                http_check.kind == ControlProxyFailureKind::Ok,
                true,
            ),
            detail: err.to_string(),
        },
    };

    let (healthy, http_ok, https_connect_ok, notes) =
        evaluate_control_proxy_health(&http_check, &https_example_check, &https_trace_check);

    ControlProxyHealth {
        proxy_url: sanitized,
        healthy,
        http_ok,
        https_connect_ok,
        http_check,
        https_example_check,
        https_trace_check,
        notes,
    }
}
