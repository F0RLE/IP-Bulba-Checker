use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use reqwest::Client;

use crate::signatures;

use super::TRANSIENT_RETRY_ATTEMPTS;
use super::analysis::is_transient_error;
use super::types::{
    ControlProxyCheck, ControlProxyFailureKind, ControlProxyHealth, control_proxy_failure_label,
};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ProxyClientKey {
    proxy_url: String,
    timeout_secs: u64,
    max_redirects: usize,
}

static PROXY_CLIENT_CACHE: OnceLock<Mutex<HashMap<ProxyClientKey, Client>>> = OnceLock::new();

fn proxy_client_cache() -> &'static Mutex<HashMap<ProxyClientKey, Client>> {
    PROXY_CLIENT_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(crate) fn build_request(
    client: &Client,
    url: &str,
    user_agent: &str,
    proxy: Option<&String>,
    timeout_secs: u64,
    max_redirects: usize,
) -> anyhow::Result<reqwest::RequestBuilder> {
    if let Some(p) = proxy {
        let proxy_client = build_fallback_client(Some(p), timeout_secs, max_redirects)?;
        Ok(proxy_client
            .get(url)
            .header("User-Agent", user_agent)
            .timeout(Duration::from_secs(timeout_secs)))
    } else {
        Ok(client
            .get(url)
            .header("User-Agent", user_agent)
            .timeout(Duration::from_secs(timeout_secs)))
    }
}

pub(crate) async fn send_with_retries(
    client: &Client,
    url: &str,
    user_agent: &str,
    proxy: Option<&String>,
    timeout_secs: u64,
    max_redirects: usize,
) -> anyhow::Result<reqwest::Response> {
    let mut last_error = None;

    for attempt in 0..=TRANSIENT_RETRY_ATTEMPTS {
        let request = build_request(client, url, user_agent, proxy, timeout_secs, max_redirects)?;
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

    // Ensure there's a scheme so the URL parser can parse the host accurately
    let parseable_url = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    };

    if let Ok(parsed) = url::Url::parse(&parseable_url)
        && let Some(host) = parsed.host_str()
    {
        let host = host.trim_end_matches('.');
        if !host.is_empty() {
            return Some(host.to_string());
        }
    }

    None
}

fn sanitize_proxy_url(proxy_url: &str) -> String {
    if let Some((scheme, rest)) = proxy_url.split_once("://")
        && let Some((_, host_part)) = rest.rsplit_once('@')
    {
        return format!("{scheme}://{host_part}");
    }

    proxy_url.to_string()
}

fn proxy_check_with_detail(
    target: &str,
    kind: ControlProxyFailureKind,
    detail: impl Into<String>,
) -> ControlProxyCheck {
    ControlProxyCheck {
        target: target.to_string(),
        kind,
        detail: detail.into(),
    }
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
    let healthy = https_connect_ok;
    let mut notes = Vec::new();

    if !http_ok {
        notes.push(format!(
            "HTTP proxy preflight failed (non-fatal for comparison): {}",
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

pub(crate) async fn send_via_http(
    client: &Client,
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
) -> anyhow::Result<Client> {
    if let Some(proxy_url) = proxy {
        let key = ProxyClientKey {
            proxy_url: proxy_url.to_string(),
            timeout_secs,
            max_redirects,
        };

        if let Some(client) = proxy_client_cache()
            .lock()
            .expect("proxy client cache poisoned")
            .get(&key)
            .cloned()
        {
            return Ok(client);
        }

        let client = build_fallback_client_uncached(Some(proxy_url), timeout_secs, max_redirects)?;
        proxy_client_cache()
            .lock()
            .expect("proxy client cache poisoned")
            .insert(key, client.clone());
        return Ok(client);
    }

    build_fallback_client_uncached(None, timeout_secs, max_redirects)
}

fn build_fallback_client_uncached(
    proxy: Option<&str>,
    timeout_secs: u64,
    max_redirects: usize,
) -> anyhow::Result<Client> {
    let mut builder = Client::builder()
        .brotli(true)
        .gzip(true)
        .zstd(true)
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
    let fallback_client = match build_fallback_client(Some(proxy_url), timeout_secs, max_redirects)
    {
        Ok(client) => client,
        Err(err) => {
            return proxy_check_with_detail(
                target,
                ControlProxyFailureKind::UnknownFailure,
                err.to_string(),
            );
        }
    };

    match send_via_http(&fallback_client, target, user_agent).await {
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

            proxy_check_with_detail(target, kind, detail)
        }
        Err(err) => proxy_check_with_detail(
            target,
            classify_control_proxy_error(&err.to_string(), false, target.starts_with("https://")),
            err.to_string(),
        ),
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
    let fallback_client = build_fallback_client(Some(proxy_url), timeout_secs, max_redirects);

    let (https_example_check, https_trace_check) = if let Ok(fallback_client) = fallback_client {
        let https_example_check = match send_via_http(
            &fallback_client,
            "https://example.com/",
            signatures::get_random_user_agent(),
        )
        .await
        {
            Ok(response) => proxy_check_with_detail(
                "https://example.com/",
                if response.status() == reqwest::StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                    ControlProxyFailureKind::AuthFailed
                } else if response.status().is_server_error() {
                    ControlProxyFailureKind::UnknownFailure
                } else {
                    ControlProxyFailureKind::Ok
                },
                format!("HTTP {}", response.status().as_u16()),
            ),
            Err(err) => proxy_check_with_detail(
                "https://example.com/",
                classify_control_proxy_error(
                    &err.to_string(),
                    http_check.kind == ControlProxyFailureKind::Ok,
                    true,
                ),
                err.to_string(),
            ),
        };
        let https_trace_check = match send_via_http(
            &fallback_client,
            "https://cloudflare.com/cdn-cgi/trace",
            signatures::get_random_user_agent(),
        )
        .await
        {
            Ok(response) => proxy_check_with_detail(
                "https://cloudflare.com/cdn-cgi/trace",
                if response.status() == reqwest::StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                    ControlProxyFailureKind::AuthFailed
                } else if response.status().is_server_error() {
                    ControlProxyFailureKind::UnknownFailure
                } else {
                    ControlProxyFailureKind::Ok
                },
                format!("HTTP {}", response.status().as_u16()),
            ),
            Err(err) => proxy_check_with_detail(
                "https://cloudflare.com/cdn-cgi/trace",
                classify_control_proxy_error(
                    &err.to_string(),
                    http_check.kind == ControlProxyFailureKind::Ok,
                    true,
                ),
                err.to_string(),
            ),
        };
        (https_example_check, https_trace_check)
    } else {
        let detail = fallback_client
            .err()
            .map_or_else(|| "invalid proxy client".to_string(), |err| err.to_string());
        (
            proxy_check_with_detail(
                "https://example.com/",
                ControlProxyFailureKind::UnknownFailure,
                detail.clone(),
            ),
            proxy_check_with_detail(
                "https://cloudflare.com/cdn-cgi/trace",
                ControlProxyFailureKind::UnknownFailure,
                detail,
            ),
        )
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

#[cfg(test)]
mod tests {
    use super::{ControlProxyFailureKind, preflight_control_proxy};

    #[tokio::test]
    async fn invalid_control_proxy_does_not_panic() {
        let health = preflight_control_proxy("://bad-proxy", 3, 1).await;

        assert!(!health.healthy);
        assert_eq!(
            health.http_check.kind,
            ControlProxyFailureKind::UnknownFailure
        );
        assert_eq!(
            health.https_example_check.kind,
            ControlProxyFailureKind::UnknownFailure
        );
        assert_eq!(
            health.https_trace_check.kind,
            ControlProxyFailureKind::UnknownFailure
        );
        assert!(!health.http_check.detail.is_empty());
    }
}
