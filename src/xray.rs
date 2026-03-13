use anyhow::{Context, anyhow, bail};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use url::Url;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransportKind {
    Raw,
    WebSocket,
    HttpUpgrade,
    Grpc,
    Xhttp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SecurityKind {
    None,
    Tls,
    Reality,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VlessControlLink {
    id: String,
    address: String,
    port: u16,
    transport: TransportKind,
    security: SecurityKind,
    server_name: Option<String>,
    fingerprint: Option<String>,
    flow: Option<String>,
    path: Option<String>,
    host: Option<String>,
    mode: Option<String>,
    service_name: Option<String>,
    authority: Option<String>,
    alpn: Vec<String>,
    reality_password: Option<String>,
    reality_short_id: Option<String>,
    reality_spider_x: Option<String>,
}

/// Generated local Xray client configuration and the matching SOCKS proxy URL.
#[derive(Clone, Debug, PartialEq)]
pub struct GeneratedXrayClientConfig {
    /// Local listen address for the generated SOCKS inbound.
    pub socks_listen: String,
    /// Proxy URL to pass to `--proxy` or `--control-proxy`.
    pub socks_proxy_url: String,
    /// Xray client configuration payload.
    pub config: Value,
}

fn parse_transport(value: Option<&str>) -> anyhow::Result<TransportKind> {
    match value.unwrap_or("tcp").to_ascii_lowercase().as_str() {
        "tcp" | "raw" => Ok(TransportKind::Raw),
        "ws" | "websocket" => Ok(TransportKind::WebSocket),
        "httpupgrade" | "http-upgrade" => Ok(TransportKind::HttpUpgrade),
        "grpc" => Ok(TransportKind::Grpc),
        "xhttp" | "splithttp" => Ok(TransportKind::Xhttp),
        other => bail!("unsupported VLESS transport '{other}'"),
    }
}

fn parse_security(value: Option<&str>) -> anyhow::Result<SecurityKind> {
    match value.unwrap_or("none").to_ascii_lowercase().as_str() {
        "none" => Ok(SecurityKind::None),
        "tls" => Ok(SecurityKind::Tls),
        "reality" => Ok(SecurityKind::Reality),
        other => bail!("unsupported VLESS security '{other}'"),
    }
}

fn parse_query_map(url: &Url) -> BTreeMap<String, String> {
    url.query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect()
}

fn normalize_optional(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn parse_listen_endpoint(listen: &str) -> anyhow::Result<(String, u16)> {
    if let Ok(parsed) = listen.parse::<SocketAddr>() {
        return Ok((parsed.ip().to_string(), parsed.port()));
    }

    let (host, port) = listen
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("listen address must be in HOST:PORT format"))?;
    let port = port
        .parse::<u16>()
        .with_context(|| format!("invalid SOCKS listen port in '{listen}'"))?;
    let host = host.trim().trim_matches('[').trim_matches(']');
    if host.is_empty() {
        bail!("listen host is empty");
    }

    Ok((host.to_string(), port))
}

fn build_socks_proxy_url(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("socks5h://[{host}]:{port}")
    } else {
        format!("socks5h://{host}:{port}")
    }
}

fn parse_vless_control_link(link: &str) -> anyhow::Result<VlessControlLink> {
    let url = Url::parse(link).with_context(|| "failed to parse VLESS control link")?;
    if url.scheme() != "vless" {
        bail!("unsupported control link scheme '{}'", url.scheme());
    }

    let query = parse_query_map(&url);
    let transport = parse_transport(query.get("type").map(String::as_str))?;
    let security = parse_security(query.get("security").map(String::as_str))?;
    let id = url.username().trim();
    if id.is_empty() {
        bail!("VLESS link is missing the client UUID");
    }

    let address = url
        .host_str()
        .ok_or_else(|| anyhow!("VLESS link is missing the server address"))?
        .to_string();
    let port = url.port().unwrap_or(443);
    let server_name = normalize_optional(
        query
            .get("sni")
            .cloned()
            .or_else(|| query.get("serverName").cloned())
            .or_else(|| query.get("host").cloned()),
    );
    let fingerprint = normalize_optional(
        query
            .get("fp")
            .cloned()
            .or_else(|| query.get("fingerprint").cloned()),
    );
    let path = normalize_optional(query.get("path").cloned());
    let host = normalize_optional(query.get("host").cloned());
    let mode = normalize_optional(query.get("mode").cloned());
    let flow = normalize_optional(query.get("flow").cloned());
    let service_name = normalize_optional(
        query
            .get("serviceName")
            .cloned()
            .or_else(|| query.get("service_name").cloned()),
    );
    let authority = normalize_optional(query.get("authority").cloned());
    let alpn = query
        .get("alpn")
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let reality_password = normalize_optional(
        query
            .get("password")
            .cloned()
            .or_else(|| query.get("pbk").cloned()),
    );
    let reality_short_id = normalize_optional(
        query
            .get("shortId")
            .cloned()
            .or_else(|| query.get("sid").cloned()),
    );
    let reality_spider_x = normalize_optional(
        query
            .get("spiderX")
            .cloned()
            .or_else(|| query.get("spx").cloned()),
    );

    if matches!(security, SecurityKind::Reality) && reality_password.is_none() {
        bail!("REALITY link is missing 'pbk' or 'password'");
    }
    if matches!(security, SecurityKind::Reality) && server_name.is_none() {
        bail!("REALITY link is missing 'sni' or equivalent server name");
    }
    if matches!(transport, TransportKind::Grpc) && service_name.is_none() {
        bail!("gRPC transport requires 'serviceName'");
    }

    Ok(VlessControlLink {
        id: id.to_string(),
        address,
        port,
        transport,
        security,
        server_name,
        fingerprint,
        flow,
        path,
        host,
        mode,
        service_name,
        authority,
        alpn,
        reality_password,
        reality_short_id,
        reality_spider_x,
    })
}

fn transport_settings(link: &VlessControlLink) -> Option<(&'static str, Value)> {
    match link.transport {
        TransportKind::Raw => None,
        TransportKind::WebSocket => Some((
            "wsSettings",
            json!({
                "path": link.path.clone().unwrap_or_else(|| "/".to_string()),
                "headers": {
                    "Host": link.host.clone().unwrap_or_default(),
                }
            }),
        )),
        TransportKind::HttpUpgrade => Some((
            "httpupgradeSettings",
            json!({
                "path": link.path.clone().unwrap_or_else(|| "/".to_string()),
                "host": link.host.clone().unwrap_or_default(),
            }),
        )),
        TransportKind::Grpc => Some((
            "grpcSettings",
            json!({
                "serviceName": link.service_name.clone().unwrap_or_default(),
                "authority": link.authority.clone().unwrap_or_default(),
            }),
        )),
        TransportKind::Xhttp => Some((
            "xhttpSettings",
            json!({
                "path": link.path.clone().unwrap_or_else(|| "/".to_string()),
                "host": link.host.clone().unwrap_or_default(),
                "mode": link.mode.clone().unwrap_or_else(|| "auto".to_string()),
            }),
        )),
    }
}

fn security_settings(link: &VlessControlLink) -> Option<(&'static str, Value)> {
    match link.security {
        SecurityKind::None => None,
        SecurityKind::Tls => Some((
            "tlsSettings",
            json!({
                "serverName": link.server_name.clone().unwrap_or_default(),
                "fingerprint": link.fingerprint.clone().unwrap_or_else(|| "chrome".to_string()),
                "alpn": link.alpn,
            }),
        )),
        SecurityKind::Reality => Some((
            "realitySettings",
            json!({
                "serverName": link.server_name.clone().unwrap_or_default(),
                "fingerprint": link.fingerprint.clone().unwrap_or_else(|| "chrome".to_string()),
                "password": link.reality_password.clone().unwrap_or_default(),
                "shortId": link.reality_short_id.clone().unwrap_or_default(),
                "spiderX": link.reality_spider_x.clone().unwrap_or_else(|| "/".to_string()),
            }),
        )),
    }
}

fn outbound_user(link: &VlessControlLink) -> Value {
    let mut user = json!({
        "id": link.id,
        "encryption": "none",
    });

    if let Some(flow) = &link.flow
        && let Some(object) = user.as_object_mut()
    {
        object.insert("flow".to_string(), Value::String(flow.clone()));
    }

    user
}

/// Generate a local Xray client config that exposes a SOCKS5 proxy for scanner control-vantage.
pub fn generate_xray_socks_client_config(
    control_link: &str,
    socks_listen: &str,
) -> anyhow::Result<GeneratedXrayClientConfig> {
    let link = parse_vless_control_link(control_link)?;
    let (listen_host, listen_port) = parse_listen_endpoint(socks_listen)?;
    let socks_proxy_url = build_socks_proxy_url(&listen_host, listen_port);

    let mut stream_settings = json!({
        "network": match link.transport {
            TransportKind::Raw => "raw",
            TransportKind::WebSocket => "ws",
            TransportKind::HttpUpgrade => "httpupgrade",
            TransportKind::Grpc => "grpc",
            TransportKind::Xhttp => "xhttp",
        },
        "security": match link.security {
            SecurityKind::None => "none",
            SecurityKind::Tls => "tls",
            SecurityKind::Reality => "reality",
        },
    });

    if let Some((field, value)) = transport_settings(&link)
        && let Some(object) = stream_settings.as_object_mut()
    {
        object.insert(field.to_string(), value);
    }
    if let Some((field, value)) = security_settings(&link)
        && let Some(object) = stream_settings.as_object_mut()
    {
        object.insert(field.to_string(), value);
    }

    let config = json!({
        "log": {
            "loglevel": "warning",
        },
        "dns": {
            "servers": ["1.1.1.1", "8.8.8.8", "localhost"],
        },
        "inbounds": [
            {
                "tag": "local-socks",
                "listen": listen_host,
                "port": listen_port,
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
                    "udp": true,
                },
                "sniffing": {
                    "enabled": true,
                    "destOverride": ["http", "tls"],
                },
            }
        ],
        "outbounds": [
            {
                "tag": "control-proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": link.address,
                            "port": link.port,
                            "users": [outbound_user(&link)],
                        }
                    ]
                },
                "streamSettings": stream_settings,
                "mux": {
                    "enabled": false,
                },
            },
            {
                "tag": "direct",
                "protocol": "freedom",
            },
            {
                "tag": "blocked",
                "protocol": "blackhole",
            }
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {
                    "type": "field",
                    "inboundTag": ["local-socks"],
                    "outboundTag": "control-proxy",
                }
            ]
        }
    });

    Ok(GeneratedXrayClientConfig {
        socks_listen: format!("{listen_host}:{listen_port}"),
        socks_proxy_url,
        config,
    })
}

#[cfg(test)]
mod tests {
    use super::generate_xray_socks_client_config;

    #[test]
    fn generates_reality_xhttp_client_config_from_vless_link() {
        let generated = generate_xray_socks_client_config(
            "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?type=xhttp&path=%2Fv-api&host=dl.google.com&mode=auto&security=reality&pbk=PUBLICKEY123&fp=chrome&sni=dl.google.com&sid=77cc&spx=%2F#demo",
            "127.0.0.1:1080",
        )
        .expect("config should be generated");

        assert_eq!(generated.socks_proxy_url, "socks5h://127.0.0.1:1080");
        assert_eq!(generated.config["inbounds"][0]["protocol"], "socks");
        assert_eq!(
            generated.config["outbounds"][0]["streamSettings"]["network"],
            "xhttp"
        );
        assert_eq!(
            generated.config["outbounds"][0]["streamSettings"]["realitySettings"]["password"],
            "PUBLICKEY123"
        );
        assert_eq!(
            generated.config["outbounds"][0]["streamSettings"]["xhttpSettings"]["path"],
            "/v-api"
        );
    }

    #[test]
    fn rejects_reality_link_without_public_key() {
        let err = generate_xray_socks_client_config(
            "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?type=xhttp&security=reality&sni=dl.google.com",
            "127.0.0.1:1080",
        )
        .expect_err("REALITY without key should fail");

        assert!(err.to_string().contains("pbk"));
    }
}
