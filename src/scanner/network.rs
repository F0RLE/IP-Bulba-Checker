use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use tokio::net::{TcpStream, lookup_host};
use tokio_rustls::TlsConnector as RustlsTlsConnector;

use crate::signatures;

use super::transport::{build_fallback_client, host_for_target};
use super::types::{NetworkEvidence, ProbeEvidence, ProbeStatus};
use super::{DohResponse, NETWORK_PROBE_TIMEOUT_SECS};

/// SAFETY: TLS certificate verification is intentionally disabled.
///
/// This tool is a scanning/probing utility — it needs to complete TLS handshakes
/// to detect network-level blocks (connection reset, TLS failure, etc.), NOT to
/// establish trusted communication. We never send sensitive data over these
/// connections; we only observe what happens during the handshake and read the
/// response body for block signatures. This is standard practice for network
/// probing tools.
#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

pub(crate) fn build_tls_connector() -> RustlsTlsConnector {
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
        .with_no_client_auth();
    RustlsTlsConnector::from(Arc::new(config))
}

pub(crate) async fn resolve_host(host: &str, timeout_secs: u64) -> (ProbeEvidence, Vec<IpAddr>) {
    match tokio::time::timeout(Duration::from_secs(timeout_secs), lookup_host((host, 443))).await {
        Ok(Ok(resolved)) => {
            let mut ips = Vec::new();
            for addr in resolved {
                let ip = addr.ip();
                if !ips.contains(&ip) {
                    ips.push(ip);
                }
                if ips.len() >= 4 {
                    break;
                }
            }

            if ips.is_empty() {
                (ProbeEvidence::failed("resolved no addresses"), Vec::new())
            } else {
                let preview = ips
                    .iter()
                    .take(2)
                    .map(std::string::ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                (ProbeEvidence::ok(preview), ips)
            }
        }
        Ok(Err(err)) => (
            ProbeEvidence::failed(format!("dns lookup failed: {err}")),
            Vec::new(),
        ),
        Err(_) => (ProbeEvidence::failed("dns lookup timed out"), Vec::new()),
    }
}

fn preview_ip_list(ips: &[IpAddr]) -> String {
    ips.iter()
        .take(2)
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn short_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(16);
    for byte in bytes.iter().take(8) {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

pub(crate) async fn resolve_host_via_path_dns(
    host: &str,
    proxy: Option<&String>,
    timeout_secs: u64,
) -> ProbeEvidence {
    let endpoints = [
        format!("https://cloudflare-dns.com/dns-query?name={host}&type=A"),
        format!("https://dns.google/resolve?name={host}&type=A"),
    ];
    let proxy = proxy.map(std::string::String::as_str);
    let user_agent = signatures::get_random_user_agent();
    let mut last_error = None;

    for endpoint in endpoints {
        let client = match build_fallback_client(proxy, timeout_secs, 2) {
            Ok(client) => client,
            Err(err) => return ProbeEvidence::failed(err.to_string()),
        };

        let response = match client
            .get(&endpoint)
            .header("User-Agent", user_agent)
            .header("Accept", "application/dns-json")
            .send()
            .await
        {
            Ok(response) => response,
            Err(err) => {
                last_error = Some(err.to_string());
                continue;
            }
        };

        if !response.status().is_success() {
            last_error = Some(format!(
                "doh endpoint {} returned HTTP {}",
                endpoint,
                response.status()
            ));
            continue;
        }

        match response.json::<DohResponse>().await {
            Ok(payload) => {
                if payload.status != 0 {
                    last_error = Some(
                        payload
                            .comment
                            .unwrap_or_else(|| format!("doh status {}", payload.status)),
                    );
                    continue;
                }

                let ips = payload
                    .answers
                    .into_iter()
                    .filter(|answer| answer.record_type == 1)
                    .filter_map(|answer| answer.data.parse::<IpAddr>().ok())
                    .collect::<Vec<_>>();

                if ips.is_empty() {
                    last_error = Some("doh returned no A records".to_string());
                    continue;
                }

                return ProbeEvidence::ok(preview_ip_list(&ips));
            }
            Err(err) => {
                last_error = Some(format!("invalid doh response: {err}"));
            }
        }
    }

    ProbeEvidence::failed(last_error.unwrap_or_else(|| "path dns probe failed".to_string()))
}

pub(crate) async fn probe_tcp_port(ips: &[IpAddr], port: u16, timeout_secs: u64) -> ProbeEvidence {
    let mut last_error = None;

    for ip in ips {
        let addr = SocketAddr::new(*ip, port);
        match tokio::time::timeout(Duration::from_secs(timeout_secs), TcpStream::connect(addr))
            .await
        {
            Ok(Ok(stream)) => {
                let peer = stream
                    .peer_addr()
                    .map_or_else(|_| addr.to_string(), |peer| peer.to_string());
                return ProbeEvidence::ok(peer);
            }
            Ok(Err(err)) => last_error = Some(err.to_string()),
            Err(_) => last_error = Some(format!("tcp/{port} timed out")),
        }
    }

    ProbeEvidence::failed(
        last_error.unwrap_or_else(|| format!("no reachable address on tcp/{port}")),
    )
}

pub(crate) async fn probe_tls_443(
    host: &str,
    ips: &[IpAddr],
    tls_connector: &RustlsTlsConnector,
    timeout_secs: u64,
) -> ProbeEvidence {
    let mut last_error = None;
    let Ok(server_name) = ServerName::try_from(host.to_string()) else {
        return ProbeEvidence::failed("invalid tls server name");
    };

    for ip in ips {
        let addr = SocketAddr::new(*ip, 443);
        let tcp =
            tokio::time::timeout(Duration::from_secs(timeout_secs), TcpStream::connect(addr)).await;

        let stream = match tcp {
            Ok(Ok(stream)) => stream,
            Ok(Err(err)) => {
                last_error = Some(err.to_string());
                continue;
            }
            Err(_) => {
                last_error = Some("tcp/443 timed out before tls handshake".to_string());
                continue;
            }
        };

        match tokio::time::timeout(
            Duration::from_secs(timeout_secs),
            tls_connector.connect(server_name.clone(), stream),
        )
        .await
        {
            Ok(Ok(stream)) => {
                let mut detail = addr.to_string();
                if let Some(cert) = stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|certs| certs.first())
                {
                    let _ = write!(&mut detail, " cert={}", short_hex(cert.as_ref()));
                }
                return ProbeEvidence::ok(detail);
            }
            Ok(Err(err)) => last_error = Some(err.to_string()),
            Err(_) => last_error = Some("tls handshake timed out".to_string()),
        }
    }

    ProbeEvidence::failed(last_error.unwrap_or_else(|| "tls handshake failed".to_string()))
}

pub(crate) async fn collect_network_evidence(
    domain: &str,
    proxy: Option<&String>,
    timeout_secs: u64,
    tls_connector: &RustlsTlsConnector,
) -> NetworkEvidence {
    let Some(host) = host_for_target(domain) else {
        return NetworkEvidence {
            dns: ProbeEvidence::failed("invalid host"),
            path_dns: ProbeEvidence::failed("invalid host"),
            tcp_443: ProbeEvidence::skipped("invalid host"),
            tls_443: ProbeEvidence::skipped("invalid host"),
            tcp_80: ProbeEvidence::skipped("invalid host"),
        };
    };

    let probe_timeout = timeout_secs.clamp(2, NETWORK_PROBE_TIMEOUT_SECS);
    let path_dns = resolve_host_via_path_dns(&host, proxy, probe_timeout).await;

    if proxy.is_some() {
        return NetworkEvidence {
            dns: ProbeEvidence::skipped("proxy mode"),
            path_dns,
            tcp_443: ProbeEvidence::skipped("proxy mode"),
            tls_443: ProbeEvidence::skipped("proxy mode"),
            tcp_80: ProbeEvidence::skipped("proxy mode"),
        };
    }
    let (dns, ips) = resolve_host(&host, probe_timeout).await;

    if dns.status != ProbeStatus::Ok {
        return NetworkEvidence {
            dns,
            path_dns,
            tcp_443: ProbeEvidence::skipped("dns failed"),
            tls_443: ProbeEvidence::skipped("dns failed"),
            tcp_80: ProbeEvidence::skipped("dns failed"),
        };
    }

    let tcp_443 = probe_tcp_port(&ips, 443, probe_timeout).await;
    let tls_443 = if tcp_443.status == ProbeStatus::Ok {
        probe_tls_443(&host, &ips, tls_connector, probe_timeout).await
    } else {
        ProbeEvidence::skipped("tcp/443 failed")
    };
    let tcp_80 = probe_tcp_port(&ips, 80, probe_timeout).await;

    NetworkEvidence {
        dns,
        path_dns,
        tcp_443,
        tls_443,
        tcp_80,
    }
}
