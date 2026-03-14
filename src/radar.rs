use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;
use rquest::Client;

#[derive(Debug, Serialize, Deserialize)]
pub struct RadarRankingResponse {
    pub result: Option<RadarRankingResult>,
    pub success: bool,
    pub errors: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RadarRankingResult {
    #[serde(flatten)]
    pub buckets: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RadarDomain {
    pub domain: String,
    pub rank: u32,
}

pub struct RadarClient {
    client: Client,
    token: Option<String>,
}

impl RadarClient {
    pub fn new(token: Option<String>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .cert_verification(false)
            .build()
            .expect("Failed to build Radar client");

        Self { client, token }
    }

    pub async fn fetch_top_domains(&self, limit: u32) -> anyhow::Result<Vec<String>> {
        if self.token.is_none() {
            anyhow::bail!(
                "Cloudflare Radar requires an API token. Pass --radar-token or set CLOUDFLARE_RADAR_TOKEN."
            );
        }

        // Cloudflare Radar /ranking/top currently enforces a maximum limit of 100.
        // It does NOT support deep pagination via 'page' or 'offset' on this endpoint.
        let current_limit = limit.min(100);
        if limit > 100 {
            println!(
                "Note: Cloudflare Radar top API is currently limited to 100 domains per request."
            );
        }

        let url =
            format!("https://api.cloudflare.com/client/v4/radar/ranking/top?limit={current_limit}");

        let mut request = self.client.get(&url);
        if let Some(ref token) = self.token {
            request = request.header("Authorization", format!("Bearer {token}"));
        }

        let response: RadarRankingResponse = request.send().await?.json().await?;

        if !response.success {
            let error_msg = format_api_error(&response.errors);
            return Err(anyhow::anyhow!("Cloudflare Radar Error: {error_msg}"));
        }

        let result = response.result.ok_or_else(|| {
            anyhow::anyhow!(
                "Cloudflare Radar returned success=true but result was null or missing."
            )
        })?;

        let top_domains = result
            .buckets
            .iter()
            .find_map(|(key, value)| {
                if !key.starts_with("top_") {
                    return None;
                }
                serde_json::from_value::<Vec<RadarDomain>>(value.clone()).ok()
            })
            .ok_or_else(|| {
                anyhow::anyhow!("Cloudflare Radar response did not contain a top_* domain bucket.")
            })?;

        Ok(top_domains.into_iter().map(|d| d.domain).collect())
    }
}

fn format_api_error(errors: &[serde_json::Value]) -> String {
    if let Some(err) = errors.first() {
        format!(
            "{} (code: {})",
            err.get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("Unknown error"),
            err.get("code")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0)
        )
    } else {
        "Unknown Radar API error".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::{RadarRankingResponse, format_api_error};

    #[test]
    fn parses_null_result_without_failing_deserialization() {
        let payload = r#"{
            "success": false,
            "errors": [{"code": 9106, "message": "Missing Authorization"}],
            "result": null
        }"#;
        let parsed: RadarRankingResponse = serde_json::from_str(payload).unwrap();
        assert!(!parsed.success);
        assert!(parsed.result.is_none());
        assert_eq!(
            format_api_error(&parsed.errors),
            "Missing Authorization (code: 9106)"
        );
    }

    #[test]
    fn parses_top_bucket_response_shape() {
        let payload = r#"{
            "success": true,
            "errors": [],
            "result": {
                "top_0": [
                    {"rank": 1, "domain": "google.com"},
                    {"rank": 2, "domain": "cloudflare.com"}
                ],
                "meta": {"top_0": {"date": "2026-03-09"}}
            }
        }"#;
        let parsed: RadarRankingResponse = serde_json::from_str(payload).unwrap();
        let result = parsed.result.unwrap();
        let top_domains: Vec<super::RadarDomain> =
            serde_json::from_value(result.buckets["top_0"].clone()).unwrap();
        assert_eq!(top_domains.len(), 2);
        assert_eq!(top_domains[0].domain, "google.com");
    }
}
