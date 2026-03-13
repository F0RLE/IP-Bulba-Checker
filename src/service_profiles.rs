//! Service profile registry — maps known hostnames to service names and roles.
//!
//! Profiles are loaded from a `profiles.toml` file located next to the binary at
//! startup. If the file is absent, the compiled-in copy is used as a fallback.
//! This means all 60+ service profiles can be updated by editing `profiles.toml`
//! without recompiling.
//!
//! # Extension
//! To add or modify services, edit `profiles.toml`. The format is documented
//! at the top of that file. No code changes required.

use std::sync::OnceLock;

use serde::Deserialize;

// ─── TOML Schema ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct TomlConfig {
    #[serde(default)]
    geo_markers: Option<TomlGeoMarkers>,
    services: Vec<TomlProfile>,
}

#[derive(Deserialize, Default, Clone)]
struct TomlGeoMarkers {
    #[serde(default)]
    title_keywords: Vec<String>,
}

#[derive(Deserialize)]
struct TomlProfile {
    name: String,
    browser_verification: bool,
    expected_roles: Vec<String>,
    critical_roles: Vec<String>,
    hosts: Vec<TomlHost>,
}

#[derive(Deserialize)]
struct TomlHost {
    domain: String,
    role: String,
    probe_paths: Vec<String>,
}

// ─── Runtime types ────────────────────────────────────────────────────────────

struct ProfileEntry {
    name: String,
    browser_verification: bool,
    expected_roles: Vec<String>,
    critical_roles: Vec<String>,
    hosts: Vec<HostEntry>,
}

struct HostEntry {
    domain: String,
    role: String,
    probe_paths: Vec<String>,
}

// ─── Public API types ─────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ServiceMatch {
    pub(crate) service_name: String,
    pub(crate) host_role: String,
    pub(crate) probe_paths: Vec<String>,
    pub(crate) browser_verification: bool,
}

// ─── Registry ─────────────────────────────────────────────────────────────────

/// Compiled-in TOML fallback — always present at compile time.
static BUILTIN_PROFILES: &str = include_str!("../profiles.toml");

struct ProfileRegistry {
    services: Vec<ProfileEntry>,
    geo_title_keywords: Vec<String>,
}

static REGISTRY: OnceLock<ProfileRegistry> = OnceLock::new();

fn load_registry() -> ProfileRegistry {
    // Try to load from disk — allows updating profiles without recompiling
    if let Some(exe_dir) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(std::path::Path::to_path_buf))
    {
        let path = exe_dir.join("profiles.toml");
        if path.exists()
            && let Ok(content) = std::fs::read_to_string(&path)
            && let Ok(config) = toml::from_str::<TomlConfig>(&content)
        {
            return build_registry(config);
        }
    }

    // Fallback: compiled-in copy
    let config: TomlConfig =
        toml::from_str(BUILTIN_PROFILES).expect("built-in profiles.toml must be valid TOML");
    build_registry(config)
}

fn build_registry(config: TomlConfig) -> ProfileRegistry {
    let services = config
        .services
        .into_iter()
        .map(|p| ProfileEntry {
            name: p.name,
            browser_verification: p.browser_verification,
            expected_roles: p.expected_roles,
            critical_roles: p.critical_roles,
            hosts: p
                .hosts
                .into_iter()
                .map(|h| HostEntry {
                    domain: h.domain,
                    role: h.role,
                    probe_paths: h.probe_paths,
                })
                .collect(),
        })
        .collect();

    let default_geo = vec![
        "region".into(),
        "country".into(),
        "unavailable".into(),
        "not available".into(),
        "not supported".into(),
        "restricted".into(),
        "blocked".into(),
        "недоступ".into(),
        "не поддерж".into(),
        "регион".into(),
        "стране".into(),
    ];

    ProfileRegistry {
        services,
        geo_title_keywords: config
            .geo_markers
            .map(|gm| gm.title_keywords)
            .filter(|v| !v.is_empty())
            .unwrap_or(default_geo),
    }
}

fn registry() -> &'static ProfileRegistry {
    REGISTRY.get_or_init(load_registry)
}

// ─── Host matching ────────────────────────────────────────────────────────────

fn normalize_host(target: &str) -> Option<&str> {
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

    if host.is_empty() { None } else { Some(host) }
}

fn host_matches(host: &str, expected: &str) -> bool {
    host == expected
        || (host.len() > expected.len()
            && host.ends_with(expected)
            && host.as_bytes()[host.len() - expected.len() - 1] == b'.')
}

// ─── Public API ───────────────────────────────────────────────────────────────

const DEFAULT_PROBE_PATHS: &[&str] = &["/"];
const DEFAULT_CRITICAL_ROLES: &[&str] = &["web", "auth", "console", "storefront", "player", "app"];

/// Find the best-matching service profile for a given target (URL or hostname).
pub(crate) fn match_target(domain: &str) -> Option<ServiceMatch> {
    let reg = REGISTRY.get_or_init(load_registry);
    let host = normalize_host(domain)?.to_ascii_lowercase();
    let mut best: Option<(usize, ServiceMatch)> = None;

    for profile in &reg.services {
        for host_entry in &profile.hosts {
            if host_matches(&host, &host_entry.domain) {
                let candidate = ServiceMatch {
                    service_name: profile.name.clone(),
                    host_role: host_entry.role.clone(),
                    probe_paths: host_entry.probe_paths.clone(),
                    browser_verification: profile.browser_verification,
                };

                if best
                    .as_ref()
                    .is_none_or(|(best_len, _)| host_entry.domain.len() > *best_len)
                {
                    best = Some((host_entry.domain.len(), candidate));
                }
            }
        }
    }

    best.map(|(_, m)| m)
}

/// Return the probe paths for a given target, or `["/"]` if unknown.
pub(crate) fn probe_paths(target: &str) -> Vec<String> {
    match_target(target).map_or_else(
        || {
            DEFAULT_PROBE_PATHS
                .iter()
                .map(ToString::to_string)
                .collect()
        },
        |m| m.probe_paths,
    )
}

/// Return true if browser verification should be attempted for this target.
pub(crate) fn should_use_browser_verification(domain: &str) -> bool {
    match_target(domain).is_some_and(|m| m.browser_verification)
}

/// Return the expected roles for a named service (empty if unknown).
pub(crate) fn expected_roles_for_service(service_name: &str) -> Vec<String> {
    registry()
        .services
        .iter()
        .find(|p| p.name == service_name)
        .map(|p| p.expected_roles.clone())
        .unwrap_or_default()
}

/// Return the critical roles for a named service. Returns empty for unknown services.
pub(crate) fn critical_roles_for_service(service_name: &str) -> Vec<String> {
    registry()
        .services
        .iter()
        .find(|p| p.name == service_name)
        .map(|p| p.critical_roles.clone())
        .unwrap_or_default()
}

pub(crate) fn title_supports_geo(title_lower: &str) -> bool {
    registry()
        .geo_title_keywords
        .iter()
        .any(|needle| title_lower.contains(needle))
}

/// Return true if `role` is a critical role for the given service.
///
/// - `None` service → uses the generic default critical roles.
/// - An unknown named service → returns `false` (no specific critical roles defined).
pub(crate) fn is_service_role_critical(service_name: Option<&str>, role: Option<&str>) -> bool {
    let Some(role) = role else {
        return false;
    };

    let critical: Vec<String> = match service_name {
        None => DEFAULT_CRITICAL_ROLES
            .iter()
            .map(ToString::to_string)
            .collect(),
        Some(name) => critical_roles_for_service(name),
    };

    critical.iter().any(|r| r == role)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_service_and_role_from_url() {
        let matched = match_target("https://platform.openai.com/login").unwrap();
        assert_eq!(matched.service_name, "OpenAI");
        assert_eq!(matched.host_role, "console");
    }

    #[test]
    fn preserves_service_specific_probe_paths() {
        let paths = probe_paths("www.strava.com");
        assert!(paths.iter().any(|p| p == "/login"));
        assert!(paths.iter().any(|p| p == "/register/free"));
    }

    #[test]
    fn prefers_more_specific_host_profile() {
        let matched = match_target("listen.tidal.com").unwrap();
        assert_eq!(matched.service_name, "TIDAL");
        assert_eq!(matched.host_role, "player");
    }

    #[test]
    fn expanded_ai_and_fintech_hosts_map_to_expected_roles() {
        let chat = match_target("chat.openai.com").unwrap();
        assert_eq!(chat.service_name, "OpenAI");
        assert_eq!(chat.host_role, "web");

        let upwork_api = match_target("api.upwork.com").unwrap();
        assert_eq!(upwork_api.service_name, "Upwork");
        assert_eq!(upwork_api.host_role, "api");

        let perplexity_api = match_target("api.perplexity.ai").unwrap();
        assert_eq!(perplexity_api.service_name, "Perplexity");
        assert_eq!(perplexity_api.host_role, "api");
    }

    #[test]
    fn expanded_streaming_and_music_hosts_map_to_expected_roles() {
        let max = match_target("www.max.com").unwrap();
        assert_eq!(max.service_name, "Max");
        assert_eq!(max.host_role, "playback");

        let disney_auth = match_target("auth.disneyplus.com").unwrap();
        assert_eq!(disney_auth.service_name, "Disney+");
        assert_eq!(disney_auth.host_role, "auth");

        let tidal_auth = match_target("login.tidal.com").unwrap();
        assert_eq!(tidal_auth.service_name, "TIDAL");
        assert_eq!(tidal_auth.host_role, "auth");
    }

    #[test]
    fn expanded_social_and_gaming_hosts_map_to_expected_roles() {
        let whatsapp = match_target("whatsapp.com").unwrap();
        assert_eq!(whatsapp.service_name, "Meta");
        assert_eq!(whatsapp.host_role, "web");

        let instagram_assets = match_target("cdninstagram.com").unwrap();
        assert_eq!(instagram_assets.service_name, "Meta");
        assert_eq!(instagram_assets.host_role, "assets");

        let playstation_api = match_target("playstation.net").unwrap();
        assert_eq!(playstation_api.service_name, "PlayStation");
        assert_eq!(playstation_api.host_role, "api");
    }

    #[test]
    fn expanded_short_video_and_security_hosts_map_to_expected_roles() {
        let tiktok_api = match_target("tiktokv.com").unwrap();
        assert_eq!(tiktok_api.service_name, "TikTok");
        assert_eq!(tiktok_api.host_role, "api");

        let tiktok_www = match_target("www.tiktok.com").unwrap();
        assert_eq!(tiktok_www.service_name, "TikTok");
        assert_eq!(tiktok_www.host_role, "app");

        let capcut = match_target("capcutapi.com").unwrap();
        assert_eq!(capcut.service_name, "TikTok");
        assert_eq!(capcut.host_role, "app");

        let capcut_web = match_target("www.capcut.com").unwrap();
        assert_eq!(capcut_web.service_name, "TikTok");
        assert_eq!(capcut_web.host_role, "app");

        let avast = match_target("avast.com").unwrap();
        assert_eq!(avast.service_name, "Avast");
        assert_eq!(avast.host_role, "web");
    }

    #[test]
    fn unknown_hosts_fall_back_to_root_probe() {
        let paths = probe_paths("example.com");
        assert_eq!(paths, vec!["/".to_string()]);
        assert!(!should_use_browser_verification("example.com"));
    }

    #[test]
    fn exposes_expected_roles_for_known_service() {
        let roles = expected_roles_for_service("OpenAI");
        assert!(roles.contains(&"web".to_string()));
        assert!(roles.contains(&"api".to_string()));

        let critical = critical_roles_for_service("OpenAI");
        assert!(critical.contains(&"web".to_string()));
        assert!(critical.contains(&"api".to_string()));
    }

    #[test]
    fn uses_neutral_coverage_for_unknown_services() {
        assert!(!is_service_role_critical(Some("Example"), Some("web")));
        assert!(!is_service_role_critical(Some("Example"), Some("assets")));
    }
}
