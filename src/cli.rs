//! CLI argument definitions, enums, and domain-parsing utilities.
//!
//! This module owns the public interface visible to the user: the `Args` struct,
//! the scan/export/format profile enums, and all functions that parse domain
//! input files into the canonical `(domain, expected_outcome)` representation.

use std::path::PathBuf;

use clap::{Parser, ValueEnum};

use crate::validation;

// ─── Domain parsing ───────────────────────────────────────────────────────────

/// Convert a keyword like `"geo"` into an expected outcome annotation.
pub(crate) fn parse_expected_outcome(input: &str) -> Option<validation::ExpectedOutcome> {
    match input.trim().to_ascii_lowercase().as_str() {
        "geo" | "geo_blocked" | "blocked" => Some(validation::ExpectedOutcome::Geo),
        "waf" | "challenge" | "captcha" => Some(validation::ExpectedOutcome::Waf),
        "direct" | "ok" | "accessible" | "control" => Some(validation::ExpectedOutcome::Direct),
        _ => None,
    }
}

/// Parse one line from a domain list file.
///
/// Supports plain domains, annotated lines (`geo domain.com`), and all
/// common list prefixes (`full:`, `DOMAIN-SUFFIX,`, `domain:`, …).
/// Returns `None` for blank lines and comments.
pub(crate) fn parse_annotated_domain_line(
    input: &str,
) -> Option<(String, Option<validation::ExpectedOutcome>)> {
    let trimmed = input.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    let tokens = trimmed
        .split(|ch: char| ch.is_whitespace() || ch == ',' || ch == '|')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();

    if let Some((first, rest)) = tokens.split_first()
        && let Some(expected) = parse_expected_outcome(first)
        && let Some(domain_token) = rest.first()
    {
        return normalize_domain(domain_token).map(|domain| (domain, Some(expected)));
    }

    normalize_domain(trimmed).map(|domain| (domain, None))
}

/// Strip all prefixes and path components from a domain string, returning
/// only the canonical lowercase host.
pub(crate) fn normalize_domain(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    let mut value = trimmed
        .strip_prefix("full:")
        .or_else(|| trimmed.strip_prefix("include:"))
        .or_else(|| trimmed.strip_prefix("domain:"))
        .or_else(|| trimmed.strip_prefix("domain-suffix:"))
        .or_else(|| trimmed.strip_prefix("DOMAIN-SUFFIX,"))
        .or_else(|| trimmed.strip_prefix("DOMAIN,"))
        .or_else(|| trimmed.strip_prefix("HOST,"))
        .unwrap_or(trimmed)
        .trim()
        .trim_end_matches('/')
        .to_ascii_lowercase();

    if let Some(rest) = value.strip_prefix("https://") {
        value = rest.to_string();
    } else if let Some(rest) = value.strip_prefix("http://") {
        value = rest.to_string();
    }

    if let Some((host, _)) = value.split_once('/') {
        value = host.to_string();
    }
    if let Some((host, _)) = value.split_once('?') {
        value = host.to_string();
    }
    if let Some((host, _)) = value.split_once('#') {
        value = host.to_string();
    }

    if value.is_empty() {
        return None;
    }

    Some(value)
}

// ─── Path helpers ─────────────────────────────────────────────────────────────

/// Convert arbitrary text into a safe filesystem stem (alphanumerics, `-`, `_`).
pub(crate) fn sanitize_results_stem(input: &str) -> String {
    let mut stem = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            stem.push(ch);
        } else {
            stem.push('_');
        }
    }

    let trimmed = stem.trim_matches('_');
    if trimmed.is_empty() {
        "scan".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Derive the default results directory name from the input file name.
pub(crate) fn default_results_dir_for_input(file: &std::path::Path) -> PathBuf {
    let stem = file
        .file_stem()
        .and_then(std::ffi::OsStr::to_str)
        .map_or_else(|| "scan".to_string(), sanitize_results_stem);
    PathBuf::from(format!("results_{stem}"))
}

// ─── Enums ────────────────────────────────────────────────────────────────────

/// Scan depth profile.
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum ScanProfileArg {
    /// Quieter profile — fewer probes, fewer retries.
    Safe,
    /// Aggressive profile — deep probing, more retries, higher noise.
    Aggressive,
}

impl ScanProfileArg {
    pub(crate) fn as_scanner_policy(self) -> crate::scanner::ScanPolicy {
        match self {
            Self::Safe => crate::scanner::ScanPolicy::safe(),
            Self::Aggressive => crate::scanner::ScanPolicy::aggressive(),
        }
    }
}

/// Output export profile.
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum ExportProfileArg {
    /// Minimal: blocked-domains.txt + geosite.dat only.
    Simple,
    /// Adds routing lists and router-native exports.
    Router,
    /// Everything: all reports, comparisons, validation.
    Full,
}

/// Format of the plain blocked-domain list.
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum BlockedListFormatArg {
    /// One domain per line.
    Plain,
    /// `full:domain` prefix for geosite source files.
    GeositeSource,
}

impl BlockedListFormatArg {
    pub(crate) fn format_domain(self, domain: &str) -> String {
        match self {
            Self::Plain => domain.to_string(),
            Self::GeositeSource => format!("full:{domain}"),
        }
    }
}

// ─── Args ─────────────────────────────────────────────────────────────────────

/// CLI arguments for Bulbascan.
#[derive(Parser, Debug)]
#[allow(clippy::struct_excessive_bools)]
#[command(
    author,
    version,
    about = "Checks which domains really need proxying on the current connection.",
    long_about = "Bulbascan is a selective-proxy scanner for routers and home gateways.\n\nThe simplest way to use it on Windows is to drag one or more input files onto bulbascan.exe.\n  - .txt files: read as plain domain lists (one domain per line)\n  - .dat files: read as binary geosite.dat (use --import-geosite-category to pick a category)\n  - Mix and match: drag both .txt and .dat files at the same time.",
    after_help = "Common examples:\n  bulbascan.exe my-list.txt\n  bulbascan.exe geosite.dat --import-geosite-category ru-blocked\n  bulbascan.exe geosite1.dat geosite2.dat list.txt --import-geosite-category blocked\n  bulbascan.exe geo_validation_set.txt --control-proxy http://user:pass@host:port --export-profile full"
)]
pub(crate) struct Args {
    /// One or more input files: .dat files are read as geosite.dat (binary), text files as domain lists.
    /// On Windows you can select multiple files and drag them all onto the EXE at once.
    #[arg(default_value = "targets.txt", num_args = 1..)]
    pub(crate) files: Vec<PathBuf>,

    /// Max size (bytes) of response body to inspect for signatures
    #[arg(short = 'b', long, default_value = "131072")]
    pub(crate) max_body_size: usize,

    /// Number of concurrent checks (saved between runs; last live value is reused on next start)
    #[arg(short, long)]
    pub(crate) concurrency: Option<usize>,

    /// Accessible-domains log file name
    #[arg(short = 'k', long, default_value = "ok.log")]
    pub(crate) out_ok: PathBuf,

    /// Blocked-domains log file name
    #[arg(short = 'l', long, default_value = "blocked.log")]
    pub(crate) out_blocked: PathBuf,

    /// Blocked-domain list file name generated for simple usage
    #[arg(short = 'B', long, default_value = "blocked-domains.txt")]
    pub(crate) blocked_list: PathBuf,

    /// Format for the blocked-domain list
    #[arg(short = 'F', long, value_enum, default_value_t = BlockedListFormatArg::Plain)]
    pub(crate) blocked_list_format: BlockedListFormatArg,

    /// Merge detected blocked domains into an existing regional list file
    #[arg(short = 'm', long, value_name = "FILE")]
    pub(crate) merge_into_list: Option<PathBuf>,

    /// Keep a local regional state directory with blocked, direct, and manual-review sets
    #[arg(short = 'W', long, value_name = "DIR")]
    pub(crate) state_dir: Option<PathBuf>,

    /// Recheck domains already known as blocked or direct inside --state-dir
    #[arg(short = 'K', long, default_value_t = false)]
    pub(crate) refresh_known: bool,

    /// Timeout in seconds per request
    #[arg(short, long, default_value_t = 12)]
    pub(crate) timeout: u64,

    /// Maximum number of redirects to follow
    #[arg(short = 'r', long, default_value_t = 10)]
    pub(crate) max_redirects: usize,

    /// Global timeout in seconds for the entire scan process (0 = infinite)
    #[arg(short = 'g', long, default_value_t = 0)]
    pub(crate) global_timeout: u64,

    /// Custom file with block signatures to override defaults
    #[arg(short = 's', long, value_name = "FILE")]
    pub(crate) signatures: Option<PathBuf>,

    /// Print detailed information in real-time
    #[arg(short, long, default_value_t = false)]
    pub(crate) verbose: bool,

    /// Proxy for the main scan (example: <socks5h://127.0.0.1:1080>)
    #[arg(short, long)]
    pub(crate) proxy: Option<String>,

    /// Use a text file containing a list of proxies (HTTP/SOCKS5) for rotation
    #[arg(short = 'P', long, value_name = "FILE")]
    pub(crate) proxies: Option<PathBuf>,

    /// Run a second confirmation scan through a control proxy
    #[arg(short = 'x', long)]
    pub(crate) control_proxy: Option<String>,

    /// VLESS control link used to generate a local Xray SOCKS config
    #[arg(short = 'L', long, value_name = "URL")]
    pub(crate) control_link: Option<String>,

    /// Write a local Xray SOCKS config from --control-link and exit
    #[arg(short = 'E', long, value_name = "FILE", requires = "control_link")]
    pub(crate) emit_xray_socks_config: Option<PathBuf>,

    /// Local listen address for the generated Xray SOCKS inbound
    #[arg(long, default_value = "127.0.0.1:1080")]
    pub(crate) xray_socks_listen: String,

    /// Output format (text or json)
    #[arg(short, long, default_value = "text")]
    pub(crate) format: String,

    /// Output profile: simple = clean default, router = routing files, full = all reports
    #[arg(short = 'e', long, value_enum, default_value_t = ExportProfileArg::Simple)]
    pub(crate) export_profile: ExportProfileArg,

    /// Scan profile: safe is quieter, aggressive probes deeper and can create more noise
    #[arg(short = 'q', long, value_enum, default_value_t = ScanProfileArg::Safe)]
    pub(crate) profile: ScanProfileArg,

    /// Fetch top domains from Cloudflare Radar instead of reading a file
    #[arg(short = 'R', long, default_value_t = 0)]
    pub(crate) fetch_radar: u32,

    /// Cloudflare API Token for Radar integration
    #[arg(short = 'X', long, env = "CLOUDFLARE_RADAR_TOKEN")]
    pub(crate) radar_token: Option<String>,

    /// SNI Fragmentation: Set maximum TLS record size (e.g., 100) to bypass ECH-aware DPI
    #[arg(short = 'S', long)]
    pub(crate) sni_fragment: Option<u16>,

    /// Path to Chromium/Chrome binary for DOM-dump verification.
    /// If not provided, will attempt automatic detection.
    #[arg(short = 'n', long)]
    pub(crate) browser: Option<PathBuf>,

    /// geosite.dat file name to generate
    #[arg(short = 'd', long, value_name = "FILE", default_value = "geosite.dat")]
    pub(crate) geosite: PathBuf,

    /// Category name inside geosite.dat
    #[arg(short = 'C', long, default_value = "blocked")]
    pub(crate) geosite_category: String,

    /// Result directory. If not set, drag-and-drop runs automatically use results_<input-file>.
    #[arg(short = 'D', long, default_value = "results")]
    pub(crate) results_dir: PathBuf,

    /// Import domains from an existing geosite.dat file instead of a text file
    #[arg(short = 'I', long, value_name = "FILE", conflicts_with = "fetch_radar")]
    pub(crate) import_geosite: Option<PathBuf>,

    /// Category to extract from --import-geosite (e.g. "blocked", "ru", "cn")
    #[arg(long, default_value = "blocked", requires = "import_geosite")]
    pub(crate) import_geosite_category: String,

    /// List all categories available in a geosite.dat file and exit
    #[arg(short = 'G', long, value_name = "FILE")]
    pub(crate) list_geosite_categories: Option<PathBuf>,

    /// POTATO MODE: Enable funniest UI experience (mashed potato progress bars, emoji headers)
    #[arg(long, default_value_t = false)]
    pub(crate) potato: bool,

    /// Use ASCII-only output — no emoji or Unicode spinner (useful for narrow TTYs or CI logs)
    #[arg(short = 'A', long, default_value_t = false)]
    pub(crate) ascii_only: bool,
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validation::ExpectedOutcome;

    #[test]
    fn normalizes_domain_variants() {
        assert_eq!(
            normalize_domain(" full:HTTPS://Example.com/path/ "),
            Some("example.com".to_string())
        );
        assert_eq!(
            normalize_domain("DOMAIN-SUFFIX,Example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(
            normalize_domain("domain:example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(normalize_domain("# comment"), None);
        assert_eq!(normalize_domain(""), None);
    }

    #[test]
    fn parses_expected_outcomes() {
        assert_eq!(parse_expected_outcome("geo"), Some(ExpectedOutcome::Geo));
        assert_eq!(
            parse_expected_outcome("challenge"),
            Some(ExpectedOutcome::Waf)
        );
        assert_eq!(
            parse_expected_outcome("direct"),
            Some(ExpectedOutcome::Direct)
        );
        assert_eq!(parse_expected_outcome("mystery"), None);
    }

    #[test]
    fn parses_annotated_domain_lines() {
        assert_eq!(
            parse_annotated_domain_line("geo https://claude.ai/login"),
            Some(("claude.ai".to_string(), Some(ExpectedOutcome::Geo)))
        );
        assert_eq!(
            parse_annotated_domain_line("direct google.com"),
            Some(("google.com".to_string(), Some(ExpectedOutcome::Direct)))
        );
        assert_eq!(
            parse_annotated_domain_line("example.com"),
            Some(("example.com".to_string(), None))
        );
    }

    #[test]
    fn derives_results_dir_from_input_filename() {
        let derived = default_results_dir_for_input(std::path::Path::new("lists/belarus seed.txt"));
        assert_eq!(derived, std::path::PathBuf::from("results_belarus_seed"));
    }
}
