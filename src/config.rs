//! Configuration file loading and precedence handling for `bulbascan.toml`.

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use clap::{ArgMatches, parser::ValueSource};
use serde::Deserialize;

use crate::cli::{Args, BlockedListFormatArg, ExportProfileArg, ScanProfileArg};

const DEFAULT_CONFIG_FILE: &str = "bulbascan.toml";

#[derive(Debug, Default, Deserialize)]
pub(crate) struct FileConfig {
    #[serde(default)]
    scan: ScanConfig,
    #[serde(default)]
    network: NetworkConfig,
    #[serde(default)]
    comparison: ComparisonConfig,
    #[serde(default)]
    output: OutputConfig,
    #[serde(default)]
    ui: UiConfig,
}

#[derive(Debug, Default, Deserialize)]
struct ScanConfig {
    max_body_size: Option<usize>,
    concurrency: Option<usize>,
    timeout: Option<u64>,
    max_redirects: Option<usize>,
    global_timeout: Option<u64>,
    signatures: Option<PathBuf>,
    verbose: Option<bool>,
    profile: Option<ScanProfileArg>,
    sni_fragment: Option<u16>,
    browser: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
struct NetworkConfig {
    proxy: Option<String>,
    proxies: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
struct ComparisonConfig {
    control_proxy: Option<String>,
    xray_socks_listen: Option<String>,
    state_dir: Option<PathBuf>,
    refresh_known: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
struct OutputConfig {
    format: Option<String>,
    export_profile: Option<ExportProfileArg>,
    results_dir: Option<PathBuf>,
    out_ok: Option<PathBuf>,
    out_blocked: Option<PathBuf>,
    blocked_list: Option<PathBuf>,
    blocked_list_format: Option<BlockedListFormatArg>,
    merge_into_list: Option<PathBuf>,
    geosite: Option<PathBuf>,
    geosite_category: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct UiConfig {
    potato: Option<bool>,
    ascii_only: Option<bool>,
}

pub(crate) fn load_and_apply(
    args: &mut Args,
    matches: &ArgMatches,
) -> anyhow::Result<Option<PathBuf>> {
    let Some((config_path, explicit)) = resolve_config_path(args) else {
        return Ok(None);
    };

    if !config_path.exists() {
        if explicit {
            bail!("Config file '{}' not found.", config_path.display());
        }
        return Ok(None);
    }

    let content = std::fs::read_to_string(&config_path)
        .with_context(|| format!("Failed to read config file '{}'.", config_path.display()))?;
    let mut config: FileConfig = toml::from_str(&content)
        .with_context(|| format!("Failed to parse config file '{}'.", config_path.display()))?;
    config.resolve_paths(config_path.parent().unwrap_or_else(|| Path::new(".")));
    config.apply(args, matches);
    Ok(Some(config_path))
}

fn resolve_config_path(args: &Args) -> Option<(PathBuf, bool)> {
    if args.no_config {
        return None;
    }

    if let Some(path) = args.config.clone() {
        return Some((path, true));
    }

    Some((PathBuf::from(DEFAULT_CONFIG_FILE), false))
}

fn should_apply(matches: &ArgMatches, id: &str) -> bool {
    !matches
        .value_source(id)
        .is_some_and(|source| matches!(source, ValueSource::CommandLine | ValueSource::EnvVariable))
}

fn resolve_path(path: &mut Option<PathBuf>, base_dir: &Path) {
    if let Some(existing) = path.as_mut()
        && existing.is_relative()
    {
        *existing = base_dir.join(&*existing);
    }
}

impl FileConfig {
    fn resolve_paths(&mut self, base_dir: &Path) {
        resolve_path(&mut self.scan.signatures, base_dir);
        resolve_path(&mut self.scan.browser, base_dir);
        resolve_path(&mut self.network.proxies, base_dir);
        resolve_path(&mut self.comparison.state_dir, base_dir);
        resolve_path(&mut self.output.results_dir, base_dir);
        resolve_path(&mut self.output.merge_into_list, base_dir);
    }

    #[allow(clippy::too_many_lines)]
    fn apply(self, args: &mut Args, matches: &ArgMatches) {
        if should_apply(matches, "max_body_size")
            && let Some(value) = self.scan.max_body_size
        {
            args.max_body_size = value;
        }
        if should_apply(matches, "concurrency")
            && let Some(value) = self.scan.concurrency
        {
            args.concurrency = Some(value);
        }
        if should_apply(matches, "timeout")
            && let Some(value) = self.scan.timeout
        {
            args.timeout = value;
        }
        if should_apply(matches, "max_redirects")
            && let Some(value) = self.scan.max_redirects
        {
            args.max_redirects = value;
        }
        if should_apply(matches, "global_timeout")
            && let Some(value) = self.scan.global_timeout
        {
            args.global_timeout = value;
        }
        if should_apply(matches, "signatures")
            && let Some(value) = self.scan.signatures
        {
            args.signatures = Some(value);
        }
        if should_apply(matches, "verbose")
            && let Some(value) = self.scan.verbose
        {
            args.verbose = value;
        }
        if should_apply(matches, "profile")
            && let Some(value) = self.scan.profile
        {
            args.profile = value;
        }
        if should_apply(matches, "sni_fragment")
            && let Some(value) = self.scan.sni_fragment
        {
            args.sni_fragment = Some(value);
        }
        if should_apply(matches, "browser")
            && let Some(value) = self.scan.browser
        {
            args.browser = Some(value);
        }
        if should_apply(matches, "proxy")
            && let Some(value) = self.network.proxy
        {
            args.proxy = Some(value);
        }
        if should_apply(matches, "proxies")
            && let Some(value) = self.network.proxies
        {
            args.proxies = Some(value);
        }
        if should_apply(matches, "control_proxy")
            && let Some(value) = self.comparison.control_proxy
        {
            args.control_proxy = Some(value);
        }
        if should_apply(matches, "xray_socks_listen")
            && let Some(value) = self.comparison.xray_socks_listen
        {
            args.xray_socks_listen = value;
        }
        if should_apply(matches, "state_dir")
            && let Some(value) = self.comparison.state_dir
        {
            args.state_dir = Some(value);
        }
        if should_apply(matches, "refresh_known")
            && let Some(value) = self.comparison.refresh_known
        {
            args.refresh_known = value;
        }
        if should_apply(matches, "format")
            && let Some(value) = self.output.format
        {
            args.format = value;
        }
        if should_apply(matches, "export_profile")
            && let Some(value) = self.output.export_profile
        {
            args.export_profile = value;
        }
        if should_apply(matches, "results_dir")
            && let Some(value) = self.output.results_dir
        {
            args.results_dir = value;
        }
        if should_apply(matches, "out_ok")
            && let Some(value) = self.output.out_ok
        {
            args.out_ok = value;
        }
        if should_apply(matches, "out_blocked")
            && let Some(value) = self.output.out_blocked
        {
            args.out_blocked = value;
        }
        if should_apply(matches, "blocked_list")
            && let Some(value) = self.output.blocked_list
        {
            args.blocked_list = value;
        }
        if should_apply(matches, "blocked_list_format")
            && let Some(value) = self.output.blocked_list_format
        {
            args.blocked_list_format = value;
        }
        if should_apply(matches, "merge_into_list")
            && let Some(value) = self.output.merge_into_list
        {
            args.merge_into_list = Some(value);
        }
        if should_apply(matches, "geosite")
            && let Some(value) = self.output.geosite
        {
            args.geosite = value;
        }
        if should_apply(matches, "geosite_category")
            && let Some(value) = self.output.geosite_category
        {
            args.geosite_category = value;
        }
        if should_apply(matches, "potato")
            && let Some(value) = self.ui.potato
        {
            args.potato = value;
        }
        if should_apply(matches, "ascii_only")
            && let Some(value) = self.ui.ascii_only
        {
            args.ascii_only = value;
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, FromArgMatches};

    use super::*;
    use crate::cli::Args;

    #[test]
    fn config_applies_only_when_cli_is_silent() {
        let matches = Args::command()
            .try_get_matches_from(["bulbascan", "--timeout", "5"])
            .expect("matches");
        let mut args = Args::from_arg_matches(&matches).expect("args");
        let config: FileConfig = toml::from_str(
            r#"
[scan]
timeout = 12
concurrency = 80

[output]
export_profile = "full"
"#,
        )
        .expect("config");

        config.apply(&mut args, &matches);

        assert_eq!(args.timeout, 5);
        assert_eq!(args.concurrency, Some(80));
        assert_eq!(args.export_profile, ExportProfileArg::Full);
    }

    #[test]
    fn relative_paths_resolve_against_config_dir() {
        let mut config: FileConfig = toml::from_str(
            r#"
[network]
proxies = "lists/proxies.txt"

[comparison]
state_dir = "state"

[output]
results_dir = "results/custom"
"#,
        )
        .expect("config");

        config.resolve_paths(Path::new("C:/tmp/bulbascan"));

        assert_eq!(
            config.network.proxies,
            Some(PathBuf::from("C:/tmp/bulbascan/lists/proxies.txt"))
        );
        assert_eq!(
            config.comparison.state_dir,
            Some(PathBuf::from("C:/tmp/bulbascan/state"))
        );
        assert_eq!(
            config.output.results_dir,
            Some(PathBuf::from("C:/tmp/bulbascan/results/custom"))
        );
    }
}
