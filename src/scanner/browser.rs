use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::anyhow;
use chaser_oxide::cdp::browser_protocol::browser::{
    SetDownloadBehaviorBehavior, SetDownloadBehaviorParams,
};
use chaser_oxide::cdp::browser_protocol::emulation::{
    SetLocaleOverrideParams, SetTimezoneOverrideParams,
};
use chaser_oxide::{Browser, BrowserConfig, ChaserPage, ChaserProfile, Page};
use futures::StreamExt;
use tokio::task::JoinHandle;

use crate::service_profiles;

use super::types::{ScanResult, Verdict};

struct PageCloseGuard(Option<Page>);

impl PageCloseGuard {
    fn new(page: Page) -> Self {
        Self(Some(page))
    }

    fn page(&self) -> &Page {
        self.0.as_ref().expect("page guard should hold a page")
    }

    async fn close_now(mut self) {
        if let Some(page) = self.0.take() {
            page.close().await.ok();
        }
    }
}

impl Drop for PageCloseGuard {
    fn drop(&mut self) {
        if let Some(page) = self.0.take() {
            tokio::spawn(async move {
                page.close().await.ok();
            });
        }
    }
}

fn browser_stealth_profile() -> ChaserProfile {
    let builder = if cfg!(target_os = "windows") {
        ChaserProfile::windows()
    } else if cfg!(target_os = "macos") {
        if cfg!(target_arch = "aarch64") {
            ChaserProfile::macos_arm()
        } else {
            ChaserProfile::macos_intel()
        }
    } else {
        ChaserProfile::linux()
    };

    builder.build()
}

fn browser_no_sandbox_requested() -> bool {
    std::env::var_os("BULBASCAN_BROWSER_NO_SANDBOX").is_some_and(|value| {
        let lower = value.to_string_lossy().to_ascii_lowercase();
        matches!(lower.as_str(), "1" | "true" | "yes" | "on")
    })
}

fn existing_path(path: impl Into<PathBuf>) -> Option<PathBuf> {
    let path = path.into();
    path.exists().then_some(path)
}

fn path_exts() -> Vec<String> {
    if cfg!(target_os = "windows") {
        std::env::var_os("PATHEXT").map_or_else(
            || vec![".exe".into(), ".cmd".into(), ".bat".into()],
            |value| {
                value
                    .to_string_lossy()
                    .split(';')
                    .filter(|ext| !ext.is_empty())
                    .map(str::to_ascii_lowercase)
                    .collect()
            },
        )
    } else {
        Vec::new()
    }
}

fn candidate_file_names(name: &str) -> Vec<String> {
    if cfg!(target_os = "windows") {
        let has_ext = Path::new(name)
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| {
                ext.eq_ignore_ascii_case("exe")
                    || ext.eq_ignore_ascii_case("cmd")
                    || ext.eq_ignore_ascii_case("bat")
            });
        if has_ext {
            vec![name.to_string()]
        } else {
            let mut out = vec![name.to_string()];
            for ext in path_exts() {
                out.push(format!("{name}{ext}"));
            }
            out
        }
    } else {
        vec![name.to_string()]
    }
}

fn find_in_path_from(path_env: &std::ffi::OsStr, names: &[&str]) -> Option<PathBuf> {
    let path_dirs = std::env::split_paths(path_env);
    for dir in path_dirs {
        for name in names {
            for candidate in candidate_file_names(name) {
                let full = dir.join(&candidate);
                if full.exists() {
                    return Some(full);
                }
            }
        }
    }
    None
}

fn find_in_path(names: &[&str]) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    find_in_path_from(&path, names)
}

pub(crate) fn detect_browser_binary() -> Option<PathBuf> {
    for env_var in [
        "BULBASCAN_BROWSER",
        "CHROME_PATH",
        "CHROMIUM_PATH",
        "EDGE_PATH",
        "BROWSER",
    ] {
        if let Some(path) = std::env::var_os(env_var).and_then(existing_path) {
            return Some(path);
        }
    }

    let path_names: &[&str] = if cfg!(target_os = "windows") {
        &[
            "chrome",
            "chrome.exe",
            "msedge",
            "msedge.exe",
            "chromium",
            "chromium.exe",
        ]
    } else if cfg!(target_os = "macos") {
        &[
            "Google Chrome",
            "Microsoft Edge",
            "Chromium",
            "google-chrome",
            "microsoft-edge",
            "chromium",
        ]
    } else {
        &[
            "google-chrome",
            "google-chrome-stable",
            "chromium-browser",
            "chromium",
            "microsoft-edge",
            "microsoft-edge-stable",
        ]
    };

    if let Some(path) = find_in_path(path_names) {
        return Some(path);
    }

    let mut candidates: Vec<PathBuf> = Vec::new();
    if cfg!(target_os = "windows") {
        candidates.extend([
            PathBuf::from(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
            PathBuf::from(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),
            PathBuf::from(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
            PathBuf::from(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
        ]);

        if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
            let local = PathBuf::from(local_app_data);
            candidates.extend([
                local.join(r"Google\Chrome\Application\chrome.exe"),
                local.join(r"Chromium\Application\chrome.exe"),
                local.join(r"Microsoft\Edge\Application\msedge.exe"),
            ]);
        }
    } else if cfg!(target_os = "macos") {
        candidates.extend([
            PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
            PathBuf::from("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"),
            PathBuf::from("/Applications/Chromium.app/Contents/MacOS/Chromium"),
            PathBuf::from(
                "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
            ),
        ]);

        if let Some(home) = std::env::var_os("HOME") {
            let home = PathBuf::from(home);
            candidates.extend([
                home.join("Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
                home.join("Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"),
                home.join("Applications/Chromium.app/Contents/MacOS/Chromium"),
            ]);
        }
    } else {
        candidates.extend([
            PathBuf::from("/usr/bin/google-chrome"),
            PathBuf::from("/usr/bin/google-chrome-stable"),
            PathBuf::from("/usr/bin/chromium-browser"),
            PathBuf::from("/usr/bin/chromium"),
            PathBuf::from("/snap/bin/chromium"),
            PathBuf::from("/usr/bin/microsoft-edge"),
            PathBuf::from("/usr/bin/microsoft-edge-stable"),
            PathBuf::from("/opt/google/chrome/chrome"),
        ]);
    }

    candidates.into_iter().find(|path| path.exists())
}

pub(crate) fn browser_proxy_server_arg(proxy: &str) -> Option<String> {
    let parsed = url::Url::parse(proxy).ok()?;
    let host = parsed.host_str()?;
    let port = parsed.port_or_known_default()?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return None;
    }
    let host_with_port = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };

    match parsed.scheme() {
        "socks5" | "socks5h" => Some(format!("socks5://{host_with_port}")),
        "http" | "https" => Some(format!("http://{host_with_port}")),
        _ => None,
    }
}

pub(crate) fn browser_proxy_host_resolver_rules(proxy: &str) -> Option<String> {
    let parsed = url::Url::parse(proxy).ok()?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return None;
    }

    let host = parsed.host_str()?;
    match parsed.scheme() {
        "socks5" | "socks5h" => Some(format!("MAP * ~NOTFOUND , EXCLUDE {host}")),
        _ => None,
    }
}

pub(crate) fn should_try_browser_verify(
    result: &ScanResult,
    domain: &str,
    browser_verify_all: bool,
) -> bool {
    (browser_verify_all || service_profiles::should_use_browser_verification(domain))
        && !matches!(result.verdict, Verdict::GeoBlocked | Verdict::Captcha)
        && matches!(
            result.verdict,
            Verdict::Accessible
                | Verdict::WafBlocked
                | Verdict::UnexpectedStatus
                | Verdict::Unreachable
        )
}

fn is_browser_interstitial_challenge(html: &str) -> bool {
    let lower = html.to_ascii_lowercase();
    let weak_hits = ["just a moment", "one moment", "один момент"]
        .into_iter()
        .filter(|needle| lower.contains(needle))
        .count();
    let challenge_context = [
        "checking your browser",
        "verify you are human",
        "browser verification",
        "security check",
        "enable cookies",
        "challenge-platform",
        "cf-challenge",
        "cf-mitigated",
        "turnstile",
        "cdn-cgi/challenge-platform",
    ]
    .into_iter()
    .any(|needle| lower.contains(needle));

    challenge_context || weak_hits >= 2
}

fn browser_navigation_is_allowed(url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    matches!(parsed.scheme(), "http" | "https")
}

async fn disable_browser_downloads(browser: &Browser) -> anyhow::Result<()> {
    browser
        .execute(
            SetDownloadBehaviorParams::builder()
                .behavior(SetDownloadBehaviorBehavior::Deny)
                .build()
                .map_err(|e| anyhow!("failed to build browser download policy: {e}"))?,
        )
        .await
        .map_err(|e| anyhow!("failed to disable browser downloads: {e}"))?;
    Ok(())
}

pub(crate) async fn run_browser_dom_dump(
    browser_path: &Path,
    url: &str,
    proxy: Option<&str>,
    timeout: Duration,
) -> anyhow::Result<String> {
    let profile_dir = std::env::temp_dir().join(format!("bulba-browser-{}", fastrand::u64(..)));
    let stealth_profile = browser_stealth_profile();

    let mut config_builder = BrowserConfig::builder()
        .chrome_executable(browser_path)
        .user_data_dir(&profile_dir)
        // Keep the browser fully headless and suppress first-run / sync / promo UI.
        .arg("--headless=new")
        .arg("--disable-gpu")
        .arg("--no-first-run")
        .arg("--no-default-browser-check")
        .arg("--disable-features=ChromeWhatsNewUI")
        .arg("--disable-sync")
        .arg("--disable-background-networking")
        .arg("--disable-extensions")
        .arg("--disable-default-apps")
        .arg("--disable-component-update")
        .arg("--disable-breakpad")
        .arg("--metrics-recording-only")
        .arg("--password-store=basic")
        .arg("--use-mock-keychain")
        .arg("--hide-crash-restore-bubble")
        .arg("--disable-notifications")
        .arg("--deny-permission-prompts")
        .arg("--disable-popup-blocking")
        .arg("--disable-external-intent-requests")
        .arg("--no-pings")
        .arg("--disable-blink-features=AutomationControlled")
        .arg(format!("--accept-lang={}", stealth_profile.locale()))
        .window_size(
            stealth_profile.screen_width(),
            stealth_profile.screen_height(),
        );

    if browser_no_sandbox_requested() {
        config_builder = config_builder.no_sandbox();
    }

    if let Some(proxy_str) = proxy.and_then(browser_proxy_server_arg) {
        config_builder = config_builder.arg(format!("--proxy-server={proxy_str}"));
        if let Some(resolver_rules) = proxy.and_then(browser_proxy_host_resolver_rules) {
            config_builder = config_builder.arg(format!("--host-resolver-rules={resolver_rules}"));
        }
    }

    let (mut browser, mut handler) = match Browser::launch(
        config_builder
            .build()
            .map_err(|e| anyhow::anyhow!("config build error: {e}"))?,
    )
    .await
    {
        Ok(b) => b,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&profile_dir);
            return Err(anyhow::anyhow!("failed to launch browser: {e}"));
        }
    };

    let handler_task: JoinHandle<()> =
        tokio::task::spawn(async move { while handler.next().await.is_some() {} });

    if let Err(error) = disable_browser_downloads(&browser).await {
        browser.close().await.ok();
        handler_task.abort();
        let _ = std::fs::remove_dir_all(&profile_dir);
        return Err(error);
    }

    let page_result = match tokio::time::timeout(
        timeout,
        collect_dom_with_browser(&browser, &stealth_profile, url),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(anyhow!(
            "browser verification timed out after {}s",
            timeout.as_secs()
        )),
    };

    // Cleanup
    browser.close().await.ok();
    handler_task.abort();
    let _ = std::fs::remove_dir_all(&profile_dir);

    page_result
}

async fn collect_dom_with_browser(
    browser: &Browser,
    stealth_profile: &ChaserProfile,
    url: &str,
) -> anyhow::Result<String> {
    let page = browser.new_page("about:blank").await?;
    collect_dom_on_page(page, stealth_profile, url).await
}

async fn collect_dom_on_page(
    page: Page,
    stealth_profile: &ChaserProfile,
    url: &str,
) -> anyhow::Result<String> {
    let page_guard = PageCloseGuard::new(page);
    let chaser = ChaserPage::new(page_guard.page().clone());
    let result = async {
        // Apply the same profile across CDP, HTTP headers, and emulation settings.
        chaser
            .apply_profile(stealth_profile)
            .await
            .map_err(|e| anyhow!("failed to apply stealth profile: {e}"))?;
        chaser
            .raw_page()
            .emulate_locale(
                SetLocaleOverrideParams::builder()
                    .locale(stealth_profile.locale())
                    .build(),
            )
            .await?;
        chaser
            .raw_page()
            .emulate_timezone(
                SetTimezoneOverrideParams::builder()
                    .timezone_id(stealth_profile.timezone())
                    .build()
                    .map_err(|e| anyhow!("failed to build timezone override: {e}"))?,
            )
            .await?;

        chaser.goto(url).await?;

        // Let the initial load settle, then only extend the wait window when
        // the DOM looks like a transient challenge/interstitial page.
        tokio::time::sleep(Duration::from_secs(2)).await;

        let current_url = chaser.url().await?.unwrap_or_default();
        if current_url == "about:blank" {
            return Err(anyhow!("browser navigation stayed at about:blank"));
        }
        if !browser_navigation_is_allowed(&current_url) {
            return Err(anyhow!(
                "browser navigation left http/https scope: {current_url}"
            ));
        }

        let mut content = chaser.content().await?;
        if is_browser_interstitial_challenge(&content) {
            for _ in 0..12 {
                tokio::time::sleep(Duration::from_millis(500)).await;
                let refreshed = chaser.content().await?;
                if !is_browser_interstitial_challenge(&refreshed) {
                    content = refreshed;
                    break;
                }
                content = refreshed;
            }
        }

        if content.trim().is_empty() {
            return Err(anyhow!("browser returned empty DOM"));
        }

        Ok(content)
    }
    .await;

    page_guard.close_now().await;
    result
}

#[cfg(test)]
mod tests {
    use super::{
        browser_navigation_is_allowed, find_in_path_from, is_browser_interstitial_challenge,
        should_try_browser_verify,
    };
    use crate::scanner::types::{DomainStatus, build_scan_result};
    use crate::scanner::{RoutingDecision, Verdict};

    #[test]
    fn find_in_path_from_finds_matching_binary() {
        let root = std::env::temp_dir().join(format!("bulba-path-test-{}", fastrand::u64(..)));
        let _ = std::fs::remove_dir_all(&root);
        let bin = root.join("bin");
        std::fs::create_dir_all(&bin).unwrap();

        let file_name = if cfg!(target_os = "windows") {
            "chrome.exe"
        } else {
            "google-chrome"
        };
        let browser = bin.join(file_name);
        std::fs::write(&browser, b"stub").unwrap();

        let path_env = std::env::join_paths([bin.clone()]).unwrap();
        let found = find_in_path_from(path_env.as_os_str(), &["chrome", "google-chrome"]);

        assert_eq!(found, Some(browser));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn detects_browser_interstitial_challenge_pages() {
        assert!(is_browser_interstitial_challenge(
            "<html><title>Just a moment</title><body>Checking your browser before accessing</body></html>"
        ));
        assert!(is_browser_interstitial_challenge(
            "<html><body><script src=\"/cdn-cgi/challenge-platform\"></script></body></html>"
        ));
        assert!(!is_browser_interstitial_challenge(
            "<html><title>Example</title><body>Normal content</body></html>"
        ));
    }

    #[test]
    fn browser_navigation_only_allows_http_and_https() {
        assert!(browser_navigation_is_allowed("https://example.com"));
        assert!(browser_navigation_is_allowed("http://example.com"));
        assert!(!browser_navigation_is_allowed(
            "file:///C:/Users/FORLE/Downloads/test.exe"
        ));
        assert!(!browser_navigation_is_allowed("about:blank"));
        assert!(!browser_navigation_is_allowed("javascript:alert(1)"));
    }

    #[test]
    fn browser_all_overrides_service_profile_gate() {
        let mut result = build_scan_result(
            "unmapped.example".to_string(),
            DomainStatus::Blocked,
            Verdict::WafBlocked,
            85,
            Some(403),
            "challenge".to_string(),
            None,
        );
        result.routing_decision = RoutingDecision::ManualReview;

        assert!(!should_try_browser_verify(
            &result,
            "unmapped.example",
            false
        ));
        assert!(should_try_browser_verify(&result, "unmapped.example", true));
    }
}
