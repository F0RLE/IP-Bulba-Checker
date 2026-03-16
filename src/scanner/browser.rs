use std::path::{Path, PathBuf};
use std::time::Duration;

use chaser_oxide::cdp::browser_protocol::emulation::{
    SetLocaleOverrideParams, SetTimezoneOverrideParams,
};
use chaser_oxide::{Browser, BrowserConfig, ChaserPage, ChaserProfile};
use futures::StreamExt;
use tokio::task::JoinHandle;

use crate::service_profiles;

use super::types::{ScanResult, Verdict};

fn browser_stealth_profile() -> ChaserProfile {
    let builder = if cfg!(target_os = "windows") {
        ChaserProfile::windows()
    } else if cfg!(target_os = "macos") {
        ChaserProfile::macos_arm()
    } else {
        ChaserProfile::linux()
    };

    builder.build()
}

pub(crate) fn detect_browser_binary() -> Option<PathBuf> {
    let candidates: &[&str] = if cfg!(target_os = "windows") {
        &[
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        ]
    } else if cfg!(target_os = "macos") {
        &[
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
        ]
    } else {
        // Linux and other Unix-like
        &[
            "/usr/bin/google-chrome",
            "/usr/bin/google-chrome-stable",
            "/usr/bin/chromium-browser",
            "/usr/bin/chromium",
            "/snap/bin/chromium",
            "/usr/bin/microsoft-edge",
        ]
    };

    candidates
        .iter()
        .map(PathBuf::from)
        .find(|path| path.exists())
}

pub(crate) fn browser_proxy_server_arg(proxy: &str) -> Option<String> {
    let parsed = url::Url::parse(proxy).ok()?;
    let host = parsed.host_str()?;
    let port = parsed.port_or_known_default()?;
    let host_with_port = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };

    match parsed.scheme() {
        "socks5" | "socks5h" => Some(format!("socks5://{host_with_port}")),
        "http" | "https" if parsed.username().is_empty() && parsed.password().is_none() => {
            Some(format!("http://{host_with_port}"))
        }
        _ => None,
    }
}

pub(crate) fn should_try_browser_verify(result: &ScanResult, domain: &str) -> bool {
    service_profiles::should_use_browser_verification(domain)
        && !matches!(result.verdict, Verdict::GeoBlocked | Verdict::Captcha)
        && matches!(
            result.verdict,
            Verdict::Accessible
                | Verdict::WafBlocked
                | Verdict::UnexpectedStatus
                | Verdict::Unreachable
        )
}

pub(crate) async fn run_browser_dom_dump(
    browser_path: &Path,
    url: &str,
    proxy: Option<&str>,
) -> anyhow::Result<String> {
    let profile_dir = std::env::temp_dir().join(format!("bulba-browser-{}", fastrand::u64(..)));
    let stealth_profile = browser_stealth_profile();

    let mut config_builder = BrowserConfig::builder()
        .chrome_executable(browser_path)
        .user_data_dir(&profile_dir)
        // Note: We use 'new' headless mode because old headless is easily detected by Cloudflare
        .arg("--headless=new")
        .arg("--disable-gpu")
        .arg("--disable-blink-features=AutomationControlled")
        .arg(format!("--accept-lang={}", stealth_profile.locale()))
        .window_size(
            stealth_profile.screen_width(),
            stealth_profile.screen_height(),
        )
        .no_sandbox()
        .disable_default_args();

    if let Some(proxy_str) = proxy.and_then(browser_proxy_server_arg) {
        config_builder = config_builder.arg(format!("--proxy-server={proxy_str}"));
    }

    let (mut browser, mut handler) = match Browser::launch(config_builder.build().map_err(|e| anyhow::anyhow!("config build error: {e}"))?).await {
        Ok(b) => b,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&profile_dir);
            return Err(anyhow::anyhow!("failed to launch browser: {e}"));
        }
    };

    let handler_task: JoinHandle<()> = tokio::task::spawn(async move {
        while let Some(_) = handler.next().await {}
    });

    let page_result = async {
        let page = browser.new_page("about:blank").await?;
        let chaser = ChaserPage::new(page);

        // Apply the same profile across CDP, HTTP headers, and emulation settings.
        chaser.apply_profile(&stealth_profile).await.map_err(|e| anyhow::anyhow!("failed to apply stealth profile: {e}"))?;
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
                    .map_err(|e| anyhow::anyhow!("failed to build timezone override: {e}"))?,
            )
            .await?;

        chaser.goto(url).await?;
        chaser.raw_page().wait_for_navigation().await?;
        
        // Give it a brief moment for Cloudflare/JS to execute challenges
        tokio::time::sleep(Duration::from_secs(3)).await;

        let content = chaser.raw_page().content().await?;
        Ok::<String, anyhow::Error>(content)
    }
    .await;

    // Cleanup
    browser.close().await.ok();
    handler_task.abort();
    let _ = std::fs::remove_dir_all(&profile_dir);

    page_result
}

