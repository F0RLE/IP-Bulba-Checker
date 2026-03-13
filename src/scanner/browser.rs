use std::path::{Path, PathBuf};

use crate::service_profiles;

use super::types::{ScanResult, Verdict};

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
    let profile = std::env::temp_dir().join(format!("bulba-browser-{}", fastrand::u64(..)));
    let mut command = tokio::process::Command::new(browser_path);
    command
        .arg("--headless=new")
        .arg("--disable-gpu")
        .arg("--no-first-run")
        .arg("--no-default-browser-check")
        .arg(format!("--user-data-dir={}", profile.display()))
        .arg("--dump-dom");

    if let Some(proxy) = proxy.and_then(browser_proxy_server_arg) {
        command.arg(format!("--proxy-server={proxy}"));
    }

    let output = command.arg(url).output().await?;

    let _ = std::fs::remove_dir_all(&profile);

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "browser verification failed with status {}",
            output.status
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
