//! Self-test smoke check: scan a small set of domains with known RU blocking status
//! to verify that the scanner and control proxy are configured and working correctly.
//!
//! Activated via `--self-test` CLI flag.

use crate::scanner::{RoutingDecision, ScanResult};

// ── Known test domains ─────────────────────────────────────────────────────────

/// A domain with a well-known, stable expected result from inside Russia.
pub struct TestCase {
    pub domain: &'static str,
    pub label: &'static str,
    /// `true` = should need proxy (blocked in RU), `false` = should be direct.
    pub expect_blocked: bool,
    /// If `true`, skip this case when no control proxy is provided (result
    /// cannot be confirmed without a second vantage point).
    pub requires_control_proxy: bool,
}

/// Canonical domain set.
///
/// Blocked set: RKN/ТСПУ bans that have been in place for 2+ years and are
/// stable across all major Russian ISPs (Rostelecom, MTS, Beeline, `MegaFon`).
///
/// Direct set: global services accessible from Russia with no ISP restriction.
pub const TEST_CASES: &[TestCase] = &[
    // ── DIRECT (no Russian ISP block) ─────────────────────────────
    TestCase {
        domain: "google.com",
        label: "Google",
        expect_blocked: false,
        requires_control_proxy: false,
    },
    TestCase {
        domain: "github.com",
        label: "GitHub",
        expect_blocked: false,
        requires_control_proxy: false,
    },
    TestCase {
        domain: "cloudflare.com",
        label: "Cloudflare",
        expect_blocked: false,
        requires_control_proxy: false,
    },
    // ── BLOCKED by RKN since 2022 ─────────────────────────────────
    // dual-vantage required for confirmation
    TestCase {
        domain: "instagram.com",
        label: "Instagram (RKN Mar 2022)",
        expect_blocked: true,
        requires_control_proxy: true,
    },
    TestCase {
        domain: "facebook.com",
        label: "Facebook (RKN Mar 2022)",
        expect_blocked: true,
        requires_control_proxy: true,
    },
    TestCase {
        domain: "x.com",
        label: "X / Twitter (RKN Mar 2023)",
        expect_blocked: true,
        requires_control_proxy: true,
    },
    TestCase {
        domain: "linkedin.com",
        label: "LinkedIn (RKN Nov 2016)",
        expect_blocked: true,
        requires_control_proxy: true,
    },
    // ── GEO-RESTRICTED (commercial, returns geo-block body) ───────
    // Does NOT require control proxy — the site itself says "not available".
    TestCase {
        domain: "deepl.com",
        label: "DeepL (commercial geo-block)",
        expect_blocked: true,
        requires_control_proxy: false,
    },
];

// ── Result type ────────────────────────────────────────────────────────────────

pub struct TestResult {
    pub label: String,
    pub expected_blocked: bool,
    pub actual_blocked: bool,
    pub verdict: String,
    pub confidence: u8,
    pub passed: bool,
}

impl TestResult {
    pub fn from_scan(case: &TestCase, result: &ScanResult) -> Self {
        let actual_blocked = result.routing_decision != RoutingDecision::DirectOk;
        let passed = actual_blocked == case.expect_blocked;
        Self {
            label: case.label.to_string(),
            expected_blocked: case.expect_blocked,
            actual_blocked,
            verdict: format!("{:?}", result.verdict),
            confidence: result.confidence,
            passed,
        }
    }
}

// ── Report ─────────────────────────────────────────────────────────────────────

pub fn print_report(results: &[TestResult], has_control_proxy: bool) {
    let total = results.len();
    let passed = results.iter().filter(|r| r.passed).count();
    let failed = total - passed;

    eprintln!();
    eprintln!("┌──────────────────────────────────────────────────────────────┐");
    eprintln!("│               🥔  BULBASCAN SELF-TEST                        │");
    eprintln!("└──────────────────────────────────────────────────────────────┘");

    if !has_control_proxy {
        eprintln!("  ⚠  No --control-proxy — confirmed-block cases are SKIPPED.");
        eprintln!("     Pass --control-proxy <url> for full dual-vantage test.");
        eprintln!();
    }

    for r in results {
        let icon = if r.passed { "✓" } else { "✗" };
        let expect = if r.expected_blocked {
            "BLOCKED"
        } else {
            "DIRECT "
        };
        let got = if r.actual_blocked {
            "proxy-required"
        } else {
            "direct-ok     "
        };
        eprintln!(
            "  {icon}  {:<36}  expect={expect}  got={got}  [{} conf={}%]",
            r.label, r.verdict, r.confidence
        );
    }

    eprintln!();
    if failed == 0 {
        eprintln!("  ✓  All {total} tests passed — detection is working correctly.");
    } else {
        eprintln!("  ✗  {failed}/{total} tests FAILED.");
        eprintln!();
        eprintln!("  Possible causes:");
        eprintln!("    – Scanning from outside Russia? RKN blocks won't trigger locally.");
        eprintln!("    – Control proxy also in Russia? Geo-blocks undetectable from proxy.");
        eprintln!("    – Timeout too low? Try --timeout 15 for slower connections.");
        eprintln!("    – Run with --verbose to see per-domain evidence.");
    }
    eprintln!();
}

// ── Domain list helper ─────────────────────────────────────────────────────────

/// Return the domains to scan for self-test, filtered by control proxy availability.
pub fn domains_to_scan(has_control_proxy: bool) -> Vec<String> {
    TEST_CASES
        .iter()
        .filter(|c| !c.requires_control_proxy || has_control_proxy)
        .map(|c| c.domain.to_string())
        .collect()
}

/// Match scan results back to test cases and build `TestResult` list.
pub fn evaluate(scan_results: &[ScanResult], has_control_proxy: bool) -> Vec<TestResult> {
    let cases: Vec<&TestCase> = TEST_CASES
        .iter()
        .filter(|c| !c.requires_control_proxy || has_control_proxy)
        .collect();

    cases
        .iter()
        .filter_map(|case| {
            scan_results
                .iter()
                .find(|r| r.domain == case.domain)
                .map(|result| TestResult::from_scan(case, result))
        })
        .collect()
}
