//! Two-line live block: [profile header] + [bar].
//!
//! * `prev_cols` tracks previous terminal width.
//! * On resize: old content may reflow to N phys lines each → go up 2N-1, then `\x1b[J`.
//! * Written to stderr. Cursor hidden while active. ASCII-safe bar chars.

use crossterm::terminal;
use std::io::{self, Write};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};
use unicode_width::UnicodeWidthChar;

// ─── helpers ──────────────────────────────────────────────────────────────────

fn fit_to_width(s: &str, max_cols: usize) -> String {
    if max_cols == 0 {
        return String::new();
    }
    let mut out = String::with_capacity(s.len());
    let mut vis = 0usize;
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            out.push(ch);
            for c in chars.by_ref() {
                out.push(c);
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }
        let w = UnicodeWidthChar::width(ch).unwrap_or(0);
        if vis + w > max_cols {
            break;
        }
        out.push(ch);
        vis += w;
    }
    out
}

fn vis_width(s: &str) -> usize {
    s.chars()
        .map(|c| UnicodeWidthChar::width(c).unwrap_or(0))
        .sum()
}

fn tier(n: usize) -> &'static str {
    match n {
        0..=50 => "Safe",
        51..=100 => "Standard",
        101..=200 => "Balanced",
        201..=300 => "Active",
        301..=400 => "Fast",
        401..=500 => "Turbo",
        501..=600 => "Heavy",
        601..=700 => "Intense",
        701..=800 => "Brute",
        801..=900 => "Rush",
        _ => "Aggressive",
    }
}

// ─── public API ───────────────────────────────────────────────────────────────

pub struct LiveBar {
    pub pos: Arc<AtomicU64>,
    pub ok: Arc<AtomicU64>,
    pub blocked: Arc<AtomicU64>,
    pub dead: Arc<AtomicU64>,
    pub workers: Arc<AtomicUsize>,
    total: u64,
    start: Instant,
    stopped: Arc<AtomicBool>,
    out: Arc<Mutex<io::Stderr>>,
    potato: bool,
    output_display: String,
    /// Terminal width from the previous render tick.
    prev_cols: Arc<AtomicUsize>,
}

impl LiveBar {
    pub fn new(
        total: u64,
        workers: Arc<AtomicUsize>,
        potato: bool,
        output_display: String,
    ) -> Arc<Self> {
        Arc::new(Self {
            pos: Arc::new(AtomicU64::new(0)),
            ok: Arc::new(AtomicU64::new(0)),
            blocked: Arc::new(AtomicU64::new(0)),
            dead: Arc::new(AtomicU64::new(0)),
            workers,
            total,
            start: Instant::now(),
            stopped: Arc::new(AtomicBool::new(false)),
            out: Arc::new(Mutex::new(io::stderr())),
            potato,
            output_display,
            prev_cols: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Print a log line — clears current bar line, prints msg, bar redraws next tick.
    pub fn println(&self, msg: impl AsRef<str>) {
        let mut o = self.out.lock().unwrap();
        // Go up past the profile line, clear it, print msg, leave cursor for bar tick.
        write!(o, "\x1b[1A\r\x1b[2K{}\n\n", msg.as_ref()).ok();
        o.flush().ok();
    }

    pub fn finish(&self, msg: impl AsRef<str>) {
        self.stopped.store(true, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(150));
        let mut o = self.out.lock().unwrap();
        write!(o, "\x1b[?25h\r\x1b[2K{}\n", msg.as_ref()).ok();
        o.flush().ok();
    }

    pub fn start_draw_thread(self: &Arc<Self>) -> std::thread::JoinHandle<()> {
        let bar = Arc::clone(self);
        {
            let mut o = bar.out.lock().unwrap();
            // main.rs already printed a blank line (profile slot).
            // Write one more \n to reserve the bar slot; hide cursor.
            write!(o, "\n\x1b[?25l").ok();
            o.flush().ok();
        }
        std::thread::spawn(move || {
            let frames: &[&str] = if bar.potato {
                &["🌱", "🌿", "🥔", "🍟", "😋"]
            } else {
                &["-", "\\", "|", "/"]
            };
            let mut tick = 0usize;
            loop {
                if bar.stopped.load(Ordering::Relaxed) {
                    if let Ok(mut o) = bar.out.lock() {
                        write!(o, "\x1b[?25h\r\x1b[2K").ok();
                        o.flush().ok();
                    }
                    break;
                }
                bar.render(frames[tick % frames.len()]);
                tick += 1;
                std::thread::sleep(Duration::from_millis(100));
            }
        })
    }

    fn render(&self, spinner: &str) {
        let (cols, _) = terminal::size().unwrap_or((120, 30));
        let cols = cols as usize;
        let max_vis = cols.saturating_sub(1);

        // ── metrics ──────────────────────────────────────────────────────
        let pos = self.pos.load(Ordering::Relaxed);
        let ok = self.ok.load(Ordering::Relaxed);
        let blocked = self.blocked.load(Ordering::Relaxed);
        let dead = self.dead.load(Ordering::Relaxed);
        let workers = self.workers.load(Ordering::Relaxed);
        let profile = tier(workers);

        let elapsed = self.start.elapsed();
        let s = elapsed.as_secs();
        let elapsed_str = format!("{:02}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60);

        let speed = pos / s.max(1);
        let pct = if self.total > 0 {
            pos * 100 / self.total
        } else {
            0
        };
        let eta_s = if speed > 0 {
            self.total.saturating_sub(pos) / speed
        } else {
            0
        };
        let eta_str = if eta_s >= 3600 {
            format!("{}h", (eta_s + 1800) / 3600)
        } else if eta_s >= 60 {
            format!("{}m", (eta_s + 30) / 60)
        } else {
            format!("{eta_s}s")
        };

        // ── profile header (line 1) ───────────────────────────────────
        let profile_raw = format!(
            "  \x1b[2mProfile:\x1b[0m \x1b[33m{profile}\x1b[0m  \x1b[2mWorkers:\x1b[0m \x1b[33m{workers}\x1b[0m  \x1b[2mOutput:\x1b[0m \x1b[33m{}\x1b[0m",
            self.output_display
        );
        let profile_line = fit_to_width(&profile_raw, max_vis);

        // ── bar (line 2) ──────────────────────────────────────────────
        // Right plain (width measurement — no ANSI)
        let right_plain = format!(
            "] {pct:>3}% | {pos}/{tot} | v {ok} X {blocked} o {dead} | {speed}/s | ETA: {eta_str}",
            tot = self.total,
        );
        let right_vis = vis_width(&right_plain);

        // Left prefix: " {sp} [{elapsed}] ["
        let sp_vis: usize = spinner
            .chars()
            .map(|c| UnicodeWidthChar::width(c).unwrap_or(1))
            .sum();
        let left_vis = 1 + sp_vis + 1 + 1 + elapsed_str.len() + 1 + 2;

        // Bar fill
        let bar_w = max_vis.saturating_sub(left_vis + right_vis);
        let filled = if self.total > 0 && bar_w > 0 {
            let pos_u = usize::try_from(pos).unwrap_or(usize::MAX);
            let tot_u = usize::try_from(self.total).unwrap_or(usize::MAX);
            (bar_w * pos_u / tot_u).min(bar_w)
        } else {
            0
        };
        let empty = bar_w.saturating_sub(filled);

        // Colorized bar line
        let sp_col = format!("\x1b[32m{spinner}\x1b[0m");
        let bar_col = format!(
            "\x1b[36m{}\x1b[34;2m{}\x1b[0m",
            "\u{2588}".repeat(filled), // █
            "\u{2591}".repeat(empty),  // ░
        );
        let sep = "\x1b[2m|\x1b[0m";
        let right_col = format!(
            "] {pct:>3}% {sep} {pos}/{tot} {sep} \x1b[32m\u{2713} {ok}\x1b[0m \x1b[31m\u{2717} {blocked}\x1b[0m \x1b[2m\u{25cb} {dead}\x1b[0m {sep} \x1b[33m{speed}/s\x1b[0m {sep} ETA: {eta_str}",
            tot = self.total,
        );
        let bar_raw = format!(" {sp_col} [{elapsed_str}] [{bar_col}{right_col}");
        let bar_line = fit_to_width(&bar_raw, max_vis);

        // ── erase old 2-line block, redraw ───────────────────────────
        //
        // Both previous lines were truncated to (prev_cols - 1) columns.
        // After terminal narrows to curr_cols, each line may wrap to
        // ceil((prev_cols-1) / curr_cols) physical lines.
        // Cursor sits at the LAST physical line of the old bar.
        // go_up = 2 * old_per_line - 1 brings us to top of old profile line.
        // Then \r\x1b[J wipes everything from there down, and we redraw both.
        let pc = self.prev_cols.load(Ordering::Relaxed);
        let go_up = if pc == 0 {
            1 // first render: cursor is on the blank bar-slot line, go up 1 to profile slot
        } else {
            let old_per_line = pc.saturating_sub(1).div_ceil(cols).max(1);
            2 * old_per_line - 1
        };

        let mut o = self.out.lock().unwrap();
        for _ in 0..go_up {
            write!(o, "\x1b[1A").ok();
        }
        write!(o, "\r\x1b[J{profile_line}\n\r{bar_line}").ok();
        o.flush().ok();

        self.prev_cols.store(cols, Ordering::Relaxed);
    }
}
