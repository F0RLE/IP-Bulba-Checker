use bulbascan::signatures::{BlockMatcher, get_random_user_agent};
use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};

// ─── Fixtures ─────────────────────────────────────────────────────────────────

const GEO_BLOCKED_BODY: &[u8] = b"<!DOCTYPE html><html><head><title>Access Denied</title></head>\
<body><h1>Access Denied</h1>\
<p>This content is not available in your region.</p>\
<p>Error reference: CF-1020</p>\
<div class=\"cf-error-code\">1020</div></body></html>";

const CLEAN_BODY: &[u8] = b"<!DOCTYPE html><html><head><title>Home</title></head>\
<body><main><h1>Welcome</h1><p>Everything is fine.</p></main></body></html>";

fn large_clean_body() -> Vec<u8> {
    let chunk = b"<p>Lorem ipsum dolor sit amet, consectetur adipiscing elit.</p>\n";
    chunk.repeat(100_000 / chunk.len() + 1)
}

// ─── Benchmarks ───────────────────────────────────────────────────────────────

fn bench_find_body_geo_blocked(c: &mut Criterion) {
    let matcher = BlockMatcher::new(None).unwrap();
    c.bench_function("body_match/geo_blocked", |b| {
        b.iter(|| matcher.find_body_text(std::str::from_utf8(GEO_BLOCKED_BODY).unwrap()));
    });
}

fn bench_find_body_clean(c: &mut Criterion) {
    let matcher = BlockMatcher::new(None).unwrap();
    c.bench_function("body_match/clean_no_hit", |b| {
        b.iter(|| matcher.find_body_text(std::str::from_utf8(CLEAN_BODY).unwrap()));
    });
}

fn bench_find_body_large_clean(c: &mut Criterion) {
    let matcher = BlockMatcher::new(None).unwrap();
    let body = large_clean_body();
    c.bench_function("body_match/large_clean_100kb", |b| {
        b.iter(|| matcher.find_body_text(std::str::from_utf8(&body).unwrap()));
    });
}

fn bench_ua_pool(c: &mut Criterion) {
    c.bench_function("ua_pool/random_pick", |b| {
        b.iter(get_random_user_agent);
    });
}

fn bench_body_match_sizes(c: &mut Criterion) {
    let matcher = BlockMatcher::new(None).unwrap();
    let mut group = c.benchmark_group("body_match/sizes");

    for kb in [1_usize, 4, 16, 64, 128] {
        let chunk = b"Lorem ipsum dolor sit amet consectetur adipiscing elit. ";
        let body: Vec<u8> = chunk.repeat((kb * 1024) / chunk.len() + 1);
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{kb}kb")),
            &body,
            |b, body| {
                b.iter_batched(
                    || body.clone(),
                    |data| matcher.find_body_text(std::str::from_utf8(&data).unwrap()),
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_find_body_geo_blocked,
    bench_find_body_clean,
    bench_find_body_large_clean,
    bench_ua_pool,
    bench_body_match_sizes,
);
criterion_main!(benches);
