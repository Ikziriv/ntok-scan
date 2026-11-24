//! `svcdb::match_banner` hot-path bench — the video's "perf stat" step.
//! Mixed banners: early hits, late hits, and a worst-case miss that must
//! scan the whole probe DB.
use criterion::{Criterion, criterion_group, criterion_main};
use ntok_core::svcdb;
use std::hint::black_box;
use std::time::Duration;

const BANNERS: &[&str] = &[
    "SSH-2.0-OpenSSH_9.6p1 Debian-5\r\n",
    "HTTP/1.1 200 OK\r\nServer: Apache/2.4.62 (Debian)\r\n\r\n",
    "+PONG\r\n",
    "RFB 003.008\n",
    "220 mail.example.com ESMTP Postfix (Ubuntu)\r\n",
    "Xyzzy-Unknown/9.9 garbled-banner-that-matches-nothing 12345\r\n",
];

fn match_banner(c: &mut Criterion) {
    svcdb::warm(); // compile once outside the measured loop
    let mut g = c.benchmark_group("match_banner");
    g.measurement_time(Duration::from_secs(4));
    for b in BANNERS {
        g.bench_function(*b, |ben| {
            ben.iter(|| black_box(svcdb::match_banner(black_box(b))))
        });
    }
    g.finish();
}

criterion_group!(benches, match_banner);
criterion_main!(benches);
