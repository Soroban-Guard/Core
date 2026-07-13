use criterion::{criterion_group, criterion_main, Criterion};

fn benchmark_empty_analysis(c: &mut Criterion) {
    c.bench_function("empty_analysis", |b| {
        b.iter(|| {
            let _config = soroban_guard_core::Config {
                paths: vec![],
                format: soroban_guard_core::OutputFormat::Human,
                severity: soroban_guard_core::SeverityLevel::Warn,
                output: None,
                exclude: None,
                jobs: 1,
            };
        });
    });
}

criterion_group!(benches, benchmark_empty_analysis);
criterion_main!(benches);
