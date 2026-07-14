use criterion::{black_box, criterion_group, criterion_main, Criterion};
use soroban_guard_core::analysis::AnalysisEngine;
use soroban_guard_core::parser::ContractParser;

fn bench_analyze_small_contract(c: &mut Criterion) {
    let code = r#"
        #![no_std]
        use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};
        #[contract]
        pub struct Small;
        #[contractimpl]
        impl Small {
            pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
                from.require_auth();
                let balance: i128 = env.storage().instance()
                    .get(&Symbol::new(&env, "balance")).unwrap_or(0);
                env.invoke_contract::<()>(&to, &Symbol::new(&env, "transfer"), (&amount,));
                env.storage().instance()
                    .set(&Symbol::new(&env, "balance"), &(balance - amount));
            }
        }
    "#;
    let parser = ContractParser::new();
    let engine = AnalysisEngine::with_default_rules();
    let contract = parser.parse_source(code).unwrap();

    c.bench_function("analyze_small_contract", |b| {
        b.iter(|| {
            let findings = engine.run(black_box(&contract));
            black_box(findings)
        })
    });
}

fn bench_parse_large_contract(c: &mut Criterion) {
    let mut code = String::from(
        r#"
        #![no_std]
        use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};
        #[contract]
        pub struct Large;
        #[contractimpl]
        impl Large {
        "#,
    );
    for i in 0..100 {
        code.push_str(&format!(
            "    pub fn fn_{}(env: Env) {{ env.storage().instance().set(&Symbol::new(&env, \"key{}\"), &{}i128); }}\n",
            i, i, i
        ));
    }
    code.push('}');

    c.bench_function("parse_large_contract_100_fns", |b| {
        b.iter(|| {
            let parser = ContractParser::new();
            let contract = parser.parse_source(black_box(&code)).unwrap();
            black_box(contract)
        })
    });
}

fn bench_full_pipeline_vulnerable(c: &mut Criterion) {
    let code = include_str!("../tests/fixtures/contracts/vault_vulnerable.rs");
    let parser = ContractParser::new();
    let engine = AnalysisEngine::with_default_rules();

    c.bench_function("full_pipeline_vault_vulnerable", |b| {
        b.iter(|| {
            let contract = parser.parse_source(black_box(code)).unwrap();
            let report = engine.analyze_contract(black_box(&contract), "vault_vulnerable.rs");
            black_box(report)
        })
    });
}

fn bench_full_pipeline_safe(c: &mut Criterion) {
    let code = include_str!("../tests/fixtures/contracts/vault_safe.rs");
    let parser = ContractParser::new();
    let engine = AnalysisEngine::with_default_rules();

    c.bench_function("full_pipeline_vault_safe", |b| {
        b.iter(|| {
            let contract = parser.parse_source(black_box(code)).unwrap();
            let report = engine.analyze_contract(black_box(&contract), "vault_safe.rs");
            black_box(report)
        })
    });
}

criterion_group!(
    benches,
    bench_analyze_small_contract,
    bench_parse_large_contract,
    bench_full_pipeline_vulnerable,
    bench_full_pipeline_safe,
);
criterion_main!(benches);
