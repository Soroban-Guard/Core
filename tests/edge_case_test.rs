use soroban_guard_core::analysis::AnalysisEngine;
use soroban_guard_core::parser::ContractParser;
use soroban_guard_core::scoring::SecurityScore;
use soroban_guard_core::Finding;

fn analyze_code(code: &str, file_name: &str) -> (Vec<Finding>, SecurityScore) {
    let parser = ContractParser::new();
    let engine = AnalysisEngine::with_default_rules();
    let contract = parser.parse_source(code).unwrap();
    let report = engine.analyze_contract(&contract, file_name);
    (report.findings, report.score)
}

fn wrap_code(body: &str) -> String {
    format!(
        r#"#![no_std]
use soroban_sdk::{{contract, contractimpl, Address, Env, Symbol}};
#[contract]
pub struct EdgeTest;
#[contractimpl]
impl EdgeTest {{
    pub fn run(env: Env) {{
        {}
    }}
}}"#,
        body
    )
}

fn wrap_code_with_fn(name: &str, body: &str) -> String {
    format!(
        r#"#![no_std]
use soroban_sdk::{{contract, contractimpl, Address, Env, Symbol}};
#[contract]
pub struct EdgeTest;
#[contractimpl]
impl EdgeTest {{
    pub fn {}(env: Env) {{
        {}
    }}
}}"#,
        name, body
    )
}

#[test]
fn multiple_functions_same_key_different_categories() {
    let code = r#"
        #![no_std]
        use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};
        #[contract]
        pub struct MultiKey;
        #[contractimpl]
        impl MultiKey {
            pub fn set_a(env: Env) {
                env.storage().instance().set(&Symbol::new(&env, "x"), &1i128);
            }
            pub fn set_b(env: Env) {
                env.storage().temporary().set(&Symbol::new(&env, "x"), &1i128);
            }
        }
    "#;
    let (findings, _) = analyze_code(code, "multi_key.rs");
    let rule_ids: Vec<_> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        rule_ids.contains(&"S-04"),
        "Instance/temporary confusion on key 'x' should trigger S-04, got: {:?}",
        rule_ids
    );
}

#[test]
fn zero_length_storage_key() {
    let code = wrap_code(r#"env.storage().instance().set(&Symbol::new(&env, ""), &1i128);"#);
    let parser = ContractParser::new();
    let contract = parser.parse_source(&code).unwrap();
    assert!(
        !contract.functions.is_empty(),
        "Should parse even with empty key"
    );
}

#[test]
fn long_function_name() {
    let code = wrap_code_with_fn(
        "this_is_a_very_long_function_name_that_should_still_be_parsed_correctly_by_the_analyzer",
        r#"
            env.storage().instance().set(&Symbol::new(&env, "key"), &1i128);
        "#,
    );
    let parser = ContractParser::new();
    let result = parser.parse_source(&code);
    assert!(result.is_ok(), "Long function names should parse correctly");
    let contract = result.unwrap();
    assert_eq!(contract.functions.len(), 1);
}

#[test]
fn empty_contractimpl_block() {
    let code = r#"
        #![no_std]
        use soroban_sdk::*;
        pub struct Empty;
        #[contractimpl]
        impl Empty {}
    "#;
    let parser = ContractParser::new();
    let contract = parser.parse_source(code).unwrap();
    assert!(contract.functions.is_empty());
    let engine = AnalysisEngine::with_default_rules();
    let findings = engine.run(&contract);
    let rule_ids: Vec<_> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert_eq!(
        rule_ids,
        vec!["S-05"],
        "Empty contract should only have S-05 (no version key), got: {:?}",
        rule_ids
    );
}

#[test]
fn contract_with_complex_expressions() {
    let code = wrap_code(
        r#"
            let a: i128 = env.storage().instance().get(&Symbol::new(&env, "a")).unwrap_or(0);
            let b: i128 = env.storage().instance().get(&Symbol::new(&env, "b")).unwrap_or(0);
            let c = (a + b) * (a - b) / 2;
            env.storage().instance().set(&Symbol::new(&env, "c"), &c);
        "#,
    );
    let (findings, _) = analyze_code(&code, "complex.rs");
    let overflow_rules: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id.starts_with("O-"))
        .collect();
    assert!(
        overflow_rules.len() >= 2,
        "Complex arithmetic should trigger multiple overflow rules, got: {:?}",
        overflow_rules
    );
}

#[test]
fn contract_with_no_storage_ops() {
    let code = wrap_code(
        r#"
            let x = 42;
        "#,
    );
    let (findings, _score) = analyze_code(&code, "no_storage.rs");
    let rule_ids: Vec<_> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        rule_ids.contains(&"A-04"),
        "No-storage contract should have A-04 (public fn without auth), got: {:?}",
        rule_ids
    );
    assert!(
        rule_ids.contains(&"S-05"),
        "No-storage contract should have S-05 (no version key), got: {:?}",
        rule_ids
    );
}

#[test]
fn multiple_require_auth_calls() {
    let code = r#"
        #![no_std]
        use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};
        #[contract]
        pub struct MultiAuth;
        #[contractimpl]
        impl MultiAuth {
            pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
                from.require_auth();
                to.require_auth();
                env.storage().instance().set(&Symbol::new(&env, "bal"), &amount);
            }
        }
    "#;
    let (findings, _) = analyze_code(code, "multi_auth.rs");
    let auth_issues: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id.starts_with("A-"))
        .collect();
    assert!(
        auth_issues.is_empty(),
        "Multiple require_auth calls should suppress all A-01 findings, got: {:?}",
        auth_issues
    );
}

#[test]
fn contract_with_many_storage_keys() {
    let mut body = String::new();
    for i in 0..50 {
        body.push_str(&format!(
            "env.storage().instance().set(&Symbol::new(&env, \"key{}\"), &{}i128);\n",
            i, i
        ));
    }
    let code = wrap_code(&body);
    let parser = ContractParser::new();
    let contract = parser.parse_source(&code).unwrap();
    let total_ops = contract.functions[0].body_analysis.storage_writes.len()
        + contract.functions[0].body_analysis.storage_reads.len();
    assert_eq!(total_ops, 50);
}

#[test]
fn perfect_score_contract() {
    let code = r#"
        #![no_std]
        use soroban_sdk::{contract, contractimpl, Env, Symbol};
        #[contract]
        pub struct Perfect;
        #[contractimpl]
        impl Perfect {
            pub fn __constructor(env: Env) {
                env.storage().instance().set(&Symbol::new(&env, "VERSION"), &1u32);
            }
            pub fn greet(env: Env) -> Symbol {
                Symbol::new(&env, "hello")
            }
        }
    "#;
    let (findings, score) = analyze_code(code, "perfect.rs");
    let has_r03 = findings.iter().any(|f| f.rule_id == "R-03");
    let has_r03_guard = !has_r03;
    let has_s05 = findings.iter().any(|f| f.rule_id == "S-05");
    let has_s05_version = !has_s05;
    let expected_bonus = if has_r03_guard { 5 } else { 0 } + if has_s05_version { 3 } else { 0 };
    let expected_score = 100u8.saturating_sub(
        findings
            .iter()
            .map(|f| match f.severity {
                soroban_guard_core::Severity::Critical => 30,
                soroban_guard_core::Severity::High => 15,
                soroban_guard_core::Severity::Medium => 7,
                soroban_guard_core::Severity::Low => 3,
                soroban_guard_core::Severity::Info => 1,
            })
            .sum::<u8>()
            .saturating_sub(expected_bonus),
    );
    assert_eq!(
        score.overall, expected_score,
        "Score should match calculation"
    );
}

#[test]
fn contract_with_unicode_in_comments() {
    let code = r#"#![no_std]
// 你好, 世界 — Unicode comments should not break parsing
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};
#[contract]
pub struct Unicode;
#[contractimpl]
impl Unicode {
    /// 🔒 This function requires auth
    pub fn set(env: Env, admin: Address, val: i128) {
        admin.require_auth();
        env.storage().instance().set(&Symbol::new(&env, "data"), &val);
    }
}
"#
    .to_string();
    let parser = ContractParser::new();
    let result = parser.parse_source(&code);
    assert!(result.is_ok(), "Unicode comments should parse correctly");
}
