use soroban_guard_core::analysis::AnalysisEngine;
use soroban_guard_core::parser::ContractParser;
use soroban_guard_core::Finding;

fn analyze_code(code: &str, _file_name: &str) -> Vec<Finding> {
    let parser = ContractParser::new();
    let engine = AnalysisEngine::with_default_rules();
    let contract = parser.parse_source(code).unwrap();
    engine.run(&contract)
}

fn code_with_body(body: &str) -> String {
    format!(
        r#"#![no_std]
use soroban_sdk::{{contract, contractimpl, Address, Env, Symbol}};
#[contract]
pub struct Test;
#[contractimpl]
impl Test {{
    pub fn run(env: Env) {{
        {}
    }}
}}"#,
        body
    )
}

#[test]
fn contract_with_no_functions() {
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
}

#[test]
fn contract_with_only_constructor() {
    let code = r#"
        #![no_std]
        use soroban_sdk::*;
        pub struct InitOnly;
        #[contractimpl]
        impl InitOnly {
            pub fn __constructor(env: Env) {
                env.storage().instance().set(&Symbol::new(&env, "VERSION"), &1u32);
            }
        }
    "#;
    let parser = ContractParser::new();
    let engine = AnalysisEngine::with_default_rules();
    let contract = parser.parse_source(code).unwrap();
    assert_eq!(contract.functions.len(), 1);
    let findings = engine.run(&contract);
    let rule_ids: Vec<_> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        !rule_ids.contains(&"A-01"),
        "Constructor should not trigger A-01, got: {:?}",
        rule_ids
    );
    assert!(
        !rule_ids.contains(&"A-02"),
        "Constructor should not trigger A-02, got: {:?}",
        rule_ids
    );
    assert!(
        !rule_ids.contains(&"R-01"),
        "Constructor should not trigger R-01, got: {:?}",
        rule_ids
    );
}

#[test]
fn contract_with_nested_calls() {
    let code = code_with_body(
        r#"
            let result = env.invoke_contract::<()>(&addr, &Symbol::new(&env, "inner"), (&arg,));
            let other = env.invoke_contract::<i128>(&other, &Symbol::new(&env, "get"), ());
            env.storage().instance().set(&Symbol::new(&env, "key"), &result);
        "#,
    );
    let findings = analyze_code(&code, "nested.rs");
    assert!(
        findings.iter().any(|f| f.rule_id == "R-01"),
        "Nested external calls followed by store should trigger R-01, got: {:?}",
        findings
    );
}

#[test]
fn contract_with_conditional_auth() {
    let code = r#"
        #![no_std]
        use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};
        #[contract]
        pub struct Conditional;
        #[contractimpl]
        impl Conditional {
            pub fn guarded_set(env: Env, admin: Address, key: Symbol, value: i128) {
                if admin == env.current_contract_address() {
                    env.storage().instance().set(&key, &value);
                } else {
                    admin.require_auth();
                    env.storage().instance().set(&key, &value);
                }
            }
        }
    "#;
    let findings = analyze_code(code, "conditional.rs");
    let rule_ids: Vec<_> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        !rule_ids.contains(&"A-01"),
        "Conditional auth should suppress A-01 (require_auth is present in one branch), got: {:?}",
        rule_ids
    );
}

#[test]
fn contract_named_admin_without_admin_function() {
    let code = r#"
        #![no_std]
        use soroban_sdk::{contract, contractimpl, Env, Symbol};
        #[contract]
        pub struct AdminConfig;
        #[contractimpl]
        impl AdminConfig {
            pub fn set(env: Env, key: Symbol, value: i128) {
                env.storage().instance().set(&key, &value);
            }
        }
    "#;
    let findings = analyze_code(code, "admin_config.rs");
    let rule_ids: Vec<_> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        !rule_ids.contains(&"A-02"),
        "Contract named 'AdminConfig' but no admin-named function — should not trigger A-02 on 'set', got: {:?}",
        rule_ids
    );
}

#[test]
fn division_by_literal_not_flagged() {
    let code = code_with_body(
        r#"
            let result = total / 100;
        "#,
    );
    let findings = analyze_code(&code, "div_literal.rs");
    assert!(
        !findings.iter().any(|f| f.rule_id == "O-03"),
        "Division by literal 100 should not trigger O-03, got: {:?}",
        findings
    );
}

#[test]
fn checked_arithmetic_not_flagged() {
    let code = code_with_body(
        r#"
            let x: i128 = env.storage().instance().get(&Symbol::new(&env, "val")).unwrap_or(0);
            let y = x.checked_add(5).unwrap();
        "#,
    );
    let findings = analyze_code(&code, "checked.rs");
    assert!(
        !findings.iter().any(|f| f.rule_id.starts_with("O-0")),
        "Checked arithmetic should not trigger overflow rules, got: {:?}",
        findings
    );
}
