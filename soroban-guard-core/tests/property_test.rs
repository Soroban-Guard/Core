use proptest::prelude::*;
use soroban_guard_core::analysis::AnalysisEngine;
use soroban_guard_core::parser::ContractParser;

fn wrap_in_contract(code: &str) -> String {
    format!(
        r#"#![no_std]
use soroban_sdk::{{contract, contractimpl, Address, Env, Symbol}};
#[contract]
pub struct PropTest;
#[contractimpl]
impl PropTest {{
    pub fn run(env: Env) {{
        {}
    }}
}}"#,
        code
    )
}

proptest! {
    #[test]
    fn doesnt_crash_on_random_code(code in prop::string::string_regex(".{0,200}").unwrap()) {
        let wrapped = wrap_in_contract(&code);
        let parser = ContractParser::new();
        let result = parser.parse_source(&wrapped);
        if let Ok(contract) = result {
            let engine = AnalysisEngine::with_default_rules();
            let findings = engine.run(&contract);
            prop_assert!(findings.len() < 100,
                "Suspiciously many findings ({}) for random input", findings.len());
        }
    }

    #[test]
    fn doesnt_crash_with_valid_identifiers(
        name in "[a-zA-Z_][a-zA-Z0-9_]*",
        key in "[a-zA-Z_][a-zA-Z0-9_]{0,10}",
    ) {
        let code = format!(
            r#"#![no_std]
use soroban_sdk::{{contract, contractimpl, Address, Env, Symbol}};
#[contract]
pub struct {}Var;
#[contractimpl]
impl {}Var {{
    pub fn {}(env: Env) {{
        env.storage().instance().set(&Symbol::new(&env, "{}"), &1i128);
    }}
}}
"#,
            name, name, name, key
        );
        let parser = ContractParser::new();
        let result = parser.parse_source(&code);
        if let Ok(contract) = result {
            let engine = AnalysisEngine::with_default_rules();
            let _findings = engine.run(&contract);
        }
    }

    #[test]
    fn doesnt_crash_on_various_literals(
        num in -10000i128..10000i128,
        flag in proptest::bool::ANY,
    ) {
        let code = format!(
            r#"#![no_std]
use soroban_sdk::{{contract, contractimpl, Env, Symbol}};
#[contract]
pub struct LitTest;
#[contractimpl]
impl LitTest {{
    pub fn run(env: Env) {{
        let x: i128 = {};
        let _ = {};
        env.storage().instance().set(&Symbol::new(&env, "val"), &x);
    }}
}}
"#,
            num, flag
        );
        let parser = ContractParser::new();
        let result = parser.parse_source(&code);
        if let Ok(contract) = result {
            let engine = AnalysisEngine::with_default_rules();
            let _findings = engine.run(&contract);
        }
    }

    #[test]
    fn doesnt_crash_on_various_arithmetic(
        a in -1000i128..1000i128,
        b in -1000i128..1000i128,
    ) {
        let code = format!(
            r#"#![no_std]
use soroban_sdk::{{contract, contractimpl, Env, Symbol}};
#[contract]
pub struct ArithTest;
#[contractimpl]
impl ArithTest {{
    pub fn run(env: Env) {{
        let a: i128 = {};
        let b: i128 = {};
        let c = a + b;
        let d = a - b;
        let e = a * b;
        let f = a / b;
        env.storage().instance().set(&Symbol::new(&env, "res"), &c);
    }}
}}
"#,
            a, b
        );
        let parser = ContractParser::new();
        let result = parser.parse_source(&code);
        if let Ok(contract) = result {
            let engine = AnalysisEngine::with_default_rules();
            let findings = engine.run(&contract);
            prop_assert!(findings.iter().any(|f| f.rule_id == "O-01"),
                "Bare arithmetic should trigger O-01, got {:?}",
                findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>());
        }
    }
}
