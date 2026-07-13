use soroban_guard_core::analysis::reentrancy::ReentrancyDetector;
use soroban_guard_core::analysis::{AnalysisEngine, AnalysisRule};
use soroban_guard_core::parser::ContractParser;
use soroban_guard_core::report::finding::Finding;
use soroban_guard_core::report::severity::Severity;

/// Parse a fixture file and run the reentrancy detector over it.
fn findings_for(path: &str) -> Vec<Finding> {
    let contract = ContractParser::new()
        .parse_file(path)
        .unwrap_or_else(|e| panic!("failed to parse {path}: {e}"));
    ReentrancyDetector.analyze(&contract)
}

fn has_rule(findings: &[Finding], rule_id: &str) -> bool {
    findings.iter().any(|f| f.rule_id == rule_id)
}

fn rule<'a>(findings: &'a [Finding], rule_id: &str) -> &'a Finding {
    findings
        .iter()
        .find(|f| f.rule_id == rule_id)
        .unwrap_or_else(|| panic!("expected a {rule_id} finding, got: {findings:?}"))
}

#[test]
fn test_vulnerable_contract_triggers_r01() {
    let findings = findings_for("tests/fixtures/reentrancy_vulnerable.rs");

    // R-01: state write after external call, reported as Critical.
    assert!(has_rule(&findings, "R-01"), "expected R-01, got: {findings:?}");
    let r01 = rule(&findings, "R-01");
    assert_eq!(r01.severity, Severity::Critical);
    assert!(r01.message.contains("withdraw"));
    assert!(!r01.suggestion.is_empty());
    // The location should resolve to a real call site, not a 0/0 stub.
    assert!(r01.location.contains("VulnerableVault"));
}

#[test]
fn test_safe_contract_has_no_r01() {
    let findings = findings_for("tests/fixtures/reentrancy_safe.rs");

    // State is updated before the call: no checks-effects-interactions violation.
    assert!(
        !has_rule(&findings, "R-01"),
        "safe contract should not trigger R-01, got: {findings:?}"
    );
    // It still makes an external call with no guard, so R-03 is expected.
    assert!(has_rule(&findings, "R-03"));
}

#[test]
fn test_read_only_reentrancy_is_medium() {
    let findings = findings_for("tests/fixtures/reentrancy_readonly.rs");

    assert!(has_rule(&findings, "R-02"), "expected R-02, got: {findings:?}");
    let r02 = rule(&findings, "R-02");
    assert_eq!(r02.severity, Severity::Medium);
    assert!(r02.message.contains("balance"));
}

#[test]
fn test_guard_present_suppresses_r03() {
    let findings = findings_for("tests/fixtures/reentrancy_guarded.rs");

    // A REENTRANCY_GUARD storage key is present, so R-03 must not fire.
    assert!(
        !has_rule(&findings, "R-03"),
        "guarded contract should not trigger R-03, got: {findings:?}"
    );
    // State is updated before the external call (guard writes are ignored),
    // so R-01 must not fire either.
    assert!(
        !has_rule(&findings, "R-01"),
        "guarded contract should not trigger R-01, got: {findings:?}"
    );
}

#[test]
fn test_cross_function_reentrancy_r04() {
    // Two public functions both make external calls and share the `balance` key.
    let source = r#"
        #[contractimpl]
        impl Bank {
            pub fn withdraw(env: Env, token: Address, amount: i128) {
                let b: i128 = env.storage().instance().get(&Symbol::new(&env, "balance")).unwrap();
                env.storage().instance().set(&Symbol::new(&env, "balance"), &(b - amount));
                env.invoke_contract::<()>(&token, &Symbol::new(&env, "transfer"), (&amount,));
            }
            pub fn borrow(env: Env, token: Address, amount: i128) {
                let b: i128 = env.storage().instance().get(&Symbol::new(&env, "balance")).unwrap();
                env.storage().instance().set(&Symbol::new(&env, "balance"), &(b + amount));
                env.invoke_contract::<()>(&token, &Symbol::new(&env, "transfer"), (&amount,));
            }
        }
    "#;
    let contract = ContractParser::new().parse_source(source).expect("parse");
    let findings = ReentrancyDetector.analyze(&contract);

    let r04: Vec<_> = findings.iter().filter(|f| f.rule_id == "R-04").collect();
    assert!(!r04.is_empty(), "expected R-04, got: {findings:?}");
    assert_eq!(r04[0].severity, Severity::High);
    assert!(r04.iter().all(|f| f.message.contains("balance")));
}

#[test]
fn test_no_external_calls_no_findings() {
    // A contract that never makes cross-contract calls has nothing to report.
    let source = r#"
        #[contractimpl]
        impl Counter {
            pub fn increment(env: Env) {
                let n: i128 = env.storage().instance().get(&Symbol::new(&env, "n")).unwrap_or(0);
                env.storage().instance().set(&Symbol::new(&env, "n"), &(n + 1));
            }
        }
    "#;
    let contract = ContractParser::new().parse_source(source).expect("parse");
    let findings = ReentrancyDetector.analyze(&contract);
    assert!(findings.is_empty(), "expected no findings, got: {findings:?}");
}

#[test]
fn test_analysis_engine_runs_reentrancy_first() {
    let engine = AnalysisEngine::with_default_rules();
    assert!(engine.rule_count() >= 1);

    let contract = ContractParser::new()
        .parse_file("tests/fixtures/reentrancy_vulnerable.rs")
        .expect("parse");
    let findings = engine.run(&contract);
    assert!(has_rule(&findings, "R-01"), "engine should surface R-01");
}

#[test]
fn test_detector_metadata() {
    let d = ReentrancyDetector;
    assert_eq!(d.id(), "reentrancy");
    assert!(!d.name().is_empty());
    assert!(!d.description().is_empty());
}
