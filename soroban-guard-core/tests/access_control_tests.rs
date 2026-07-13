use soroban_guard_core::analysis::access_control::AccessControlDetector;
use soroban_guard_core::analysis::{AnalysisEngine, AnalysisRule};
use soroban_guard_core::parser::ContractParser;
use soroban_guard_core::report::finding::Finding;
use soroban_guard_core::report::severity::Severity;

fn findings_for(path: &str) -> Vec<Finding> {
    let contract = ContractParser::new()
        .parse_file(path)
        .unwrap_or_else(|e| panic!("failed to parse {path}: {e}"));
    AccessControlDetector.analyze(&contract)
}

fn findings_for_source(source: &str) -> Vec<Finding> {
    let contract = ContractParser::new()
        .parse_source(source)
        .unwrap_or_else(|e| panic!("failed to parse: {e}\n---\n{source}"));
    AccessControlDetector.analyze(&contract)
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

// 1. Test missing auth on state write — A-01 Critical/High
#[test]
fn test_missing_auth_on_state_write() {
    let findings = findings_for("tests/fixtures/access_control_bad.rs");

    // withdraw_all has storage write but no auth — A-01
    assert!(has_rule(&findings, "A-01"), "expected A-01, got: {findings:?}");
    let a01 = rule(&findings, "A-01");
    assert!(
        a01.severity == Severity::High || a01.severity == Severity::Critical,
        "A-01 severity should be High or Critical, got {:?}",
        a01.severity
    );
    assert!(a01.message.contains("withdraw_all") || a01.message.contains("state"));
    assert!(!a01.suggestion.is_empty());
    assert!(a01.location.contains("AdminContract"));
}

// 2. Test admin function without auth — A-02 High
#[test]
fn test_admin_fn_without_auth() {
    let findings = findings_for("tests/fixtures/access_control_bad.rs");

    // set_admin is an admin-named function without auth
    let a02: Vec<&Finding> = findings.iter().filter(|f| f.rule_id == "A-02").collect();
    assert!(!a02.is_empty(), "expected A-02, got: {findings:?}");
    assert_eq!(a02[0].severity, Severity::High);
    assert!(a02[0].message.contains("set_admin"));
}

// 3. Test properly guarded function — no A-01 finding
#[test]
fn test_guarded_function_no_finding() {
    let source = r#"
        #[contractimpl]
        impl SafeContract {
            pub fn guarded_withdraw(env: Env, caller: Address, amount: i128) {
                caller.require_auth();
                let balance: i128 = env.storage().instance().get(&Symbol::new(&env, "balance")).unwrap_or(0);
                if balance >= amount {
                    env.storage().instance().set(&Symbol::new(&env, "balance"), &(balance - amount));
                }
            }
        }
    "#;
    let findings = findings_for_source(source);

    // Should NOT have A-01 (auth present)
    assert!(
        !has_rule(&findings, "A-01"),
        "guarded function should not trigger A-01, got: {findings:?}"
    );
    // Should NOT have A-02 (not admin named)
    assert!(!has_rule(&findings, "A-02"));
    // Should NOT have A-03 (uses require_auth, not require_auth_for_args)
    assert!(!has_rule(&findings, "A-03"));
}

// 4. Test address parameter without auth — A-04 Medium
#[test]
fn test_address_param_without_auth() {
    let source = r#"
        #[contractimpl]
        impl UnsafeContract {
            pub fn transfer(env: Env, caller: Address, to: Address, amount: i128) {
                let balance: i128 = env.storage().instance().get(&Symbol::new(&env, "balance")).unwrap_or(0);
                if balance >= amount {
                    env.storage().instance().set(&Symbol::new(&env, "balance"), &(balance - amount));
                }
            }
        }
    "#;
    let findings = findings_for_source(source);

    // Both A-01 (no auth on state write) and A-04 (Address param not authenticated) expected
    assert!(has_rule(&findings, "A-01"), "expected A-01, got: {findings:?}");
    let a04_items: Vec<&Finding> = findings.iter().filter(|f| f.rule_id == "A-04").collect();
    assert!(!a04_items.is_empty(), "expected A-04, got: {findings:?}");
    // The A-04 about Address param not authenticated should be Medium
    let addr_auth = a04_items.iter().find(|f| f.severity == Severity::Medium);
    assert!(
        addr_auth.is_some(),
        "expected A-04 Medium about unauthenticated Address param, got: {a04_items:?}"
    );
    assert!(addr_auth.unwrap().message.contains("caller"));
}

// 5. Test init function excluded from A-01
#[test]
fn test_constructor_excluded() {
    let source = r#"
        #[contractimpl]
        impl MyContract {
            pub fn __constructor(env: Env, admin: Address) {
                env.storage().instance().set(&Symbol::new(&env, "admin"), &admin);
            }
        }
    "#;
    let findings = findings_for_source(source);

    // __constructor writes storage but has no auth — should NOT trigger A-01
    assert!(
        !has_rule(&findings, "A-01"),
        "constructor should not trigger A-01, got: {findings:?}"
    );
}

// 6. Test A-04 Info for view functions (public, no auth, no Address, no state write)
#[test]
fn test_view_function_flagged_a04_info() {
    let source = r#"
        #[contractimpl]
        impl ViewContract {
            pub fn get_balance(env: Env) -> i128 {
                env.storage().instance().get(&Symbol::new(&env, "balance")).unwrap_or(0)
            }
        }
    "#;
    let findings = findings_for_source(source);

    let a04_infos: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.rule_id == "A-04" && f.severity == Severity::Info)
        .collect();
    assert!(
        !a04_infos.is_empty(),
        "expected A-04 Info for view fn, got: {findings:?}"
    );
    assert!(a04_infos[0].message.contains("get_balance"));
}

// 7. Test A-04 High for public fn without auth that modifies state
#[test]
fn test_public_state_mutator_flagged_a04_high() {
    let source = r#"
        #[contractimpl]
        impl UnsafeContract {
            pub fn reset(env: Env) {
                env.storage().instance().set(&Symbol::new(&env, "balance"), &0i128);
            }
        }
    "#;
    let findings = findings_for_source(source);

    // Should have both A-01 and A-04
    assert!(has_rule(&findings, "A-01"), "expected A-01, got: {findings:?}");
    let a04_high: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.rule_id == "A-04" && f.severity == Severity::High)
        .collect();
    assert!(
        !a04_high.is_empty(),
        "expected A-04 High for public state mutator, got: {findings:?}"
    );
}

// 8. Test A-03: require_auth_for_args without Address auth
#[test]
fn test_weak_auth_pattern_a03() {
    let source = r#"
        #[contractimpl]
        impl WeakAuthContract {
            pub fn transfer(env: Env, caller: Address, to: Address, amount: i128) {
                caller.require_auth_for_args(&[&amount]);
                let balance: i128 = env.storage().instance().get(&Symbol::new(&env, "balance")).unwrap_or(0);
                if balance >= amount {
                    env.storage().instance().set(&Symbol::new(&env, "balance"), &(balance - amount));
                }
            }
        }
    "#;
    let findings = findings_for_source(source);

    assert!(
        has_rule(&findings, "A-03"),
        "expected A-03 for weak auth, got: {findings:?}"
    );
    assert_eq!(rule(&findings, "A-03").severity, Severity::Medium);
}

// 9. Test A-03 not triggered when require_auth is also present
#[test]
fn test_a03_not_triggered_when_require_auth_present() {
    let source = r#"
        #[contractimpl]
        impl SafeContract {
            pub fn transfer(env: Env, caller: Address, to: Address, amount: i128) {
                caller.require_auth();
                caller.require_auth_for_args(&[&amount, &caller]);
                let balance: i128 = env.storage().instance().get(&Symbol::new(&env, "balance")).unwrap_or(0);
                if balance >= amount {
                    env.storage().instance().set(&Symbol::new(&env, "balance"), &(balance - amount));
                }
            }
        }
    "#;
    let findings = findings_for_source(source);

    assert!(
        !has_rule(&findings, "A-03"),
        "A-03 should not fire when require_auth is present, got: {findings:?}"
    );
}

// 10. Test hardcoded address A-05
#[test]
fn test_hardcoded_address_a05() {
    let source = r#"
        #[contractimpl]
        impl BadConfigContract {
            pub fn init(env: Env) {
                let admin = Address::from_str(&env, "GA7QYNF7SOWQ3GLR2BGM4DZP6K6V6YFQ7D6YFQ7D6YFQ7D6YFQ7D6YFQ");
                env.storage().instance().set(&Symbol::new(&env, "admin"), &admin);
            }
        }
    "#;
    let findings = findings_for_source(source);

    assert!(
        has_rule(&findings, "A-05"),
        "expected A-05 for hardcoded address, got: {findings:?}"
    );
    assert_eq!(rule(&findings, "A-05").severity, Severity::Medium);
    assert!(rule(&findings, "A-05").message.contains("GA7QYNF7"));
}

// 11. Test multiple findings from fixture
#[test]
fn test_fixture_triggers_multiple_rules() {
    let findings = findings_for("tests/fixtures/access_control_bad.rs");

    // Should have A-01, A-02, A-03, A-04, A-05
    assert!(has_rule(&findings, "A-01"), "got: {findings:?}");
    assert!(has_rule(&findings, "A-02"), "got: {findings:?}");
    assert!(has_rule(&findings, "A-05"), "got: {findings:?}");

    // reset() is pub, no auth, no address params, modifies state => A-04 High
    let a04_high: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.rule_id == "A-04" && f.severity == Severity::High)
        .collect();
    assert!(!a04_high.is_empty(), "expected A-04 High, got: {findings:?}");

    // check_balance is pub, no auth, no address, no state write => A-04 Info
    let a04_info: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.rule_id == "A-04" && f.severity == Severity::Info)
        .collect();
    assert!(!a04_info.is_empty(), "expected A-04 Info, got: {findings:?}");

    // guarded_withdraw should have NO findings
    let guarded_findings: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.message.contains("guarded_withdraw"))
        .collect();
    assert!(
        guarded_findings.is_empty(),
        "guarded_withdraw should have no findings, got: {guarded_findings:?}"
    );
}

// 12. Test engine registration
#[test]
fn test_engine_registers_access_control() {
    let engine = AnalysisEngine::with_default_rules();
    assert!(engine.rule_count() >= 3);

    let contract = ContractParser::new()
        .parse_file("tests/fixtures/access_control_bad.rs")
        .expect("parse");
    let findings = engine.run(&contract);
    assert!(has_rule(&findings, "A-01"), "engine should surface A-01");
    assert!(has_rule(&findings, "A-05"), "engine should surface A-05");
}

// 13. Test detector metadata
#[test]
fn test_detector_metadata() {
    let d = AccessControlDetector;
    assert_eq!(d.id(), "access_control");
    assert!(!d.name().is_empty());
    assert!(!d.description().is_empty());
}
