use soroban_guard_core::analysis::storage::StorageCollisionDetector;
use soroban_guard_core::analysis::{AnalysisEngine, AnalysisRule};
use soroban_guard_core::parser::ContractParser;
use soroban_guard_core::report::finding::Finding;
use soroban_guard_core::report::severity::Severity;

fn findings_for(path: &str) -> Vec<Finding> {
    let contract = ContractParser::new()
        .parse_file(path)
        .unwrap_or_else(|e| panic!("failed to parse {path}: {e}"));
    StorageCollisionDetector.analyze(&contract)
}

fn findings_for_source(source: &str) -> Vec<Finding> {
    let contract = ContractParser::new()
        .parse_source(source)
        .unwrap_or_else(|e| panic!("failed to parse: {e}\n---\n{source}"));
    StorageCollisionDetector.analyze(&contract)
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

// 1. Short key "a" — S-01 Medium
#[test]
fn test_short_key_s01() {
    let findings = findings_for("tests/fixtures/storage_bad.rs");
    assert!(has_rule(&findings, "S-01"), "expected S-01, got: {findings:?}");
    let s01 = rule(&findings, "S-01");
    assert_eq!(s01.severity, Severity::Medium);
    assert!(s01.message.contains("'a'"));
    assert!(!s01.suggestion.is_empty());
}

// 2. Generic key "balance" — S-02 Low
#[test]
fn test_generic_key_s02() {
    let findings = findings_for("tests/fixtures/storage_bad.rs");
    assert!(has_rule(&findings, "S-02"), "expected S-02, got: {findings:?}");
    let s02_all: Vec<&Finding> = findings.iter().filter(|f| f.rule_id == "S-02").collect();
    for f in &s02_all {
        assert_eq!(f.severity, Severity::Low);
    }
    // Fixture has both "admin" and "balance" as generic keys
    let mentions_balance = s02_all.iter().any(|f| f.message.contains("balance"));
    let mentions_admin = s02_all.iter().any(|f| f.message.contains("admin"));
    assert!(
        mentions_balance || mentions_admin,
        "expected S-02 about 'balance' or 'admin', got: {s02_all:?}"
    );
}

// 3. Mixed types at same key — S-03 High
#[test]
fn test_mixed_types_s03() {
    let findings = findings_for("tests/fixtures/storage_bad.rs");

    let s03: Vec<&Finding> = findings.iter().filter(|f| f.rule_id == "S-03").collect();
    assert!(!s03.is_empty(), "expected S-03, got: {findings:?}");
    assert_eq!(s03[0].severity, Severity::High);
    assert!(s03[0].message.contains("mixed"));
}

// 4. Instance/temporary confusion — S-04 High
#[test]
fn test_instance_temporary_confusion_s04() {
    let findings = findings_for("tests/fixtures/storage_bad.rs");

    let s04: Vec<&Finding> = findings.iter().filter(|f| f.rule_id == "S-04").collect();
    assert!(!s04.is_empty(), "expected S-04, got: {findings:?}");
    assert_eq!(s04[0].severity, Severity::High);
    assert!(s04[0].message.contains("shared_key"));
}

// 5. No version key — S-05 Info
#[test]
fn test_missing_version_s05() {
    let findings = findings_for("tests/fixtures/storage_bad.rs");

    assert!(has_rule(&findings, "S-05"), "expected S-05, got: {findings:?}");
    assert_eq!(rule(&findings, "S-05").severity, Severity::Info);
}

// 6. Version key present — no S-05
#[test]
fn test_version_key_present_no_s05() {
    let source = r#"
        #[contractimpl]
        impl GoodContract {
            pub fn init(env: Env) {
                env.storage().instance().set(&Symbol::new(&env, "VERSION"), &1i128);
                env.storage().instance().set(&Symbol::new(&env, "v1_balance"), &0i128);
            }
        }
    "#;
    let findings = findings_for_source(source);

    assert!(
        !has_rule(&findings, "S-05"),
        "contract with VERSION key should not trigger S-05, got: {findings:?}"
    );
    assert!(
        !has_rule(&findings, "S-01"),
        "descriptive key should not trigger S-01, got: {findings:?}"
    );
    assert!(
        !has_rule(&findings, "S-02"),
        "descriptive key should not trigger S-02, got: {findings:?}"
    );
}

// 7. Short key "a" inline
#[test]
fn test_short_key_inline() {
    let source = r#"
        #[contractimpl]
        impl C {
            pub fn set(env: Env, v: i128) {
                env.storage().instance().set(&Symbol::new(&env, "a"), &v);
            }
        }
    "#;
    let findings = findings_for_source(source);

    assert!(has_rule(&findings, "S-01"), "got: {findings:?}");
    assert_eq!(rule(&findings, "S-01").severity, Severity::Medium);
}

// 8. Generic key inline
#[test]
fn test_generic_key_inline() {
    let source = r#"
        #[contractimpl]
        impl C {
            pub fn set(env: Env, v: i128) {
                env.storage().instance().set(&Symbol::new(&env, "owner"), &v);
            }
        }
    "#;
    let findings = findings_for_source(source);

    assert!(has_rule(&findings, "S-02"), "got: {findings:?}");
    assert_eq!(rule(&findings, "S-02").severity, Severity::Low);
}

// 9. Mixed types detected inline
#[test]
fn test_mixed_types_inline() {
    let source = r#"
        #[contractimpl]
        impl C {
            pub fn set_i128(env: Env, v: i128) {
                env.storage().instance().set(&Symbol::new(&env, "x"), &v);
            }
            pub fn set_addr(env: Env, addr: Address) {
                env.storage().instance().set(&Symbol::new(&env, "x"), &addr);
            }
        }
    "#;
    let findings = findings_for_source(source);

    let s03: Vec<&Finding> = findings.iter().filter(|f| f.rule_id == "S-03").collect();
    assert!(!s03.is_empty(), "expected S-03, got: {findings:?}");
    assert_eq!(s03[0].severity, Severity::High);
    assert!(s03[0].message.contains("x"));
    assert!(s03[0].message.contains("v"));
    assert!(s03[0].message.contains("addr"));
}

// 10. Instance/temporary confusion inline
#[test]
fn test_instance_temp_confusion_inline() {
    let source = r#"
        #[contractimpl]
        impl C {
            pub fn set_instance(env: Env, v: i128) {
                env.storage().instance().set(&Symbol::new(&env, "key"), &v);
            }
            pub fn set_temporary(env: Env, v: i128) {
                env.storage().temporary().set(&Symbol::new(&env, "key"), &v);
            }
        }
    "#;
    let findings = findings_for_source(source);

    let s04: Vec<&Finding> = findings.iter().filter(|f| f.rule_id == "S-04").collect();
    assert!(!s04.is_empty(), "expected S-04, got: {findings:?}");
    assert_eq!(s04[0].severity, Severity::High);
    assert!(s04[0].message.contains("key"));
}

// 11. Descriptive key — no S-01 or S-02
#[test]
fn test_descriptive_key_no_findings() {
    let source = r#"
        #[contractimpl]
        impl C {
            pub fn set(env: Env, v: i128) {
                env.storage().instance().set(&Symbol::new(&env, "v1_user_balance"), &v);
            }
        }
    "#;
    let findings = findings_for_source(source);

    assert!(!has_rule(&findings, "S-01"), "got: {findings:?}");
    assert!(!has_rule(&findings, "S-02"), "got: {findings:?}");
}

// 12. No storage operations — only S-05 may fire
#[test]
fn test_no_storage_ops() {
    let source = r#"
        #[contractimpl]
        impl C {
            pub fn nothing(env: Env) {}
        }
    "#;
    let findings = findings_for_source(source);

    // S-05 fires because there's no version key
    assert!(has_rule(&findings, "S-05"), "got: {findings:?}");
    // No other rules should fire
    assert!(!has_rule(&findings, "S-01"));
    assert!(!has_rule(&findings, "S-02"));
    assert!(!has_rule(&findings, "S-03"));
    assert!(!has_rule(&findings, "S-04"));
}

// 13. Fixture triggers all relevant rules
#[test]
fn test_fixture_triggers_multiple_rules() {
    let findings = findings_for("tests/fixtures/storage_bad.rs");

    assert!(has_rule(&findings, "S-01"), "got: {findings:?}");
    assert!(has_rule(&findings, "S-02"), "got: {findings:?}");
    assert!(has_rule(&findings, "S-03"), "got: {findings:?}");
    assert!(has_rule(&findings, "S-04"), "got: {findings:?}");
    assert!(has_rule(&findings, "S-05"), "got: {findings:?}");
}

// 14. Engine registration
#[test]
fn test_engine_registers_storage() {
    let engine = AnalysisEngine::with_default_rules();
    assert!(engine.rule_count() >= 4);

    let contract = ContractParser::new()
        .parse_file("tests/fixtures/storage_bad.rs")
        .expect("parse");
    let findings = engine.run(&contract);
    assert!(has_rule(&findings, "S-01"), "engine should surface S-01, got: {findings:?}");
    assert!(has_rule(&findings, "S-05"), "engine should surface S-05, got: {findings:?}");
}

// 15. Detector metadata
#[test]
fn test_detector_metadata() {
    let d = StorageCollisionDetector;
    assert_eq!(d.id(), "storage");
    assert!(!d.name().is_empty());
    assert!(!d.description().is_empty());
}

// 16. symbol_short!("a") also detected
#[test]
fn test_short_key_via_macro() {
    let source = r#"
        #[contractimpl]
        impl C {
            pub fn set(env: Env, v: i128) {
                env.storage().instance().set(&symbol!("b"), &v);
            }
        }
    "#;
    let findings = findings_for_source(source);

    assert!(has_rule(&findings, "S-01"), "got: {findings:?}");
    assert!(rule(&findings, "S-01").message.contains("'b'"));
}
