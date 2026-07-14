use soroban_guard_core::analysis::overflow::OverflowChecker;
use soroban_guard_core::analysis::{AnalysisEngine, AnalysisRule};
use soroban_guard_core::parser::ContractParser;
use soroban_guard_core::report::finding::Finding;
use soroban_guard_core::report::severity::Severity;

/// Parse a source snippet and run the overflow checker over it. The snippet is
/// wrapped in a `#[contractimpl] impl` so the parser records function bodies.
fn findings_for_source(body: &str) -> Vec<Finding> {
    let source = format!("#[contractimpl]\nimpl C {{\n{}\n}}\n", body);
    let contract = ContractParser::new()
        .parse_source(&source)
        .unwrap_or_else(|e| panic!("failed to parse: {e}\n---\n{source}"));
    OverflowChecker.analyze(&contract)
}

fn findings_for_file(path: &str) -> Vec<Finding> {
    let contract = ContractParser::new()
        .parse_file(path)
        .unwrap_or_else(|e| panic!("failed to parse {path}: {e}"));
    OverflowChecker.analyze(&contract)
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

// 1. Unchecked arithmetic on i128 → O-01 High.
#[test]
fn test_unchecked_arithmetic_flagged_high() {
    let findings = findings_for_source("pub fn add(a: i128, b: i128) -> i128 { a + b }");
    assert!(
        has_rule(&findings, "O-01"),
        "expected O-01, got: {findings:?}"
    );
    let o01 = rule(&findings, "O-01");
    assert_eq!(o01.severity, Severity::High);
    assert!(o01.suggestion.contains("checked_add"));
}

// 2. Checked arithmetic → not flagged.
#[test]
fn test_checked_arithmetic_not_flagged() {
    let findings =
        findings_for_source("pub fn add(a: i128, b: i128) -> i128 { a.checked_add(b).unwrap() }");
    assert!(
        !has_rule(&findings, "O-01"),
        "checked_add must not trigger O-01, got: {findings:?}"
    );
}

// 3. Division by a variable → O-03 Medium.
#[test]
fn test_division_by_variable_flagged() {
    let findings = findings_for_source("pub fn div(a: i128, b: i128) -> i128 { a / b }");
    assert!(
        has_rule(&findings, "O-03"),
        "expected O-03, got: {findings:?}"
    );
    assert_eq!(rule(&findings, "O-03").severity, Severity::Medium);
}

// 4. Division by a nonzero literal → not flagged.
#[test]
fn test_division_by_literal_not_flagged() {
    let findings = findings_for_source("pub fn div(a: i128) -> i128 { a / 100 }");
    assert!(
        !has_rule(&findings, "O-03"),
        "division by a nonzero literal must not trigger O-03, got: {findings:?}"
    );
}

// 5. Loop accumulation over a dynamic bound → O-04 High.
#[test]
fn test_loop_accumulation_flagged_high() {
    let findings = findings_for_source(
        "pub fn sum(count: u32, item: i128) -> i128 { \
            let mut total: i128 = 0; \
            for _ in 0..count { total += item; } \
            total \
        }",
    );
    assert!(
        has_rule(&findings, "O-04"),
        "expected O-04, got: {findings:?}"
    );
    assert_eq!(rule(&findings, "O-04").severity, Severity::High);
}

// A small constant-bounded loop is NOT flagged as O-04.
#[test]
fn test_small_constant_loop_not_o04() {
    let findings = findings_for_source(
        "pub fn sum(item: i128) -> i128 { \
            let mut total: i128 = 0; \
            for _ in 0..10 { total += item; } \
            total \
        }",
    );
    assert!(
        !has_rule(&findings, "O-04"),
        "a 0..10 loop must not trigger O-04, got: {findings:?}"
    );
}

// 6. Truncating cast from i128 → O-05 Low.
#[test]
fn test_cast_truncation_flagged_low() {
    let findings = findings_for_source("pub fn shrink(amount: i128) -> u32 { amount as u32 }");
    assert!(
        has_rule(&findings, "O-05"),
        "expected O-05, got: {findings:?}"
    );
    let o05 = rule(&findings, "O-05");
    assert_eq!(o05.severity, Severity::Low);
    assert!(o05.message.contains("u32"));
}

// A cast on a non-financial value is not flagged (avoids noise).
#[test]
fn test_cast_on_non_financial_not_flagged() {
    let findings = findings_for_source("pub fn shrink(n: u64) -> u32 { n as u32 }");
    assert!(
        !has_rule(&findings, "O-05"),
        "cast on a non-financial value must not trigger O-05, got: {findings:?}"
    );
}

// O-02: arithmetic compared against a threshold is Medium, not O-01 High.
#[test]
fn test_arithmetic_compared_is_o02_not_o01() {
    let findings =
        findings_for_source("pub fn check(a: i128, b: i128, max: i128) -> bool { a + b > max }");
    assert!(
        has_rule(&findings, "O-02"),
        "expected O-02, got: {findings:?}"
    );
    assert_eq!(rule(&findings, "O-02").severity, Severity::Medium);
    assert!(
        !has_rule(&findings, "O-01"),
        "compared arithmetic must not also fire O-01, got: {findings:?}"
    );
}

// A manual unit counter `i += 1` is demoted to Medium under O-01.
#[test]
fn test_unit_counter_demoted_to_medium() {
    let findings = findings_for_source("pub fn count(mut i: i128) -> i128 { i += 1; i }");
    let o01 = rule(&findings, "O-01");
    assert_eq!(o01.severity, Severity::Medium);
}

// Non-financial arithmetic (u32 params) is not flagged by O-01.
#[test]
fn test_non_financial_arithmetic_not_flagged() {
    let findings = findings_for_source("pub fn add(a: u32, b: u32) -> u32 { a + b }");
    assert!(
        !has_rule(&findings, "O-01"),
        "u32 arithmetic must not trigger O-01, got: {findings:?}"
    );
}

#[test]
fn test_vulnerable_fixture_triggers_multiple_rules() {
    let findings = findings_for_file("tests/fixtures/overflow_vulnerable.rs");
    assert!(has_rule(&findings, "O-01"), "got: {findings:?}");
    assert!(has_rule(&findings, "O-03"), "got: {findings:?}");
    assert!(has_rule(&findings, "O-04"), "got: {findings:?}");
    assert!(has_rule(&findings, "O-05"), "got: {findings:?}");
}

#[test]
fn test_engine_registers_overflow_checker() {
    let engine = AnalysisEngine::with_default_rules();
    // Reentrancy + overflow registered.
    assert!(engine.rule_count() >= 2);

    let contract = ContractParser::new()
        .parse_file("tests/fixtures/overflow_vulnerable.rs")
        .expect("parse");
    let findings = engine.run(&contract);
    assert!(has_rule(&findings, "O-01"), "engine should surface O-01");
}

#[test]
fn test_detector_metadata() {
    let d = OverflowChecker;
    assert_eq!(d.id(), "overflow");
    assert!(!d.name().is_empty());
    assert!(!d.description().is_empty());
}
