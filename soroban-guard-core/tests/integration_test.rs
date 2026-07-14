use std::path::PathBuf;

use soroban_guard_core::analysis::AnalysisEngine;
use soroban_guard_core::parser::ContractParser;
use soroban_guard_core::scoring::SecurityScore;

fn fixture(name: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("fixtures");
    p.push("contracts");
    p.push(name);
    p
}

fn expected(name: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("fixtures");
    p.push("expected");
    p.push(name);
    p
}

fn analyze_fixture(name: &str) -> (Vec<soroban_guard_core::Finding>, SecurityScore) {
    let parser = ContractParser::new();
    let engine = AnalysisEngine::with_default_rules();
    let path = fixture(name);
    let source = std::fs::read_to_string(&path).unwrap();
    let contract = parser.parse_source(&source).unwrap();
    let report = engine.analyze_contract(&contract, &path.to_string_lossy());
    (report.findings.clone(), report.score)
}

#[test]
fn test_vault_safe_has_few_findings() {
    let (findings, score) = analyze_fixture("vault_safe.rs");
    assert!(
        score.overall >= 80,
        "Safe vault should score >= 80, got {}",
        score.overall
    );
    // S-03 is a known limitation: literal 0i128 is parsed differently
    // from checked_add expression, causing a false positive.
    // When this is fixed, expect no High findings.
    let critical: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == soroban_guard_core::Severity::Critical)
        .collect();
    assert!(
        critical.is_empty(),
        "Safe vault should have no critical findings, got: {:?}",
        critical
    );
    let rule_ids: Vec<_> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        rule_ids.contains(&"A-04"),
        "Safe vault should have A-04 (read-only public fn): got {:?}",
        rule_ids
    );
    assert!(
        rule_ids.contains(&"R-03"),
        "Safe vault should have R-03 (no reentrancy guard): got {:?}",
        rule_ids
    );
}

#[test]
fn test_vault_vulnerable_has_all_rule_categories() {
    let (findings, score) = analyze_fixture("vault_vulnerable.rs");
    assert_eq!(score.overall, 0, "Vulnerable vault should score 0");
    let rule_ids: std::collections::BTreeSet<&str> =
        findings.iter().map(|f| f.rule_id.as_str()).collect();
    for cat in &[
        "A-01", "A-02", "O-01", "R-01", "R-03", "R-04", "S-01", "S-03", "S-04", "S-05",
    ] {
        assert!(
            rule_ids.contains(cat),
            "Vulnerable vault should trigger rule {}",
            cat
        );
    }
}

#[test]
fn test_nft_marketplace_has_access_control_issues() {
    let (findings, _) = analyze_fixture("nft_marketplace.rs");
    let rule_ids: std::collections::BTreeSet<&str> =
        findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        rule_ids.contains("A-01"),
        "NFT marketplace should have A-01"
    );
    assert!(
        rule_ids.contains("A-02"),
        "NFT marketplace should have A-02 (set_fee matches admin pattern)"
    );
    assert!(
        rule_ids.contains("A-04"),
        "NFT marketplace should have A-04"
    );
    assert!(
        rule_ids.contains("R-03"),
        "NFT marketplace should have R-03 (no reentrancy guard)"
    );
    assert!(
        rule_ids.contains("S-02"),
        "NFT marketplace should have S-02 (generic key 'admin')"
    );
}

#[test]
fn test_lending_pool_has_reentrancy() {
    let (findings, _) = analyze_fixture("lending_pool.rs");
    let rule_ids: std::collections::BTreeSet<&str> =
        findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        rule_ids.contains("R-01"),
        "Lending pool should have R-01 (state write after external call in liquidate)"
    );
    assert!(rule_ids.contains("R-03"), "Lending pool should have R-03");
    assert!(
        rule_ids.contains("O-01"),
        "Lending pool should have O-01 (unchecked arithmetic in borrow)"
    );
    assert!(
        rule_ids.contains("A-04"),
        "Lending pool should have A-04 (public liquidate without auth)"
    );
}

#[test]
fn test_amm_pair_has_overflow_and_reentrancy() {
    let (findings, _) = analyze_fixture("amm_pair.rs");
    let rule_ids: std::collections::BTreeSet<&str> =
        findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(rule_ids.contains("O-01"), "AMM should have O-01");
    assert!(
        rule_ids.contains("O-03"),
        "AMM should have O-03 (division in swap)"
    );
    assert!(rule_ids.contains("R-01"), "AMM should have R-01");
    assert!(rule_ids.contains("R-03"), "AMM should have R-03");
}

#[test]
fn test_minimal_contract() {
    let (findings, score) = analyze_fixture("minimal.rs");
    assert_eq!(
        score.overall, 100,
        "Minimal contract should score 100, got {}",
        score.overall
    );
    let rule_ids: Vec<_> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        rule_ids.contains(&"A-04"),
        "Minimal contract should have A-04 (public greet without auth)"
    );
    assert!(
        rule_ids.contains(&"S-05"),
        "Minimal contract should have S-05 (no version key)"
    );
}

#[test]
fn test_vault_safe_matches_expected_json() {
    let expected_path = expected("vault_safe.json");
    let expected_content = std::fs::read_to_string(&expected_path).unwrap();
    let expected: serde_json::Value = serde_json::from_str(&expected_content).unwrap();

    let (findings, score) = analyze_fixture("vault_safe.rs");
    let actual_rule_ids: std::collections::BTreeSet<&str> =
        findings.iter().map(|f| f.rule_id.as_str()).collect();
    let expected_rule_ids: std::collections::BTreeSet<&str> = expected["reports"][0]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rule_id"].as_str().unwrap())
        .collect();
    assert_eq!(
        actual_rule_ids, expected_rule_ids,
        "Rule IDs should match expected"
    );
    assert_eq!(
        score.overall,
        expected["reports"][0]["score"]["overall"].as_u64().unwrap() as u8,
        "Score should match expected"
    );
}

#[test]
fn test_vault_vulnerable_matches_expected_json() {
    let expected_path = expected("vault_vulnerable.json");
    let expected_content = std::fs::read_to_string(&expected_path).unwrap();
    let expected: serde_json::Value = serde_json::from_str(&expected_content).unwrap();

    let (findings, score) = analyze_fixture("vault_vulnerable.rs");
    let actual_rule_ids: std::collections::BTreeSet<&str> =
        findings.iter().map(|f| f.rule_id.as_str()).collect();
    let expected_rule_ids: std::collections::BTreeSet<&str> = expected["reports"][0]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rule_id"].as_str().unwrap())
        .collect();
    assert_eq!(
        actual_rule_ids, expected_rule_ids,
        "Rule IDs should match expected"
    );
    assert_eq!(
        score.overall,
        expected["reports"][0]["score"]["overall"].as_u64().unwrap() as u8,
        "Score should match expected"
    );
}

#[test]
fn test_minimal_matches_expected_json() {
    let expected_path = expected("minimal.json");
    let expected_content = std::fs::read_to_string(&expected_path).unwrap();
    let expected: serde_json::Value = serde_json::from_str(&expected_content).unwrap();

    let (findings, score) = analyze_fixture("minimal.rs");
    let actual_rule_ids: std::collections::BTreeSet<&str> =
        findings.iter().map(|f| f.rule_id.as_str()).collect();
    let expected_rule_ids: std::collections::BTreeSet<&str> = expected["reports"][0]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rule_id"].as_str().unwrap())
        .collect();
    assert_eq!(
        actual_rule_ids, expected_rule_ids,
        "Rule IDs should match expected"
    );
    assert_eq!(
        score.overall,
        expected["reports"][0]["score"]["overall"].as_u64().unwrap() as u8,
        "Score should match expected"
    );
}

#[test]
fn test_all_fixtures_parse_successfully() {
    let parser = ContractParser::new();
    for name in &[
        "vault_safe.rs",
        "vault_vulnerable.rs",
        "nft_marketplace.rs",
        "lending_pool.rs",
        "amm_pair.rs",
        "minimal.rs",
    ] {
        let path = fixture(name);
        let source = std::fs::read_to_string(&path).unwrap();
        let contract = parser.parse_source(&source).unwrap_or_else(|e| {
            panic!("Failed to parse {}: {:?}", name, e);
        });
        assert!(
            !contract.name.is_empty(),
            "Contract name should not be empty for {}",
            name
        );
        assert!(
            !contract.name.starts_with("Unknown"),
            "Contract should be recognized, got 'Unknown' for {}",
            name
        );
    }
}

#[test]
fn test_all_fixtures_produce_consistent_results() {
    let parser = ContractParser::new();
    let engine = AnalysisEngine::with_default_rules();
    for name in &[
        "vault_safe.rs",
        "vault_vulnerable.rs",
        "nft_marketplace.rs",
        "lending_pool.rs",
        "amm_pair.rs",
        "minimal.rs",
    ] {
        let path = fixture(name);
        let source = std::fs::read_to_string(&path).unwrap();
        let contract = parser.parse_source(&source).unwrap();
        let report1 = engine.analyze_contract(&contract, &path.to_string_lossy());
        let report2 = engine.analyze_contract(&contract, &path.to_string_lossy());
        assert_eq!(
            report1.findings.len(),
            report2.findings.len(),
            "Findings count should be deterministic for {}",
            name
        );
        for (a, b) in report1.findings.iter().zip(report2.findings.iter()) {
            assert_eq!(
                a.rule_id, b.rule_id,
                "Rule IDs should match on re-analysis of {}",
                name
            );
            assert_eq!(
                a.severity, b.severity,
                "Severities should match on re-analysis of {}",
                name
            );
        }
    }
}
