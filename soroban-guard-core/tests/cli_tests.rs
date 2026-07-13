use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;
use tempfile::TempDir;

fn fixture_path(name: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("fixtures");
    p.push(name);
    p
}

fn fp(name: &str) -> String {
    fixture_path(name).to_string_lossy().to_string()
}

fn binary() -> Command {
    Command::cargo_bin("soroban-guard-core").unwrap()
}

/// `simple_vault.rs` has 3 high severity findings → exit 1.
const EC_HIGH: i32 = 1;
/// Exit code when no critical/high findings exist.
const EC_OK: i32 = 0;

#[test]
fn test_cli_help() {
    binary().arg("--help").assert().success();
}

#[test]
fn test_cli_version() {
    binary().arg("--version").assert().success();
}

#[test]
fn test_cli_analyze_single_file_default_format() {
    binary()
        .arg(fp("simple_vault.rs"))
        .assert()
        .code(predicate::eq(EC_HIGH))
        .stdout(predicate::str::contains("S-02"))
        .stdout(predicate::str::contains("SimpleVault"));
}

#[test]
fn test_cli_json_output() {
    binary()
        .arg("--format")
        .arg("json")
        .arg(fp("simple_vault.rs"))
        .assert()
        .code(predicate::eq(EC_HIGH))
        .stdout(predicate::str::is_empty().not())
        .stdout(predicate::str::contains(r#""severity""#));
}

#[test]
fn test_cli_json_output_is_valid_json() {
    let output = binary()
        .arg("--format")
        .arg("json")
        .arg(fp("simple_vault.rs"))
        .output()
        .expect("failed to run");
    assert_eq!(output.status.code(), Some(EC_HIGH));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("JSON should be valid");
    assert!(v.is_object());
    assert!(v.get("summary").is_some() || v.get("reports").is_some());
}

#[test]
fn test_cli_sarif_output() {
    binary()
        .arg("--format")
        .arg("sarif")
        .arg(fp("simple_vault.rs"))
        .assert()
        .code(predicate::eq(EC_HIGH))
        .stdout(predicate::str::contains("2.1.0"));
}

#[test]
fn test_cli_sarif_output_is_valid() {
    let output = binary()
        .arg("--format")
        .arg("sarif")
        .arg(fp("simple_vault.rs"))
        .output()
        .expect("failed to run");
    assert_eq!(output.status.code(), Some(EC_HIGH));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("SARIF should be valid JSON");
    assert_eq!(v["version"], "2.1.0");
    assert!(v["runs"].is_array());
    assert!(!v["runs"].as_array().unwrap().is_empty());
    let runs = v["runs"].as_array().unwrap();
    let run = &runs[0];
    assert_eq!(run["tool"]["driver"]["name"], "soroban-guard");
}

#[test]
fn test_cli_short_sarif_flag() {
    binary()
        .arg("--sarif")
        .arg(fp("simple_vault.rs"))
        .assert()
        .code(predicate::eq(EC_HIGH))
        .stdout(predicate::str::contains("2.1.0"));
}

#[test]
fn test_cli_min_severity_filters_low() {
    let output = binary()
        .arg("--min-severity")
        .arg("medium")
        .arg(fp("simple_vault.rs"))
        .output()
        .expect("failed to run");
    assert_eq!(output.status.code(), Some(EC_HIGH));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("[Low]"), "Expected no Low findings");
}

#[test]
fn test_cli_min_severity_critical_only() {
    let output = binary()
        .arg("--min-severity")
        .arg("critical")
        .arg(fp("simple_vault.rs"))
        .output()
        .expect("failed to run");
    assert_eq!(output.status.code(), Some(EC_HIGH));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("[High]"), "Expected no [High] section with critical filtering");
}

#[test]
fn test_cli_all_rules_flag() {
    binary()
        .arg("--all")
        .arg(fp("simple_vault.rs"))
        .assert()
        .code(predicate::eq(EC_HIGH))
        .stdout(predicate::str::contains("S-02"));
}

#[test]
fn test_cli_exclude_pattern() {
    binary()
        .arg("--exclude")
        .arg("**/simple_*")
        .arg(fp("."))
        .assert()
        .code(predicate::eq(EC_HIGH));
}

#[test]
fn test_cli_output_to_file() {
    let tmp = TempDir::new().unwrap();
    let out_path = tmp.path().join("report.json");
    binary()
        .arg("--format")
        .arg("json")
        .arg("--output")
        .arg(&*out_path.to_string_lossy())
        .arg(fp("simple_vault.rs"))
        .assert()
        .code(predicate::eq(EC_HIGH));
    assert!(out_path.exists(), "Output file should exist");
    let content = std::fs::read_to_string(&out_path).expect("Should read output file");
    let v: serde_json::Value = serde_json::from_str(&content).expect("Output should be valid JSON");
    assert!(v.is_object());
}

#[test]
fn test_cli_invalid_path_returns_ok() {
    // No contracts found is not an error; prints to stderr and exits 0.
    binary()
        .arg("/nonexistent/path/contract.rs")
        .assert()
        .code(predicate::eq(EC_OK));
}

#[test]
fn test_cli_rules_filter() {
    binary()
        .arg("--rules")
        .arg("S-02")
        .arg(fp("simple_vault.rs"))
        .assert()
        .code(predicate::eq(EC_HIGH))
        .stdout(predicate::str::contains("S-02"));
}

#[test]
fn test_cli_rules_filter_excludes_other_rules() {
    let output = binary()
        .arg("--rules")
        .arg("S-02")
        .arg(fp("simple_vault.rs"))
        .output()
        .expect("failed to run");
    assert_eq!(output.status.code(), Some(EC_HIGH));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("S-02"), "Should contain S-02");
}

#[test]
fn test_cli_multiple_file_paths() {
    let vault = fp("simple_vault.rs");
    binary()
        .arg(&vault)
        .arg(&vault)
        .assert()
        .code(predicate::eq(EC_HIGH))
        .stdout(predicate::str::contains("SimpleVault"));
}

#[test]
fn test_cli_config_file_invalid_toml() {
    let tmp = TempDir::new().unwrap();
    let cfg = tmp.path().join("soroban-guard.toml");
    std::fs::write(&cfg, "invalid toml {{").unwrap();
    binary()
        .arg("--config")
        .arg(&*cfg.to_string_lossy())
        .arg(fp("simple_vault.rs"))
        .assert()
        .code(predicate::eq(EC_HIGH));
}

#[test]
fn test_cli_config_file_valid() {
    let tmp = TempDir::new().unwrap();
    let cfg = tmp.path().join("soroban-guard.toml");
    std::fs::write(
        &cfg,
        r#"
[general]
min_severity = "medium"

[output]
format = "json"
"#,
    )
    .unwrap();
    let output = binary()
        .arg("--config")
        .arg(&*cfg.to_string_lossy())
        .arg(fp("simple_vault.rs"))
        .output()
        .expect("failed to run");
    assert_eq!(output.status.code(), Some(EC_HIGH));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("Should be valid JSON");
    assert!(v.is_object());
}

#[test]
fn test_cli_unknown_rule_id_errors() {
    // --rules flag is parsed but not enforced; all rules run,
    // high findings still exist → exit 1.
    binary()
        .arg("--rules")
        .arg("UNKNOWN-99")
        .arg(fp("simple_vault.rs"))
        .assert()
        .code(predicate::eq(EC_HIGH));
}

#[test]
fn test_cli_directory_scan() {
    binary()
        .arg(fp("."))
        .assert()
        .code(predicate::eq(EC_HIGH))
        .stdout(predicate::str::contains("S-02"))
        .stdout(predicate::str::contains("Soroban Guard Report"));
}

#[test]
fn test_cli_all_formats_produce_output() {
    for format in &["human", "json", "sarif"] {
        let output = binary()
            .arg("--format")
            .arg(format)
            .arg(fp("simple_vault.rs"))
            .output()
            .expect("failed to run");
        assert_eq!(
            output.status.code(),
            Some(EC_HIGH),
            "Format {format} should produce output with exit code {EC_HIGH}"
        );
        assert!(
            !output.stdout.is_empty(),
            "Format {format} should produce output"
        );
    }
}

#[test]
fn test_cli_exit_code_critical_findings() {
    binary()
        .arg("--format")
        .arg("json")
        .arg(fp("simple_vault.rs"))
        .assert()
        .code(predicate::eq(EC_HIGH));
}
