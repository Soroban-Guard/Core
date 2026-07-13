use std::path::Path;

use colored::Colorize;
use serde::Serialize;
use walkdir::WalkDir;

use super::finding::Finding;
use super::severity::Severity;
use crate::scoring::{generate_summary, SecurityScore};

#[derive(Debug, Clone, Serialize)]
pub struct ConsolidatedReport {
    pub tool: String,
    pub version: String,
    pub reports: Vec<ReportEntry>,
    pub total_score: SecurityScore,
    pub all_findings: Vec<Finding>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportEntry {
    pub contract: String,
    pub file: String,
    pub score: SecurityScore,
    pub findings: Vec<Finding>,
}

impl ConsolidatedReport {
    pub fn new(reports: &[crate::report::Report]) -> Self {
        let all_findings: Vec<Finding> = reports.iter().flat_map(|r| r.findings.clone()).collect();
        let total_score = crate::scoring::calculate_score(&all_findings);
        let summary = generate_summary(&total_score);

        let entries: Vec<ReportEntry> = reports
            .iter()
            .map(|r| ReportEntry {
                contract: r.contract_name.clone(),
                file: r.source_file.clone(),
                score: r.score.clone(),
                findings: r.findings.clone(),
            })
            .collect();

        ConsolidatedReport {
            tool: "soroban-guard".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            reports: entries,
            total_score,
            all_findings,
            summary,
        }
    }
}

pub fn format_human(consolidated: &ConsolidatedReport) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "{}\n{}\n\n",
        "Soroban Guard Report".bold().underline(),
        "====================".bold(),
    ));

    out.push_str(&format!("{}\n", consolidated.summary));
    out.push_str(&format!(
        "Total files analyzed: {}\n\n",
        consolidated.reports.len()
    ));

    for entry in &consolidated.reports {
        out.push_str(&format!("File: {}\n", entry.file.bold()));
        out.push_str(&format!(
            "Score: {}/100 (Grade {})\n\n",
            entry.score.overall, entry.score.grade
        ));

        let severity_order = [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ];

        for severity in &severity_order {
            let sev_findings: Vec<&Finding> = entry
                .findings
                .iter()
                .filter(|f| f.severity == *severity)
                .collect();

            if sev_findings.is_empty() {
                continue;
            }

            let label = match severity {
                Severity::Critical => "CRITICAL".red().bold(),
                Severity::High => "HIGH".red(),
                Severity::Medium => "MEDIUM".yellow(),
                Severity::Low => "LOW".normal(),
                Severity::Info => "INFO".cyan(),
            };

            out.push_str(&format!("{}:\n", label));
            for f in &sev_findings {
                out.push_str(&format!(
                    "  [{}] {}\n     Location: {}\n     Suggestion: {}\n\n",
                    f.rule_id.bold(),
                    f.message,
                    f.location,
                    f.suggestion,
                ));
            }
        }
    }

    out
}

pub fn format_json(consolidated: &ConsolidatedReport) -> Result<String, crate::error::SorobanGuardError> {
    serde_json::to_string_pretty(consolidated)
        .map_err(|e| crate::error::SorobanGuardError::Report(e.to_string()))
}

fn sarif_severity(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
        Severity::Info => "none",
    }
}

pub fn format_sarif(consolidated: &ConsolidatedReport) -> Result<String, crate::error::SorobanGuardError> {
    let mut rules: Vec<SarifRule> = Vec::new();
    let mut results: Vec<SarifResult> = Vec::new();

    for entry in &consolidated.reports {
        for finding in &entry.findings {
            let rule_id = &finding.rule_id;
            if !rules.iter().any(|r| r.id == *rule_id) {
                rules.push(SarifRule {
                    id: rule_id.clone(),
                    name: format!("{}-{}", rule_id, finding.severity.as_str()),
                    short_description: SarifMessage {
                        text: finding.message.clone(),
                    },
                    full_description: SarifMessage {
                        text: finding.suggestion.clone(),
                    },
                    default_configuration: SarifConfiguration {
                        level: sarif_severity(&finding.severity).to_string(),
                    },
                    properties: Some(SarifProperties {
                        tags: vec![finding.severity.as_str().to_lowercase()],
                    }),
                });
            }

            let (line, col) = parse_location(&finding.location);
            results.push(SarifResult {
                rule_id: rule_id.clone(),
                rule_index: rules.len() as i64 - 1,
                level: sarif_severity(&finding.severity).to_string(),
                message: SarifMessage {
                    text: finding.message.clone(),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: entry.file.clone(),
                        },
                        region: SarifRegion {
                            start_line: line,
                            start_column: col,
                        },
                    },
                }],
                properties: None,
            });
        }
    }

    let sarif = SarifLog {
        version: "2.1.0".into(),
        schema: "$schema".into(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "soroban-guard".into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    information_uri: "https://github.com/Soroban-Guard/Core".into(),
                    rules,
                },
            },
            results,
            properties: None,
        }],
    };

    serde_json::to_string_pretty(&sarif)
        .map_err(|e| crate::error::SorobanGuardError::Report(e.to_string()))
}

fn parse_location(location: &str) -> (i64, i64) {
    // format: "ContractName:line:col" or just "ContractName"
    let parts: Vec<&str> = location.split(':').collect();
    if parts.len() >= 3 {
        let line = parts[parts.len() - 2].parse::<i64>().unwrap_or(0);
        let col = parts[parts.len() - 1].parse::<i64>().unwrap_or(0);
        (line, col)
    } else {
        (0, 0)
    }
}

// SARIF data structures
#[derive(Serialize)]
struct SarifLog {
    version: String,
    #[serde(rename = "$schema")]
    schema: String,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<SarifProperties>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
struct SarifDriver {
    name: String,
    version: String,
    information_uri: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
struct SarifRule {
    id: String,
    name: String,
    short_description: SarifMessage,
    full_description: SarifMessage,
    default_configuration: SarifConfiguration,
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<SarifProperties>,
}

#[derive(Serialize)]
struct SarifConfiguration {
    level: String,
}

#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
struct SarifResult {
    rule_id: String,
    rule_index: i64,
    level: String,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<SarifProperties>,
}

#[derive(Serialize)]
struct SarifLocation {
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
struct SarifPhysicalLocation {
    artifact_location: SarifArtifactLocation,
    region: SarifRegion,
}

#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
struct SarifRegion {
    start_line: i64,
    start_column: i64,
}

#[derive(Serialize)]
struct SarifProperties {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tags: Vec<String>,
}

/// Discover contract files from the given paths, excluding those matching
/// comma-separated glob patterns.
pub fn discover_contracts(
    paths: &[String],
    exclude: Option<&str>,
) -> Result<Vec<std::path::PathBuf>, crate::error::SorobanGuardError> {
    let exclude_patterns: Vec<glob::Pattern> = exclude
        .map(|e| {
            e.split(',')
                .filter_map(|p| glob::Pattern::new(p.trim()).ok())
                .collect()
        })
        .unwrap_or_default();

    let mut files = Vec::new();
    for path_str in paths {
        let p = Path::new(path_str);
        if p.is_dir() {
            for entry in WalkDir::new(p)
                .into_iter()
                .filter_entry(|e| !is_hidden(e))
                .filter_map(|e| e.ok())
            {
                if entry.path().extension().map_or(false, |e| e == "rs") {
                    let is_excluded = exclude_patterns
                        .iter()
                        .any(|pat| pat.matches_path(entry.path()));
                    if !is_excluded {
                        files.push(entry.path().to_path_buf());
                    }
                }
            }
        } else if p.is_file() {
            files.push(p.to_path_buf());
        }
    }
    Ok(files)
}

fn is_hidden(entry: &walkdir::DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .map(|s| s.starts_with('.'))
        .unwrap_or(false)
}

/// Filter findings by minimum severity level.
pub fn filter_by_severity(findings: &[Finding], min_severity: &Severity) -> Vec<Finding> {
    findings
        .iter()
        .filter(|f| f.severity >= *min_severity)
        .cloned()
        .collect()
}
