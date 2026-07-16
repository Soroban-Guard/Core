use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use clap::Parser;

use soroban_guard_core::analysis::AnalysisEngine;
use soroban_guard_core::config::{ConfigFile, MinSeverity, OutputFormat, RuleOverride};
use soroban_guard_core::error::Result;
use soroban_guard_core::parser::ContractParser;
use soroban_guard_core::report::output::{
    discover_contracts, filter_by_severity, format_human, format_json, format_sarif,
    ConsolidatedReport,
};
use soroban_guard_core::report::Report;

#[derive(Parser)]
#[command(
    name = "soroban-guard",
    about = "Static analysis for Soroban smart contracts",
    version
)]
struct Cli {
    /// Path(s) to Soroban contract source files or directories
    path: Vec<String>,

    /// Output format
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Human)]
    format: OutputFormat,

    /// Minimum severity to report
    #[arg(short = 'm', long, value_enum, default_value_t = MinSeverity::Low)]
    min_severity: MinSeverity,

    /// Output file (stdout if not specified)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Exclude patterns (comma-separated globs)
    #[arg(long)]
    exclude: Option<String>,

    /// Number of parallel workers
    #[arg(long, default_value_t = 4)]
    jobs: usize,

    /// Enable all rules
    #[arg(long, default_value_t = true)]
    all: bool,

    /// Specific rules to run (comma-separated rule IDs)
    #[arg(long)]
    rules: Option<String>,

    /// Generate SARIF output for GitHub code scanning
    #[arg(long)]
    sarif: bool,

    /// Config file path
    #[arg(long)]
    config: Option<PathBuf>,
}

/// Returns `Some(ids)` when rule selection is explicitly specified,
/// or `None` to indicate "all rules" (the default fallback).
fn resolve_rule_ids(cli: &Cli, cfg: Option<&ConfigFile>) -> Option<Vec<&'static str>> {
    if let Some(rules_str) = &cli.rules {
        let ids: Vec<_> = rules_str.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
        return Some(ids);
    }
    if !cli.all {
        return Some(Vec::new());
    }
    if let Some(cfg) = cfg {
        let ids = cfg.rules.enabled_rule_ids();
        return Some(ids);
    }
    None
}

fn build_severity_overrides(cfg: Option<&ConfigFile>) -> Vec<(&'static str, &'_ RuleOverride)> {
    let Some(cfg) = cfg else { return Vec::new() };
    let mut overrides = Vec::new();
    if cfg.rules.reentrancy.severity.is_some() {
        overrides.push(("R-", &cfg.rules.reentrancy));
    }
    if cfg.rules.overflow.severity.is_some() {
        overrides.push(("O-", &cfg.rules.overflow));
    }
    if cfg.rules.access_control.severity.is_some() {
        overrides.push(("A-", &cfg.rules.access_control));
    }
    if cfg.rules.storage.severity.is_some() {
        overrides.push(("S-", &cfg.rules.storage));
    }
    overrides
}

fn main() -> Result<()> {
    let mut cli = Cli::parse();

    // Load config file if specified
    let cfg = cli.config.as_ref().map(|p| ConfigFile::from_file(p)).transpose()?;
    if let Some(ref cfg) = cfg {
        if let Some(ref fmt) = cfg.output.format {
            cli.format = fmt.clone();
        }
        if let Some(ref ms) = cfg.output.min_severity {
            cli.min_severity = ms.clone();
        }
        if cli.exclude.is_none() && !cfg.general.exclude.is_empty() {
            cli.exclude = Some(cfg.general.exclude.join(","));
        }
        if let Some(jobs) = cfg.general.jobs {
            cli.jobs = jobs;
        }
    }

    // SARIF flag overrides format
    let format = if cli.sarif {
        OutputFormat::Sarif
    } else {
        cli.format
    };

    // Discover contract files
    let files = discover_contracts(&cli.path, cli.exclude.as_deref())?;
    if files.is_empty() {
        eprintln!("No Soroban contract files found");
        return Ok(());
    }

    // Resolve which rules to run
    let engine = match resolve_rule_ids(&cli, cfg.as_ref()) {
        Some(ids) => {
            if ids.is_empty() {
                AnalysisEngine::new()
            } else {
                AnalysisEngine::with_rules(&ids)
            }
        }
        None => AnalysisEngine::with_default_rules(),
    };

    // Build severity overrides from config
    let severity_overrides = build_severity_overrides(cfg.as_ref());

    // Parse and analyze contracts (parallel with --jobs)
    let parser = ContractParser::new();
    let files = Arc::new(files);
    let reports = Arc::new(Mutex::new(Vec::new()));
    let engine_ref = &engine;
    let parser_ref = &parser;
    let severity_overrides_ref = &severity_overrides;

    let worker_count = cli.jobs.max(1);
    std::thread::scope(|s| {
        for worker_id in 0..worker_count {
            let files = Arc::clone(&files);
            let reports = Arc::clone(&reports);
            s.spawn(move || {
                let mut local = Vec::new();
                // Round-robin file distribution
                for i in (worker_id..files.len()).step_by(worker_count) {
                    let file = &files[i];
                    let source = match std::fs::read_to_string(file) {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    if let Ok(contract) = parser_ref.parse_source(&source) {
                        let mut report = engine_ref.analyze_contract(
                            &contract,
                            &file.to_string_lossy(),
                        );
                        // Apply severity overrides and recalculate score
                        if !severity_overrides_ref.is_empty() {
                            AnalysisEngine::apply_overrides(
                                severity_overrides_ref,
                                &mut report.findings,
                            );
                            let score = soroban_guard_core::scoring::calculate_score(&report.findings);
                            report.score = score;
                            report.summary = soroban_guard_core::scoring::generate_summary(&score);
                        }
                        local.push(report);
                    }
                }
                reports.lock().unwrap().extend(local);
            });
        }
    });

    let mut reports = reports.into_inner().unwrap();
    if reports.is_empty() {
        eprintln!("No Soroban contracts found in the specified files");
        return Ok(());
    }

    // Sort reports by file name for deterministic output
    reports.sort_by(|a, b| a.source_file.cmp(&b.source_file));

    // Build consolidated report
    let mut consolidated = ConsolidatedReport::new(&reports);

    // Filter by minimum severity
    if cli.min_severity != MinSeverity::Info {
        let min_sev = cli.min_severity.to_severity();
        for entry in &mut consolidated.reports {
            entry.findings = filter_by_severity(&entry.findings, &min_sev);
        }
        consolidated.all_findings = filter_by_severity(&consolidated.all_findings, &min_sev);
    }

    // Generate output
    let output: String = match format {
        OutputFormat::Human => format_human(&consolidated),
        OutputFormat::Json => format_json(&consolidated)?,
        OutputFormat::Sarif => format_sarif(&consolidated)?,
    };

    // Write output
    match cli.output {
        Some(path) => std::fs::write(path, output)?,
        None => println!("{}", output),
    }

    // Exit with non-zero if critical/high findings exist
    if consolidated.total_score.breakdown.critical > 0
        || consolidated.total_score.breakdown.high > 0
    {
        std::process::exit(1);
    }

    Ok(())
}
