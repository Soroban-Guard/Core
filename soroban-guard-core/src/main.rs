use std::path::PathBuf;

use clap::Parser;

use soroban_guard_core::analysis::AnalysisEngine;
use soroban_guard_core::config::{ConfigFile, MinSeverity, OutputFormat};
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

fn main() -> Result<()> {
    let mut cli = Cli::parse();

    // Load config file if specified
    if let Some(config_path) = &cli.config {
        let cfg = ConfigFile::from_file(config_path)?;
        if let Some(ref fmt) = cfg.output.format {
            cli.format = fmt.clone();
        }
        if let Some(ref ms) = cfg.output.min_severity {
            cli.min_severity = ms.clone();
        }
        if let Some(jobs) = cfg.general.jobs {
            cli.jobs = jobs;
        }
        if cli.exclude.is_none() && !cfg.general.exclude.is_empty() {
            cli.exclude = Some(cfg.general.exclude.join(","));
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

    // Initialize analysis engine
    let engine = AnalysisEngine::with_default_rules();

    // Parse and analyze each contract
    let parser = ContractParser::new();
    let mut reports: Vec<Report> = Vec::new();

    for file in &files {
        let source = std::fs::read_to_string(file)?;
        if let Ok(contract) = parser.parse_source(&source) {
            let report = engine.analyze_contract(&contract, &file.to_string_lossy());
            reports.push(report);
        }
    }

    if reports.is_empty() {
        eprintln!("No Soroban contracts found in the specified files");
        return Ok(());
    }

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
