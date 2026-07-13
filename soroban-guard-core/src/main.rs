use clap::Parser;
use std::path::PathBuf;

use soroban_guard_core::analysis::AnalysisRunner;
use soroban_guard_core::config::{Config, OutputFormat, SeverityLevel};
use soroban_guard_core::error::Result;

#[derive(Parser)]
#[command(
    name = "soroban-guard-core",
    about = "Static analysis and security auditing toolchain for Soroban smart contracts",
    version
)]
struct Cli {
    /// Path to the Soroban contract(s) to analyze
    path: Vec<String>,

    /// Output format: human, json, sarif
    #[arg(short, long, default_value = "human")]
    format: OutputFormat,

    /// Minimum severity threshold (warn, error)
    #[arg(short, long, default_value = "warn")]
    severity: SeverityLevel,

    /// Output file path (stdout if not set)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Exclude patterns (comma-separated globs)
    #[arg(long)]
    exclude: Option<String>,

    /// Maximum number of parallel workers
    #[arg(long, default_value = "4")]
    jobs: usize,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let config = Config {
        paths: cli.path,
        format: cli.format,
        severity: cli.severity,
        output: cli.output,
        exclude: cli.exclude,
        jobs: cli.jobs,
    };

    let runner = AnalysisRunner::new(config);
    let reports = runner.run()?;

    for report in &reports {
        println!("{}", report.summary);
        println!();
    }

    Ok(())
}
