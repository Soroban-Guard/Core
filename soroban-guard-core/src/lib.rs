pub mod analysis;
pub mod config;
pub mod error;
pub mod parser;
pub mod report;
pub mod scoring;

pub use analysis::AnalysisEngine;
pub use config::{ConfigFile, MinSeverity, OutputFormat};
pub use error::{Result, SorobanGuardError};
pub use parser::ContractParser;
pub use report::output::{discover_contracts, format_human, ConsolidatedReport};
pub use report::{finding::Finding, severity::Severity, Report};
pub use scoring::{SecurityScore, SeverityBreakdown};
