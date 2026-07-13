pub mod access_control;
pub mod overflow;
pub mod reentrancy;
pub mod storage;

use std::path::Path;

use walkdir::WalkDir;

use crate::config::Config;
use crate::error::Result;
use crate::parser::ast::Contract;
use crate::parser::ContractParser;
use crate::report::finding::Finding;
use crate::report::Report;
use crate::scoring::calculate_score;

pub trait Analyzer {
    fn analyze(&self, source: &str, file_path: &str) -> Vec<Finding>;
    fn name(&self) -> &'static str;
}

/// A structural analysis rule that operates on a fully parsed [`Contract`]
/// rather than raw source text. This is the interface detectors (like the
/// reentrancy detector) implement so they can reason over the parser's
/// `FnBodyAnalysis` — cross-contract calls, storage accesses, and their source
/// positions — instead of re-scanning the source.
pub trait AnalysisRule: Send + Sync {
    /// Stable identifier for the rule family (e.g. `"reentrancy"`).
    fn id(&self) -> &'static str;
    /// Human-readable name.
    fn name(&self) -> &'static str;
    /// One-line description of what the rule detects.
    fn description(&self) -> &'static str;
    /// Run the rule against a parsed contract, producing zero or more findings.
    fn analyze(&self, contract: &Contract) -> Vec<Finding>;
}

/// Registry of [`AnalysisRule`]s. Rules run in registration order and their
/// findings are concatenated. This is the `Contract`-level counterpart to the
/// source-level [`AnalysisRunner`] used by the CLI.
pub struct AnalysisEngine {
    rules: Vec<Box<dyn AnalysisRule>>,
}

impl AnalysisEngine {
    /// Create an empty engine with no rules registered.
    pub fn new() -> Self {
        AnalysisEngine { rules: Vec::new() }
    }

    /// Create an engine pre-populated with the default rule set. The reentrancy
    /// detector is registered first.
    pub fn with_default_rules() -> Self {
        let mut engine = Self::new();
        engine.register(Box::new(reentrancy::ReentrancyDetector));
        engine.register(Box::new(overflow::OverflowChecker));
        engine.register(Box::new(access_control::AccessControlDetector));
        engine.register(Box::new(storage::StorageCollisionDetector));
        engine
    }

    /// Register a rule. Rules execute in the order they are registered.
    pub fn register(&mut self, rule: Box<dyn AnalysisRule>) -> &mut Self {
        self.rules.push(rule);
        self
    }

    /// Run every registered rule against `contract`, returning all findings.
    pub fn run(&self, contract: &Contract) -> Vec<Finding> {
        let mut findings = Vec::new();
        for rule in &self.rules {
            findings.extend(rule.analyze(contract));
        }
        findings
    }

    /// Run every registered rule against `contract` and produce a scored Report.
    pub fn analyze_contract(&self, contract: &Contract, source_file: &str) -> Report {
        let findings = self.run(contract);
        let score = calculate_score(&findings);
        Report::new(&contract.name, source_file, findings, score)
    }

    /// Number of registered rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

impl Default for AnalysisEngine {
    fn default() -> Self {
        Self::with_default_rules()
    }
}

pub struct AnalysisRunner {
    config: Config,
}

impl AnalysisRunner {
    pub fn new(config: Config) -> Self {
        AnalysisRunner { config }
    }

    pub fn run(&self) -> Result<Vec<Report>> {
        let mut reports = Vec::new();

        for path_str in &self.config.paths {
            let path = Path::new(path_str);
            if path.is_dir() {
                self.analyze_dir(path, &mut reports)?;
            } else if path.is_file() {
                self.analyze_file(path, &mut reports)?;
            }
        }

        Ok(reports)
    }

    fn analyze_file(&self, path: &Path, reports: &mut Vec<Report>) -> Result<()> {
        let source = std::fs::read_to_string(path)?;
        let parser = ContractParser::new();
        if let Ok(contract) = parser.parse_source(&source) {
            let engine = AnalysisEngine::with_default_rules();
            let report = engine.analyze_contract(&contract, &path.to_string_lossy());
            reports.push(report);
        }
        Ok(())
    }

    fn analyze_dir(&self, path: &Path, reports: &mut Vec<Report>) -> Result<()> {
        for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
            if entry.path().extension().map_or(false, |ext| ext == "rs") {
                self.analyze_file(entry.path(), reports)?;
            }
        }
        Ok(())
    }
}
