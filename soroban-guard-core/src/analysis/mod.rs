pub mod access_control;
pub mod overflow;
pub mod reentrancy;
pub mod storage;

use std::path::Path;

use walkdir::WalkDir;

use crate::config::Config;
use crate::error::Result;
use crate::parser::ast::Contract;
use crate::report::finding::Finding;
use crate::report::Report;

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
    analyzers: Vec<Box<dyn Analyzer + Send + Sync>>,
}

impl AnalysisRunner {
    pub fn new(config: Config) -> Self {
        let analyzers: Vec<Box<dyn Analyzer + Send + Sync>> = vec![
            Box::new(reentrancy::ReentrancyDetector),
            Box::new(overflow::OverflowChecker),
            Box::new(access_control::AccessControlDetector),
            Box::new(storage::StorageCollisionDetector),
        ];

        AnalysisRunner { config, analyzers }
    }

    pub fn run(&self) -> Result<Report> {
        let mut report = Report::new();

        for path_str in &self.config.paths {
            let path = Path::new(path_str);
            if path.is_dir() {
                self.analyze_dir(path, &mut report)?;
            } else if path.is_file() {
                self.analyze_file(path, &mut report)?;
            }
        }

        Ok(report)
    }

    fn analyze_file(&self, path: &Path, report: &mut Report) -> Result<()> {
        let source = std::fs::read_to_string(path)?;
        for analyzer in &self.analyzers {
            let findings = analyzer.analyze(&source, &path.to_string_lossy());
            for finding in findings {
                report.add_finding(finding);
            }
        }
        Ok(())
    }

    fn analyze_dir(&self, path: &Path, report: &mut Report) -> Result<()> {
        for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
            if entry.path().extension().map_or(false, |ext| ext == "rs") {
                self.analyze_file(entry.path(), report)?;
            }
        }
        Ok(())
    }
}
