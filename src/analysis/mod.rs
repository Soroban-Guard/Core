pub mod access_control;
pub mod overflow;
pub mod reentrancy;
pub mod storage;

use crate::config::RuleOverride;
use crate::parser::ast::Contract;
use crate::report::finding::Finding;
use crate::report::severity::Severity;
use crate::report::Report;
use crate::scoring::calculate_score;

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

    /// Create an engine with only the specified rule IDs registered.
    /// Empty slice means all rules are registered (same as `with_default_rules`).
    pub fn with_rules(ids: &[&str]) -> Self {
        if ids.is_empty() {
            return Self::with_default_rules();
        }
        let mut engine = Self::new();
        for &id in ids {
            match id {
                "reentrancy" => engine.register(Box::new(reentrancy::ReentrancyDetector)),
                "overflow" => engine.register(Box::new(overflow::OverflowChecker)),
                "access_control" => engine.register(Box::new(access_control::AccessControlDetector)),
                "storage" => engine.register(Box::new(storage::StorageCollisionDetector)),
                _ => {},
            }
        }
        engine
    }

    /// Register a rule. Rules execute in the order they are registered.
    pub fn register(&mut self, rule: Box<dyn AnalysisRule>) -> &mut Self {
        self.rules.push(rule);
        self
    }

    /// Apply severity overrides from config to a set of findings.
    /// Each override changes the severity of all findings whose rule_id
    /// matches the given rule family prefix (e.g. "R-" for reentrancy).
    pub fn apply_overrides(
        overrides: &[(&str, &RuleOverride)],
        findings: &mut [Finding],
    ) {
        for (prefix, override_) in overrides {
            if let Some(ref sev_str) = override_.severity {
                if let Some(sev) = Self::parse_severity(sev_str) {
                    for finding in findings.iter_mut() {
                        if finding.rule_id.starts_with(prefix) {
                            finding.severity = sev.clone();
                        }
                    }
                }
            }
        }
    }

    fn parse_severity(s: &str) -> Option<Severity> {
        match s.to_lowercase().as_str() {
            "critical" => Some(Severity::Critical),
            "high" => Some(Severity::High),
            "medium" => Some(Severity::Medium),
            "low" => Some(Severity::Low),
            "info" => Some(Severity::Info),
            _ => None,
        }
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
