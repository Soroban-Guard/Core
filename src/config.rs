use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, ValueEnum, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    Human,
    Json,
    Sarif,
}

#[derive(Debug, Clone, ValueEnum, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MinSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl MinSeverity {
    pub fn to_severity(&self) -> crate::report::severity::Severity {
        match self {
            MinSeverity::Critical => crate::report::severity::Severity::Critical,
            MinSeverity::High => crate::report::severity::Severity::High,
            MinSeverity::Medium => crate::report::severity::Severity::Medium,
            MinSeverity::Low => crate::report::severity::Severity::Low,
            MinSeverity::Info => crate::report::severity::Severity::Info,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigFile {
    #[serde(default)]
    pub general: GeneralConfig,
    #[serde(default)]
    pub rules: RulesConfig,
    #[serde(default)]
    pub output: OutputConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub jobs: Option<usize>,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        GeneralConfig {
            exclude: Vec::new(),
            jobs: Some(4),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RulesConfig {
    #[serde(default)]
    pub reentrancy: RuleOverride,
    #[serde(default)]
    pub overflow: RuleOverride,
    #[serde(default)]
    pub access_control: RuleOverride,
    #[serde(default)]
    pub storage: RuleOverride,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleOverride {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub severity: Option<String>,
}

impl Default for RuleOverride {
    fn default() -> Self {
        RuleOverride {
            enabled: Some(true),
            severity: None,
        }
    }
}

impl RuleOverride {
    pub fn to_severity(&self) -> Option<crate::report::severity::Severity> {
        self.severity
            .as_ref()
            .and_then(|s| match s.to_lowercase().as_str() {
                "critical" => Some(crate::report::severity::Severity::Critical),
                "high" => Some(crate::report::severity::Severity::High),
                "medium" => Some(crate::report::severity::Severity::Medium),
                "low" => Some(crate::report::severity::Severity::Low),
                "info" => Some(crate::report::severity::Severity::Info),
                _ => None,
            })
    }
}

impl RulesConfig {
    pub fn enabled_rule_ids(&self) -> Vec<&'static str> {
        let mut ids = Vec::new();
        if self.reentrancy.enabled.unwrap_or(true) {
            ids.push("reentrancy");
        }
        if self.overflow.enabled.unwrap_or(true) {
            ids.push("overflow");
        }
        if self.access_control.enabled.unwrap_or(true) {
            ids.push("access_control");
        }
        if self.storage.enabled.unwrap_or(true) {
            ids.push("storage");
        }
        ids
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OutputConfig {
    #[serde(default)]
    pub format: Option<OutputFormat>,
    #[serde(default)]
    pub min_severity: Option<MinSeverity>,
}

impl ConfigFile {
    pub fn from_file(path: &Path) -> Result<Self, crate::error::SorobanGuardError> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            crate::error::SorobanGuardError::Config(format!("Cannot read config: {}", e))
        })?;
        toml::from_str(&content)
            .map_err(|e| crate::error::SorobanGuardError::Config(format!("Invalid config: {}", e)))
    }
}
