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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl Default for RulesConfig {
    fn default() -> Self {
        RulesConfig {
            reentrancy: RuleOverride::default(),
            overflow: RuleOverride::default(),
            access_control: RuleOverride::default(),
            storage: RuleOverride::default(),
        }
    }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    #[serde(default)]
    pub format: Option<OutputFormat>,
    #[serde(default)]
    pub min_severity: Option<MinSeverity>,
}

impl Default for OutputConfig {
    fn default() -> Self {
        OutputConfig {
            format: None,
            min_severity: None,
        }
    }
}

impl ConfigFile {
    pub fn from_file(path: &Path) -> Result<Self, crate::error::SorobanGuardError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| crate::error::SorobanGuardError::Config(format!("Cannot read config: {}", e)))?;
        toml::from_str(&content)
            .map_err(|e| crate::error::SorobanGuardError::Config(format!("Invalid config: {}", e)))
    }
}
