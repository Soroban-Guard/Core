use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    Human,
    Json,
    Sarif,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum SeverityLevel {
    Warn,
    Error,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub paths: Vec<String>,
    pub format: OutputFormat,
    pub severity: SeverityLevel,
    pub output: Option<PathBuf>,
    pub exclude: Option<String>,
    pub jobs: usize,
}
