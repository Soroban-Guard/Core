use thiserror::Error;

#[derive(Debug, Error)]
pub enum SorobanGuardError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("No Soroban contracts found: {0}")]
    NoContractsFound(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Analysis error: {0}")]
    Analysis(String),

    #[error("Report error: {0}")]
    Report(String),
}

pub type Result<T> = std::result::Result<T, SorobanGuardError>;
