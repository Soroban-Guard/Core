pub mod finding;
pub mod severity;

use chrono::{DateTime, Utc};

use self::finding::Finding;
use crate::scoring::{generate_summary, SecurityScore};

#[derive(Debug, Clone)]
pub struct Report {
    pub contract_name: String,
    pub source_file: String,
    pub score: SecurityScore,
    pub findings: Vec<Finding>,
    pub summary: String,
    pub analyzed_at: DateTime<Utc>,
}

impl Report {
    pub fn new(contract_name: impl Into<String>, source_file: impl Into<String>, findings: Vec<Finding>, score: SecurityScore) -> Self {
        let summary = generate_summary(&score);
        Report {
            contract_name: contract_name.into(),
            source_file: source_file.into(),
            score,
            findings,
            summary,
            analyzed_at: Utc::now(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }
}
