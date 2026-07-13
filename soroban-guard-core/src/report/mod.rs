pub mod finding;
pub mod severity;

use finding::Finding;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Report {
    pub findings: Vec<Finding>,
    pub score: u8,
}

impl Report {
    pub fn new() -> Self {
        Report {
            findings: Vec::new(),
            score: 100,
        }
    }

    pub fn add_finding(&mut self, finding: Finding) {
        self.score = self.score.saturating_sub(finding.severity.score_penalty());
        self.findings.push(finding);
    }

    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }
}

impl Default for Report {
    fn default() -> Self {
        Self::new()
    }
}
