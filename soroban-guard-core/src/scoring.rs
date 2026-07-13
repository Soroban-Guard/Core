use crate::report::finding::Finding;

pub struct ScoringEngine;

impl ScoringEngine {
    pub fn new() -> Self {
        ScoringEngine
    }

    pub fn calculate_score(&self, findings: &[Finding]) -> u8 {
        let mut score = 100u8;
        for finding in findings {
            score = score.saturating_sub(finding.severity.score_penalty());
        }
        score
    }
}

impl Default for ScoringEngine {
    fn default() -> Self {
        Self::new()
    }
}
