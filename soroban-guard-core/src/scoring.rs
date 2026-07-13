use serde::{Deserialize, Serialize};

use crate::report::finding::Finding;
use crate::report::severity::Severity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityScore {
    pub overall: u8,
    pub grade: String,
    pub breakdown: SeverityBreakdown,
    pub top_issues: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityBreakdown {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub info: u32,
}

pub struct ScoringEngine;

impl ScoringEngine {
    pub fn new() -> Self {
        ScoringEngine
    }

    pub fn calculate_score(&self, findings: &[Finding]) -> SecurityScore {
        calculate_score(findings)
    }
}

impl Default for ScoringEngine {
    fn default() -> Self {
        Self::new()
    }
}

pub fn calculate_score(findings: &[Finding]) -> SecurityScore {
    let mut score: f64 = 100.0;

    for finding in findings {
        let deduction = match finding.severity {
            Severity::Critical => 30.0,
            Severity::High => 15.0,
            Severity::Medium => 7.0,
            Severity::Low => 3.0,
            Severity::Info => 1.0,
        };
        score = (score - deduction).max(0.0);
    }

    // Bonus points for good practices (no finding = practice present)
    let has_guard = !findings.iter().any(|f| f.rule_id == "R-03");
    let has_version = !findings.iter().any(|f| f.rule_id == "S-05");

    if has_guard {
        score = (score + 5.0).min(100.0);
    }
    if has_version {
        score = (score + 3.0).min(100.0);
    }

    let overall = score.round() as u8;
    let grade = grade_for(overall);

    SecurityScore {
        overall,
        grade,
        breakdown: SeverityBreakdown {
            critical: findings.iter().filter(|f| f.severity == Severity::Critical).count() as u32,
            high: findings.iter().filter(|f| f.severity == Severity::High).count() as u32,
            medium: findings.iter().filter(|f| f.severity == Severity::Medium).count() as u32,
            low: findings.iter().filter(|f| f.severity == Severity::Low).count() as u32,
            info: findings.iter().filter(|f| f.severity == Severity::Info).count() as u32,
        },
        top_issues: findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Critical | Severity::High))
            .take(5)
            .cloned()
            .collect(),
    }
}

pub fn generate_summary(score: &SecurityScore) -> String {
    format!(
        "Security Score: {}/100 (Grade {})\n\
         Critical: {} | High: {} | Medium: {} | Low: {} | Info: {}\n\
         Top issues: {}",
        score.overall,
        score.grade,
        score.breakdown.critical,
        score.breakdown.high,
        score.breakdown.medium,
        score.breakdown.low,
        score.breakdown.info,
        score
            .top_issues
            .iter()
            .map(|f| f.message.as_str())
            .collect::<Vec<_>>()
            .join(", "),
    )
}

fn grade_for(score: u8) -> String {
    match score {
        90..=100 => "A".into(),
        70..=89 => "B".into(),
        50..=69 => "C".into(),
        30..=49 => "D".into(),
        _ => "F".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::finding::Finding;
    use crate::report::severity::Severity;

    fn finding(severity: Severity, rule_id: &str) -> Finding {
        Finding::new(severity, rule_id, "test", "test", "test")
    }

    #[test]
    fn test_perfect_score() {
        let score = calculate_score(&[]);
        assert_eq!(score.overall, 100);
        assert_eq!(score.grade, "A");
        assert!(score.top_issues.is_empty());
    }

    #[test]
    fn test_one_critical() {
        let findings = vec![finding(Severity::Critical, "A-01")];
        let score = calculate_score(&findings);
        // 100 - 30 = 70, +5 (no R-03) = 75, +3 (no S-05) = 78
        assert_eq!(score.overall, 78);
        assert_eq!(score.grade, "B");
    }

    #[test]
    fn test_mixed_findings() {
        let findings = vec![
            finding(Severity::Critical, "A-01"),
            finding(Severity::High, "R-01"),
            finding(Severity::Medium, "S-01"),
            finding(Severity::Low, "O-05"),
        ];
        // 100 - 30 - 15 - 7 - 3 = 45, +5 (no R-03) = 50, +3 (no S-05) = 53
        let score = calculate_score(&findings);
        assert_eq!(score.overall, 53);
        assert_eq!(score.grade, "C");
    }

    #[test]
    fn test_bonus_guard_present() {
        let findings = vec![finding(Severity::High, "R-01")];
        let score = calculate_score(&findings);
        // 100 - 15 = 85, +5 (no R-03) = 90, +3 (no S-05) = 93
        assert_eq!(score.overall, 93);
    }

    #[test]
    fn test_bonus_version_present() {
        let findings = vec![finding(Severity::Medium, "S-01")];
        let score = calculate_score(&findings);
        // 100 - 7 = 93, +5 (no R-03) = 98, +3 (no S-05) = 100 (capped)
        assert_eq!(score.overall, 100);
    }

    #[test]
    fn test_no_bonus_when_guard_missing() {
        let findings = vec![finding(Severity::Low, "R-03")];
        let score = calculate_score(&findings);
        // 100 - 3 = 97, no guard bonus (R-03 present), +3 (no S-05) = 100 (capped)
        assert_eq!(score.overall, 100);
    }

    #[test]
    fn test_no_bonus_when_version_missing() {
        let findings = vec![finding(Severity::Info, "S-05")];
        let score = calculate_score(&findings);
        // 100 - 1 = 99, +5 (no R-03) = 100 (capped), no version bonus (S-05 present)
        assert_eq!(score.overall, 100);
    }

    #[test]
    fn test_score_floor() {
        let mut findings = Vec::new();
        for _ in 0..10 {
            findings.push(finding(Severity::Critical, "A-01"));
        }
        let score = calculate_score(&findings);
        // 100 - 10*30 = -200, floored at 0, +5 (no R-03) = 5, +3 (no S-05) = 8
        assert_eq!(score.overall, 8);
        assert_eq!(score.grade, "F");
    }

    #[test]
    fn test_grade_boundaries() {
        assert_eq!(grade_for(100), "A");
        assert_eq!(grade_for(90), "A");
        assert_eq!(grade_for(89), "B");
        assert_eq!(grade_for(70), "B");
        assert_eq!(grade_for(69), "C");
        assert_eq!(grade_for(50), "C");
        assert_eq!(grade_for(49), "D");
        assert_eq!(grade_for(30), "D");
        assert_eq!(grade_for(29), "F");
        assert_eq!(grade_for(0), "F");
    }

    #[test]
    fn test_generate_summary() {
        let findings = vec![finding(Severity::Critical, "A-01")];
        let score = calculate_score(&findings);
        let summary = generate_summary(&score);
        assert!(summary.contains("78/100"), "summary: {}", summary);
        assert!(summary.contains("Grade B"), "summary: {}", summary);
        assert!(summary.contains("Critical: 1"), "summary: {}", summary);
    }

    #[test]
    fn test_top_issues_limit() {
        let mut findings = Vec::new();
        for i in 0..10 {
            findings.push(finding(Severity::Critical, &format!("R-{:02}", i)));
        }
        let score = calculate_score(&findings);
        assert_eq!(score.top_issues.len(), 5);
    }

    #[test]
    fn test_severity_breakdown() {
        let findings = vec![
            finding(Severity::Critical, "A-01"),
            finding(Severity::High, "A-02"),
            finding(Severity::Medium, "A-04"),
            finding(Severity::Low, "O-05"),
            finding(Severity::Info, "S-05"),
        ];
        let score = calculate_score(&findings);
        assert_eq!(score.breakdown.critical, 1);
        assert_eq!(score.breakdown.high, 1);
        assert_eq!(score.breakdown.medium, 1);
        assert_eq!(score.breakdown.low, 1);
        assert_eq!(score.breakdown.info, 1);
    }
}
