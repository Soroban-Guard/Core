use serde::{Deserialize, Serialize};

use super::severity::Severity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub rule_id: String,
    pub message: String,
    pub location: String,
    pub suggestion: String,
}

impl Finding {
    pub fn new(
        severity: Severity,
        rule_id: impl Into<String>,
        message: impl Into<String>,
        location: impl Into<String>,
        suggestion: impl Into<String>,
    ) -> Self {
        Finding {
            severity,
            rule_id: rule_id.into(),
            message: message.into(),
            location: location.into(),
            suggestion: suggestion.into(),
        }
    }
}
