use super::Analyzer;
use crate::report::finding::Finding;

pub struct ReentrancyDetector;

impl Analyzer for ReentrancyDetector {
    fn analyze(&self, _source: &str, _file_path: &str) -> Vec<Finding> {
        Vec::new()
    }

    fn name(&self) -> &'static str {
        "reentrancy"
    }
}
