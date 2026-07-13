use super::Analyzer;
use crate::report::finding::Finding;

pub struct OverflowChecker;

impl Analyzer for OverflowChecker {
    fn analyze(&self, _source: &str, _file_path: &str) -> Vec<Finding> {
        Vec::new()
    }

    fn name(&self) -> &'static str {
        "overflow"
    }
}
