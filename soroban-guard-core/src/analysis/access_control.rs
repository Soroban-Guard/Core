use super::Analyzer;
use crate::report::finding::Finding;

pub struct AccessControlAnalyzer;

impl Analyzer for AccessControlAnalyzer {
    fn analyze(&self, _source: &str, _file_path: &str) -> Vec<Finding> {
        Vec::new()
    }

    fn name(&self) -> &'static str {
        "access_control"
    }
}
