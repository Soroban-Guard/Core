use super::Analyzer;
use crate::report::finding::Finding;

pub struct StorageCollisionDetector;

impl Analyzer for StorageCollisionDetector {
    fn analyze(&self, _source: &str, _file_path: &str) -> Vec<Finding> {
        Vec::new()
    }

    fn name(&self) -> &'static str {
        "storage"
    }
}
