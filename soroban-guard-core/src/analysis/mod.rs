pub mod access_control;
pub mod overflow;
pub mod reentrancy;
pub mod storage;

use std::path::Path;

use walkdir::WalkDir;

use crate::config::Config;
use crate::error::Result;
use crate::report::finding::Finding;
use crate::report::Report;

pub trait Analyzer {
    fn analyze(&self, source: &str, file_path: &str) -> Vec<Finding>;
    fn name(&self) -> &'static str;
}

pub struct AnalysisRunner {
    config: Config,
    analyzers: Vec<Box<dyn Analyzer + Send + Sync>>,
}

impl AnalysisRunner {
    pub fn new(config: Config) -> Self {
        let analyzers: Vec<Box<dyn Analyzer + Send + Sync>> = vec![
            Box::new(reentrancy::ReentrancyDetector),
            Box::new(overflow::OverflowChecker),
            Box::new(access_control::AccessControlAnalyzer),
            Box::new(storage::StorageCollisionDetector),
        ];

        AnalysisRunner { config, analyzers }
    }

    pub fn run(&self) -> Result<Report> {
        let mut report = Report::new();

        for path_str in &self.config.paths {
            let path = Path::new(path_str);
            if path.is_dir() {
                self.analyze_dir(path, &mut report)?;
            } else if path.is_file() {
                self.analyze_file(path, &mut report)?;
            }
        }

        Ok(report)
    }

    fn analyze_file(&self, path: &Path, report: &mut Report) -> Result<()> {
        let source = std::fs::read_to_string(path)?;
        for analyzer in &self.analyzers {
            let findings = analyzer.analyze(&source, &path.to_string_lossy());
            for finding in findings {
                report.add_finding(finding);
            }
        }
        Ok(())
    }

    fn analyze_dir(&self, path: &Path, report: &mut Report) -> Result<()> {
        for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
            if entry.path().extension().map_or(false, |ext| ext == "rs") {
                self.analyze_file(entry.path(), report)?;
            }
        }
        Ok(())
    }
}
