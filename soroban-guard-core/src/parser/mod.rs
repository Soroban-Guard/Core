pub mod ast;

use crate::error::{Result, SorobanGuardError};
use crate::report::finding::Finding;
use ast::ContractAst;

pub struct ContractParser;

impl ContractParser {
    pub fn new() -> Self {
        ContractParser
    }

    pub fn parse_file(&self, path: &str) -> Result<Vec<Finding>> {
        let source = std::fs::read_to_string(path).map_err(SorobanGuardError::Io)?;
        let _ast = self.parse_source(&source)?;
        Ok(Vec::new())
    }

    pub fn parse_source(&self, source: &str) -> Result<ContractAst> {
        let syntax_tree: syn::File =
            syn::parse_file(source).map_err(|e| SorobanGuardError::Parse(e.to_string()))?;
        Ok(ContractAst::new(source.to_string(), syntax_tree.items))
    }
}

impl Default for ContractParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty_source() {
        let parser = ContractParser::new();
        let result = parser.parse_source("fn main() {}");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_invalid_source() {
        let parser = ContractParser::new();
        let result = parser.parse_source("invalid syntax !!!");
        assert!(result.is_err());
    }
}
