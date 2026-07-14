# Contributing

## Adding a new analysis rule

1. Create a new file in `src/analysis/` (e.g., `new_rule.rs`)
2. Implement the `AnalysisRule` trait:

```rust
use crate::analysis::AnalysisRule;
use crate::parser::ast::Contract;
use crate::report::finding::Finding;

pub struct NewRuleDetector;

impl AnalysisRule for NewRuleDetector {
    fn id(&self) -> &'static str {
        "new-rule"
    }
    fn name(&self) -> &'static str {
        "New Rule Detector"
    }
    fn description(&self) -> &'static str {
        "Detects new vulnerability patterns"
    }
    fn analyze(&self, contract: &Contract) -> Vec<Finding> {
        // Your analysis logic here
        vec![]
    }
}
```

3. Register the rule in `AnalysisEngine::with_default_rules()` in `src/analysis/mod.rs`
4. Add tests in `tests/` for the new rule

## Project structure

```
src/
  lib.rs              — Public API
  main.rs             — CLI entry point
  config.rs           — Configuration
  error.rs            — Error types
  analysis/
    mod.rs            — AnalysisEngine, AnalysisRule trait
    access_control.rs — A-01 to A-05
    reentrancy.rs     — R-01 to R-04
    overflow.rs       — O-01 to O-05
    storage.rs        — S-01 to S-05
  parser/
    mod.rs            — ContractParser
    ast.rs            — AST types
    patterns.rs       — Pattern matching helpers
    visitors.rs       — syn-based visitor
  report/
    mod.rs            — Report struct
    finding.rs        — Finding struct
    severity.rs       — Severity enum
    output.rs         — Formatters (human, JSON, SARIF)
  scoring.rs          — SecurityScore calculation
tests/
  fixtures/           — Test contracts and expected outputs
  integration_test.rs — Full pipeline tests
  regression_test.rs  — Regression tests
  edge_case_test.rs   — Edge case tests
  property_test.rs    — Property-based tests
  cli_tests.rs        — CLI integration tests
```

## Running tests

```bash
cargo test
cargo clippy
cargo fmt --check
```
