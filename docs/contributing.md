# Contributing

## Workflow

1. **Fork** the repository to your own GitHub account.
2. **Clone** your fork locally and create a **branch** for your work (e.g., `fix/reentrancy-false-positive` or `feature/new-rule`).
3. **Pick an issue** — look for open issues, preferably ones assigned to you or discussed in advance.
4. **Commit** your changes with clear, descriptive messages.
5. **Push** your branch and open a **Pull Request** against the main repository.
   - Provide a detailed description linking to the issue(s) your PR addresses.
   - Include a summary of changes, any relevant test results, and screenshots if the change is user-facing.
6. **Respond to feedback** — a maintainer will review your PR. Address any requested changes.
7. Once approved, your PR will be **merged**.

> If you are part of the [Drips Wave Program](https://www.drips.network/wave/stellar), make sure your PR references the Drips issue or bounty so your contribution is tracked.

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
