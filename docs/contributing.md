# Contributing

Thank you for your interest in Soroban Guard. We welcome contributions of all forms — bug reports, feature requests, documentation improvements, and code changes.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Workflow](#workflow)
- [Pull Request Guidelines](#pull-request-guidelines)
- [Adding a New Analysis Rule](#adding-a-new-analysis-rule)
- [Project Structure](#project-structure)
- [Running Tests](#running-tests)
- [Code Style](#code-style)

## Code of Conduct

This project follows the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct). By participating, you agree to uphold its standards.

## Getting Started

1. Fork the repository.
2. Clone your fork: `git clone https://github.com/<your-username>/Core.git`
3. Install Rust (edition 2021, MSRV 1.70): `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
4. Verify: `cargo build && cargo test`

## Workflow

1. **Pick an issue** — browse the [issue tracker](https://github.com/Soroban-Guard/Core/issues) for open tasks. Comment on the issue to let others know you're working on it.
2. **Create a branch** from `main`:
   - Bug fixes: `fix/description-of-bug`
   - New features: `feat/description-of-feature`
   - Docs: `docs/description-of-change`
3. **Commit your changes** with clear, descriptive messages following [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat: add reentrancy detection for read-only calls`
   - `fix: handle empty source files gracefully`
   - `docs: update CLI usage examples`
4. **Push your branch** and open a **Pull Request** against the `main` branch.
5. **Respond to feedback** — a maintainer will review your PR. Address any requested changes.
6. Once approved, your PR will be **merged**.

> If you are part of the [Drips Wave Program](https://www.drips.network/wave/stellar), make sure your PR references the Drips issue or bounty so your contribution is tracked.

## Pull Request Guidelines

- **One change per PR** — keep pull requests focused on a single concern.
- **Include tests** — new features and bug fixes must include tests.
- **Update documentation** — if your change affects user-facing behavior, update the relevant docs.
- **Pass CI** — ensure `cargo build`, `cargo test`, `cargo clippy -- -D warnings`, and `cargo fmt --check` all pass.
- **Describe your changes** — provide a clear summary of what changed and why.
- **Link related issues** — use `Closes #123` or `Fixes #456` in the PR description.

## Adding a New Analysis Rule

1. Create a new file in `src/analysis/` (e.g., `new_rule.rs`).
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
        vec![]
    }
}
```

3. Register the rule in `AnalysisEngine::with_default_rules()` in `src/analysis/mod.rs`.
4. Add rule documentation in `docs/rules/`.
5. Add tests in `tests/` and test fixtures in `tests/fixtures/`.

## Project Structure

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

## Running Tests

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run a specific test
cargo test test_cli_rules_filter

# Lint
cargo clippy -- -D warnings

# Format
cargo fmt --check

# Benchmarks
cargo bench
```

## Code Style

- Follow standard Rust conventions as enforced by `rustfmt` and `clippy`.
- Use meaningful names for variables and functions.
- Prefer `Result<T, E>` over panics for recoverable errors.
- Document public API items with doc comments.
- Keep functions focused and small; extract helpers where appropriate.
