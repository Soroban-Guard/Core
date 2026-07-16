# Soroban Guard

[![CI](https://img.shields.io/github/actions/workflow/status/Soroban-Guard/Core/ci.yml?branch=main&label=CI)](https://github.com/Soroban-Guard/Core/actions)
[![GitHub release](https://img.shields.io/github/v/release/Soroban-Guard/Core)](https://github.com/Soroban-Guard/Core/releases)
[![MIT License](https://img.shields.io/github/license/Soroban-Guard/Core)](LICENSE)

**Soroban Guard** is a static analysis and security auditing toolchain for [Soroban smart contracts](https://soroban.stellar.org/) — the Rust-based smart contract platform on the Stellar network. It analyzes Rust source code to detect common security vulnerabilities before deployment, providing actionable feedback through multiple output formats and CI/CD integrations.

Soroban Guard is part of a broader ecosystem. This repository contains the core analysis engine and CLI. Companion projects provide additional interfaces:

- **[Soroban-Guard/VS](https://github.com/Soroban-Guard/VS)** — A VS Code extension that surfaces diagnostics and code actions inline as you edit.
- **[Soroban-Guard/Actions](https://github.com/Soroban-Guard/Actions)** — A GitHub Action that runs the analyzer in CI/CD pipelines with PR annotations and SARIF uploads.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Output Formats](#output-formats)
- [Configuration](#configuration)
- [Rules Overview](#rules-overview)
- [Security Scoring](#security-scoring)
- [Integrations](#integrations)
- [Documentation](#documentation)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- **Reentrancy Detection** — Identifies state-after-call patterns, read-only reentrancy, missing guards, and cross-function reentrancy (R-01 to R-04).
- **Arithmetic Overflow & Underflow** — Detects unchecked operations on `i128`/`u128` and other financial integer types (O-01 to O-05).
- **Access Control Analysis** — Finds functions missing authorization checks, hardcoded addresses, and overly permissive visibility (A-01 to A-05).
- **Storage Collision Detection** — Prevents short or generic key names, type mismatches, and instance-vs-temporary access conflicts (S-01 to S-05).
- **Security Scoring** — Computes a 0–100 score with letter grades (A–F) and a severity breakdown for quick triage.
- **Multiple Output Formats** — Human-readable terminal output, structured JSON, and SARIF for GitHub Code Scanning.
- **CI/CD Ready** — Exits with code 1 when critical or high severity findings are present.
- **Configurable** — TOML-based configuration with exclusion patterns and output controls.

---

## Installation

### From crates.io

```bash
cargo install soroban-guard-core
```

### From source

```bash
git clone https://github.com/Soroban-Guard/Core.git
cd Core
cargo build --release
./target/release/soroban-guard-core --help
```

### System requirements

- Rust edition 2021, minimum supported Rust version (MSRV): stable
- No external runtime dependencies — the binary is self-contained

---

## Usage

```bash
# Scan a single file
soroban-guard-core ./contracts/my_contract.rs

# Scan an entire directory
soroban-guard-core ./contracts/

# Scan with JSON output
soroban-guard-core --format json ./contracts/

# Generate SARIF report for GitHub Code Scanning
soroban-guard-core --sarif --output results.sarif ./contracts/

# Filter by minimum severity
soroban-guard-core --min-severity high ./contracts/

# Exclude test files and fixtures
soroban-guard-core --exclude "**/test_*, **/fixtures/*" ./contracts/

# Use a configuration file
soroban-guard-core --config soroban-guard.toml ./contracts/
```

### CLI Options

| Option | Short | Description |
|---|---|---|
| `PATH` | | File or directory to scan (multiple allowed) |
| `--format` | `-f` | Output format: `human`, `json`, `sarif` (default: `human`) |
| `--min-severity` | `-m` | Minimum severity to report: `info`, `low`, `medium`, `high`, `critical` (default: `info`) |
| `--output` | `-o` | Write output to a file |
| `--exclude` | | Glob patterns to exclude (comma-separated) |
| `--sarif` | | Shorthand for `--format sarif` |
| `--config` | | Path to TOML configuration file |

---

## Output Formats

### Human-readable (default)

Colored terminal output with findings grouped by severity, including rule IDs, file locations, descriptions, and remediation suggestions.

```
Soroban Guard Report
====================

Security Score: 72/100 (Grade B)
Critical: 1 | High: 2 | Medium: 3 | Low: 5 | Info: 2

[CRITICAL] R-01: Storage written after external call
  → src/contract.rs:42:5
  Move storage writes before the external call or add a reentrancy guard.

[HIGH] A-01: Function mutates state without authorization
  → src/contract.rs:78:1
  Add require_auth(&caller) at the start of this function.

[...]
```

### JSON

Structured output suitable for programmatic consumption:

```json
{
  "contract_name": "vault",
  "score": 72,
  "grade": "B",
  "findings": [
    {
      "rule_id": "R-01",
      "severity": "critical",
      "message": "Storage written after external call",
      "location": {
        "file": "src/contract.rs",
        "line": 42,
        "column": 5
      },
      "suggestion": "Move storage writes before the external call or add a reentrancy guard."
    }
  ]
}
```

### SARIF

Static Analysis Results Interchange Format — [OASIS standard](https://sarifweb.azurewebsites.net/) for static analysis tool output. Compatible with GitHub Code Scanning, Azure DevOps, and other SARIF consumers.

```bash
soroban-guard-core --sarif --output results.sarif ./contracts/
```

---

## Configuration

Create a `soroban-guard.toml` file in your project root:

```toml
[general]
exclude = ["**/test_*", "**/fixtures/*"]

[output]
format = "human"
min_severity = "low"
```

Configuration file can be passed via `--config` or auto-detected when placed in the project root.

---

## Rules Overview

| ID | Rule | Severity | Description |
|---|---|---|---|
| R-01 | Reentrancy | Critical | Storage write after an external call (checks-effects-interactions violation) |
| R-02 | Read-only reentrancy | Medium | External call between a storage read and write of the same key |
| R-03 | Missing reentrancy guard | Low | External calls found but no reentrancy guard storage key detected |
| R-04 | Cross-function reentrancy | High | Two externally-calling functions share a storage key |
| O-01 | Unchecked arithmetic | High | Unchecked `+`, `-`, `*` on `i128`/`u128` types |
| O-02 | Threshold comparison | Medium | Arithmetic compared against a threshold without overflow protection |
| O-03 | Division by non-literal | Medium | Division or remainder by a non-literal divisor |
| O-04 | Loop accumulation | High | Compound accumulation inside a dynamically-bounded loop |
| O-05 | Truncating cast | Low | Narrowing cast from financial value to a smaller integer type |
| A-01 | Missing authorization | Critical/High | State-mutating function without access control |
| A-02 | Admin function | High | Admin-only function without authorization |
| A-03 | Delegate auth | Medium | `require_auth_for_args` used without direct `require_auth` |
| A-04 | Public callable | High/Medium/Info | Public function with no address parameter or auth check |
| A-05 | Hardcoded address | Medium | Hardcoded contract addresses that should be configurable |
| S-01 | Short storage key | Medium | Storage key ≤ 2 characters, risk of collision |
| S-02 | Generic key name | Low | Common key names like `"balance"`, `"owner"` without namespacing |
| S-03 | Type mismatch | High | Same key written with different value types across functions |
| S-04 | Storage tier conflict | High | Same key accessed via both `instance` and `temporary` storage |
| S-05 | Missing version key | Info | No version key found — risk during contract upgrades |

---

## Security Scoring

The scoring engine starts at 100 and deducts points based on finding severity:

| Severity | Deduction |
|---|---|
| Critical | −30 |
| High | −15 |
| Medium | −7 |
| Low | −3 |
| Info | −1 |

Bonus points are awarded for defensive patterns:

| Condition | Bonus |
|---|---|
| Reentrancy guard present (no R-03) | +5 |
| Version key present (no S-05) | +3 |

### Grades

| Range | Grade |
|---|---|
| 90–100 | A |
| 70–89 | B |
| 50–69 | C |
| 30–49 | D |
| 0–29 | F |

The report includes up to five top critical/high findings for immediate triage.

---

## Integrations

### GitHub Actions

The dedicated [Soroban Guard GitHub Action](https://github.com/Soroban-Guard/Actions) provides automated scanning with PR annotations, summary comments, and SARIF upload.

```yaml
- uses: Soroban-Guard/Actions@v1
  with:
    path: ./contracts/
    fail_on: high
    upload_sarif: true
```

Or use the CLI directly in any CI pipeline:

```yaml
- run: cargo install soroban-guard-core
- run: soroban-guard --sarif --output results.sarif ./contracts/
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### Pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: soroban-guard
        name: Soroban Guard
        entry: soroban-guard
        language: system
        files: '\.rs$'
```

### VS Code

The [Soroban Guard VS Code extension](https://github.com/Soroban-Guard/VS) provides real-time inline diagnostics, code actions with one-click fixes, and a rich report panel.

---

## Documentation

- [Getting Started](docs/getting-started.md) — A walkthrough of installation, first scan, and understanding results.
- [CLI Usage](docs/usage.md) — Complete CLI reference with examples.
- [Configuration](docs/configuration.md) — Detailed configuration file reference.
- [Integrations](docs/integrations.md) — Setup guides for GitHub Actions, VS Code, and CI/CD pipelines.
- [Architecture](docs/architecture.md) — Overview of the codebase structure and data flow.
- [Changelog](docs/changelog.md) — Version history and release notes.

### Rule Documentation

- [Reentrancy Rules](docs/rules/reentrancy.md) — R-01 through R-04
- [Overflow Rules](docs/rules/overflow.md) — O-01 through O-05
- [Access Control Rules](docs/rules/access-control.md) — A-01 through A-05
- [Storage Rules](docs/rules/storage.md) — S-01 through S-05

---

## Development

### Building

```bash
cargo build
cargo build --release
```

### Running tests

```bash
cargo test        # Unit and integration tests
cargo bench       # Criterion benchmarks
cargo clippy      # Lint
cargo fmt         # Format
```

### Project structure

```
src/
├── main.rs                   # CLI entry point
├── lib.rs                    # Library root with public re-exports
├── config.rs                 # TOML config parsing and CLI config merge
├── error.rs                  # Unified error types
├── scoring.rs                # Security scoring engine
├── parser/
│   ├── mod.rs                # ContractParser — parses source into Contract AST
│   ├── ast.rs                # AST types (Contract, ContractFn, FnBodyAnalysis)
│   ├── patterns.rs           # Soroban-specific pattern matchers
│   └── visitors.rs           # syn-based AST visitor
├── analysis/
│   ├── mod.rs                # AnalysisEngine, AnalysisRule trait
│   ├── reentrancy.rs         # R-01 to R-04 rules
│   ├── overflow.rs           # O-01 to O-05 rules
│   ├── access_control.rs     # A-01 to A-05 rules
│   └── storage.rs            # S-01 to S-05 rules
└── report/
    ├── mod.rs                # Report data structures
    ├── finding.rs            # Finding data structure
    ├── severity.rs           # Severity enum
    └── output.rs             # Human, JSON, and SARIF formatters
```

---

## Contributing

Contributions are welcome. Please see the [Contributing Guide](docs/contributing.md) for details on:

- Code style and conventions
- Pull request process
- Testing requirements
- Adding new analysis rules

This project is developed as part of the [Stellar Wave Program](https://www.drips.network/wave/stellar) on Drips — a recurring contribution sprint for the Stellar open-source ecosystem.

---

## License

Licensed under either of:

- [MIT License](LICENSE)
- [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)

at your option.
