# Getting Started with Soroban Guard

## Prerequisites

- Rust edition 2021 (MSRV 1.70): `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- A Soroban smart contract project written in Rust

## Installation

### From source

```bash
git clone https://github.com/Soroban-Guard/Core.git
cd Core
cargo build --release
```

The binary is at `target/release/soroban-guard-core`.

### From crates.io

```bash
cargo install soroban-guard-core
```

## Run your first analysis

```bash
soroban-guard-core path/to/your/contract.rs
```

This analyzes a single Soroban contract and prints a human-readable report with findings grouped by severity.

### Scan a directory

```bash
soroban-guard-core path/to/project/
```

Recursively scans all `.rs` files in the directory.

### JSON output

```bash
soroban-guard-core --format json path/to/contract.rs
```

### Save output to file

```bash
soroban-guard-core --format json --output report.json path/to/contract.rs
```

### Generate SARIF for GitHub Code Scanning

```bash
soroban-guard-core --sarif --output results.sarif ./contracts/
```

### Run only specific rules

```bash
soroban-guard-core --rules "R-01,A-01" path/to/contract.rs
```

### Use a configuration file

```bash
soroban-guard-core --config soroban-guard.toml ./contracts/
```

## Understanding the report

```
Soroban Guard Report
====================

Security Score: 44/100 (Grade D)
Critical: 0 | High: 3 | Medium: 0 | Low: 3 | Info: 2

CRITICAL:
  [R-01] Function 'withdraw' writes to storage after an external call — reentrancy risk
     Location: vault.rs:42:5
     Suggestion: Move state updates before the external call, or use a reentrancy guard
```

- **Score**: 0-100 rating based on severity and count of findings
- **Grade**: A (90-100), B (70-89), C (50-69), D (30-49), F (0-29)
- **Breakdown**: Count of findings at each severity level
- **Findings**: Grouped by severity with rule ID, description, location, and remediation suggestion

## Next steps

- Learn about all [CLI options](usage.md)
- Configure persistent settings with a [config file](configuration.md)
- Integrate with [GitHub Actions and VS Code](integrations.md)
- Read the [rule documentation](rules/reentrancy.md) for each detection category
