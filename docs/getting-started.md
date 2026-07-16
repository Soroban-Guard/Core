# Getting Started with Soroban Guard

## Installation

### From source

```bash
git clone https://github.com/Soroban-Guard/Core.git
cd Core
cargo build --release
# Binary at target/release/soroban-guard-core
```

### Using Cargo

```bash
cargo install soroban-guard-core
```

## Run your first analysis

```bash
soroban-guard-core path/to/your/contract.rs
```

This analyzes a single Soroban contract and prints a human-readable report.

### Scan a directory

```bash
soroban-guard-core path/to/project/
```

### JSON output

```bash
soroban-guard-core --format json path/to/contract.rs
```

### Save output to file

```bash
soroban-guard-core --format json --output report.json path/to/contract.rs
```

## Understanding the report

```
Soroban Guard Report
====================

Security Score: 44/100 (Grade D)
Critical: 0 | High: 3 | Medium: 0 | Low: 3 | Info: 2
```

- **Score**: 0-100 rating based on severity and count of findings
- **Grade**: A (90-100), B (70-89), C (50-69), D (30-49), F (0-29)
- **Breakdown**: Count of findings at each severity level
- **Findings**: Grouped by severity with rule ID, description, location, and remediation suggestion
