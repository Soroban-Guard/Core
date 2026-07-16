# Usage

## CLI Reference

```
soroban-guard-core [OPTIONS] [PATH]...
```

### Arguments

| Argument | Description |
|----------|-------------|
| `PATH` | One or more paths to Soroban contract source files or directories |

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-f, --format <FORMAT>` | Output format: `human`, `json`, `sarif` | `human` |
| `-m, --min-severity <LEVEL>` | Minimum severity to report: `critical`, `high`, `medium`, `low`, `info` | `low` |
| `-o, --output <FILE>` | Write output to file instead of stdout | None |
| `--exclude <PATTERNS>` | Comma-separated glob patterns to exclude | None |
| `--sarif` | Shortcut for `--format sarif` | false |
| `--config <FILE>` | Path to TOML config file | None |
| `-h, --help` | Print help | |
| `-V, --version` | Print version | |

## Examples

### Basic analysis

```bash
soroban-guard-core contract.rs
```

### Multiple files

```bash
soroban-guard-core contract1.rs contract2.rs
```

### Directory scan with exclusion

```bash
soroban-guard-core --exclude '**/test_*' --exclude '**/mocks/*' ./contracts/
```

### Generate SARIF for GitHub code scanning

```bash
soroban-guard-core --sarif -o results.sarif ./contracts/
```

### Filter critical issues only

```bash
soroban-guard-core --min-severity critical contract.rs
```

### With config file

```bash
soroban-guard-core --config soroban-guard.toml contract.rs
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | No critical or high findings |
| `1` | Critical or high findings detected |
