# Usage

## CLI Reference

```
soroban-guard-core [OPTIONS] [PATH]...
```

### Arguments

| Argument | Description |
|----------|-------------|
| `PATH` | One or more paths to Soroban contract source files or directories to scan |

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-f, --format <FORMAT>` | Output format: `human`, `json`, `sarif` | `human` |
| `-m, --min-severity <LEVEL>` | Minimum severity to report: `critical`, `high`, `medium`, `low`, `info` | `low` |
| `-o, --output <FILE>` | Write output to file instead of stdout | None |
| `--exclude <PATTERNS>` | Comma-separated glob patterns to exclude from scanning | None |
| `--jobs <N>` | Number of parallel worker threads | `4` |
| `--all` | Enable all rule families | `true` |
| `--rules <IDS>` | Comma-separated finding rule IDs to show (e.g. `R-01,S-02`) | None |
| `--sarif` | Shortcut for `--format sarif` | `false` |
| `--config <FILE>` | Path to TOML configuration file | None |
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
soroban-guard-core --exclude '**/test_*,**/mocks/*' ./contracts/
```

### Parallel analysis with 8 workers

```bash
soroban-guard-core --jobs 8 ./contracts/
```

### Filter by specific rule IDs

```bash
soroban-guard-core --rules "R-01,A-01,S-02" ./contracts/
```

### Disable all rules (config-only analysis)

```bash
soroban-guard-core --all false ./contracts/
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
| `0` | No critical or high severity findings |
| `1` | Critical or high severity findings detected |
