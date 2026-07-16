# Integrations

## GitHub Actions

The [Soroban Guard GitHub Action](https://github.com/Soroban-Guard/Actions) provides automated scanning with PR annotations, summary comments, and SARIF upload — no CLI setup required.

```yaml
name: Security Audit
on: [pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Soroban-Guard/Actions@v1
        with:
          path: contracts/
```

### Using the CLI directly

```yaml
name: Soroban Guard Analysis
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rust-lang/setup-rust-toolchain@v1
      - run: cargo install soroban-guard-core
      - run: soroban-guard-core --sarif --output results.sarif ./contracts/
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## VS Code

The [Soroban Guard VS Code extension](https://github.com/Soroban-Guard/VS) provides real-time inline diagnostics, code actions with one-click fixes, and a rich report panel.

Alternatively, add a task in `.vscode/tasks.json`:

```json
{
    "version": "2.0.0",
    "tasks": [{
        "label": "Soroban Guard",
        "type": "shell",
        "command": "soroban-guard-core --format json --output ${workspaceFolder}/report.json ${file}",
        "problemMatcher": [],
        "group": "build"
    }]
}
```

## Pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: soroban-guard
        name: Soroban Guard
        entry: soroban-guard-core
        language: system
        files: '\.rs$'
```

## CI/CD Pipeline

The tool exits with code `1` when critical or high severity findings are detected, making it suitable for CI gating:

```bash
soroban-guard-core ./contracts/ && echo "Pass" || echo "Security issues found"
```

## Coverage

| Integration | Support | Notes |
|-------------|---------|-------|
| GitHub Actions (dedicated action) | Full | PR annotations, SARIF, score comments |
| GitHub Actions (CLI) | Full | SARIF upload via codeql-action |
| VS Code (extension) | Full | Inline diagnostics, code actions |
| VS Code (task) | Basic | Run via task runner |
| Pre-commit | Basic | Per-commit scan hook |
| Generic CI | Full | Exit code based gating |
