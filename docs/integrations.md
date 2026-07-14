# Integrations

## GitHub Actions

```yaml
name: Soroban Guard Analysis
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rust-lang/setup-rust-toolchain@v1
      - run: cargo install soroban-guard
      - run: soroban-guard --sarif --output results.sarif ./contracts/
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## Pre-commit hook

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

## VS Code

Add a task in `.vscode/tasks.json`:

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

## CI/CD Pipeline

The tool exits with code `1` when critical or high findings are detected, making it suitable for CI gating:

```bash
soroban-guard-core ./contracts/ && echo "Pass" || echo "Security issues found"
```
