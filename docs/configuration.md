# Configuration File

Soroban Guard supports a TOML configuration file for persistent settings.

## Usage

```bash
soroban-guard-core --config soroban-guard.toml ./contracts/
```

## Format

```toml
[general]
exclude = ["**/test_*", "**/mocks/*"]
jobs = 4

[output]
format = "json"
min_severity = "high"

[rules.reentrancy]
enabled = true
severity = "high"

[rules.storage]
enabled = false
```

## Sections

### `[general]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `exclude` | array of strings | `[]` | Glob patterns to exclude from scanning |
| `jobs` | integer | `4` | Number of parallel worker threads |

### `[output]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `format` | string | `"human"` | Output format: `human`, `json`, `sarif` |
| `min_severity` | string | `"low"` | Override minimum severity for output filtering |

### `[rules.*]`

Each rule family can be independently configured:

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | boolean | `true` | Enable or disable the entire rule family |
| `severity` | string | `null` | Override severity for all findings in this family |

Available rule families: `reentrancy`, `overflow`, `access_control`, `storage`.

## Example

```toml
[general]
exclude = ["**/test_*", "**/fixtures/*"]
jobs = 8

[output]
format = "sarif"
min_severity = "medium"

[rules.reentrancy]
enabled = true
severity = "critical"

[rules.overflow]
enabled = true

[rules.access_control]
enabled = true

[rules.storage]
enabled = false
```

## Precedence

CLI flags override config file values when both are specified:
- `--format` overrides `output.format`
- `--min-severity` overrides `output.min_severity`
- `--exclude` overrides `general.exclude`
- `--jobs` overrides `general.jobs`
- `--all` and `--rules` override `[rules.*]` enabled settings
