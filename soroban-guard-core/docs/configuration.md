# Configuration File

Soroban Guard supports a TOML configuration file for persistent settings.

## Default location

The config file can be placed anywhere and loaded with `--config <path>`.

## Format

```toml
[general]
min_severity = "medium"
jobs = 4
exclude = ["**/test_*", "**/mocks/*"]

[output]
format = "json"
min_severity = "high"
```

## Sections

### `[general]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `min_severity` | string | `"low"` | Minimum severity: `critical`, `high`, `medium`, `low`, `info` |
| `jobs` | integer | `4` | Number of parallel workers |
| `exclude` | array | `[]` | Glob patterns to exclude from scanning |

### `[output]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `format` | string | `"human"` | Output format: `human`, `json`, `sarif` |
| `min_severity` | string | `"low"` | Override minimum severity for output filtering |

## Example

```toml
[general]
min_severity = "medium"
jobs = 8
exclude = ["**/test_*", "**/fixtures/*"]

[output]
format = "sarif"
```

Config options are overridden by CLI flags when both are specified.
