# Configuration File

Soroban Guard supports a TOML configuration file for persistent settings.

## Default location

The config file can be placed anywhere and loaded with `--config <path>`.

## Format

```toml
[general]
exclude = ["**/test_*", "**/mocks/*"]

[output]
format = "json"
min_severity = "high"
```

## Sections

### `[general]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `exclude` | array | `[]` | Glob patterns to exclude from scanning |

### `[output]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `format` | string | `"human"` | Output format: `human`, `json`, `sarif` |
| `min_severity` | string | `"low"` | Override minimum severity for output filtering |

## Example

```toml
[general]
exclude = ["**/test_*", "**/fixtures/*"]

[output]
format = "sarif"
min_severity = "medium"
```

Config options are overridden by CLI flags when both are specified.
