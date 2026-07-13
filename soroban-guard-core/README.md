# Soroban Guard

**Static analysis and security auditing for Soroban smart contracts.**

## Features

- **Reentrancy detection** — Find state-after-call patterns (R-01 to R-04)
- **Overflow checking** — Detect unchecked arithmetic on `i128`/`u128` (O-01 to O-05)
- **Access control analysis** — Find missing authorization checks (A-01 to A-05)
- **Storage collision detection** — Prevent key collisions and confusion (S-01 to S-05)
- **Security scoring** — 0-100 score with severity breakdown and grades
- **Multiple output formats** — Human-readable, JSON, SARIF (GitHub code scanning)
- **CI/CD ready** — Exit code 1 on critical/high findings

## Quick Start

```bash
cargo install soroban-guard
soroban-guard path/to/contract.rs
```

Or build from source:

```bash
git clone https://github.com/Soroban-Guard/Core.git
cd Core
cargo build --release
./target/release/soroban-guard-core path/to/contract.rs
```

## Example Output

```
Soroban Guard Report
====================

Security Score: 72/100 (Grade B)
Critical: 1 | High: 2 | Medium: 3 | Low: 5 | Info: 2
```

## Documentation

- [Getting Started](docs/getting-started.md)
- [CLI Usage](docs/usage.md)
- [Configuration](docs/configuration.md)
- [Integrations](docs/integrations.md) (GitHub Actions, VS Code, CI/CD)

### Rule Documentation

- [Reentrancy Rules](docs/rules/reentrancy.md) — R-01 to R-04
- [Overflow Rules](docs/rules/overflow.md) — O-01 to O-05
- [Access Control Rules](docs/rules/access-control.md) — A-01 to A-05
- [Storage Rules](docs/rules/storage.md) — S-01 to S-05

### Development

- [Contributing Guide](docs/contributing.md)
- [Architecture Overview](docs/architecture.md)
- [Changelog](docs/changelog.md)

## Running Tests

```bash
cargo test
cargo bench
```

## License

MIT or Apache-2.0
