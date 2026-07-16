# Changelog

All notable changes to Soroban Guard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## 0.1.0 (Unreleased)

### Added
- Reentrancy detection (R-01 to R-04): checks-effects-interactions violations, read-only reentrancy, missing guards, and cross-function reentrancy.
- Integer overflow/underflow checking (O-01 to O-05): unchecked arithmetic, threshold comparison, division-by-zero, loop accumulation, and truncating casts.
- Access control analysis (A-01 to A-05): missing authorization, admin function exposure, weak delegation patterns, public callable functions, and hardcoded addresses.
- Storage collision detection (S-01 to S-05): short keys, generic key names, type mismatches, storage tier conflicts, and missing version keys.
- Security scoring engine: 0–100 score with letter grades (A–F), severity breakdown, and top-issue triage.
- CLI interface with human-readable, JSON, and SARIF output formats.
- TOML configuration file with rule-level enable/disable and severity overrides.
- Parallel file analysis with configurable worker count (`--jobs`).
- Rule filtering by finding ID (`--rules`) and minimum severity (`--min-severity`).
- Glob-based file exclusion (`--exclude`).
- SARIF output for GitHub Code Scanning integration.
- Comprehensive test suite: unit, integration, edge case, regression, and property-based tests.
- Performance benchmarks using Criterion.
- GitHub Actions CI workflow with build, test, clippy, and format checks.
- Full documentation: getting started, CLI usage, configuration, architecture, and rule references.
