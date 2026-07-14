# Architecture

## Overview

Soroban Guard is a static analysis tool for Soroban smart contracts written in Rust. It parses contract source code, runs multiple analysis rules, and produces a security report with scoring.

## Data flow

```
Source file
  → ContractParser::parse_source()
    → syn-based visitor → Contract AST
      → AnalysisEngine with 4 rules
        → Each rule's analyze(&Contract) → Vec<Finding>
          → Scoring engine → SecurityScore
            → Report
              → ConsolidatedReport (JSON/SARIF/Human)
```

## Core components

### Parser (`src/parser/`)

Uses `syn` to parse Rust source files and walk the AST looking for Soroban-specific patterns. Produces a `Contract` struct with parsed functions, storage operations, auth checks, and external calls.

### Analysis Engine (`src/analysis/`)

Registry of `AnalysisRule` implementations. Each rule receives a `&Contract` and returns `Vec<Finding>`. Rules are independent and their findings are concatenated.

### Report (`src/report/`)

Data structures for findings, severity levels, and output formatting. Three output formats: human (colored terminal), JSON (structured data), SARIF (GitHub code scanning format).

### Scoring (`src/scoring/`)

Computes a 0-100 security score based on finding severity counts with bonus points for reentrancy guards and version keys.

## Rule execution order

1. ReentrancyDetector
2. OverflowChecker
3. AccessControlDetector
4. StorageCollisionDetector
