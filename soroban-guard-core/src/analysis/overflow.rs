//! Integer overflow / underflow detection for Soroban contracts.
//!
//! Soroban contracts compile to WASM and run in release mode, where Rust's
//! default arithmetic **wraps silently** on overflow (two's complement) rather
//! than panicking. For financial contracts using `i128`/`u128` balances this is
//! a real hazard: `balance - amount` underflows to a huge positive number,
//! `balance + amount` overflows past `i128::MAX`, and so on.
//!
//! This detector works over the parser's syntactic [`ArithExpr`]/[`CastExpr`]
//! records. Because the parser has no type inference, "financial" operands are
//! identified heuristically — an operand references an identifier annotated
//! `i128`/`u128` (a function argument or `let` binding). This is best-effort:
//! arithmetic on an inferred-typed local (no annotation) is not flagged. See
//! the module-level notes on each rule.
//!
//! Rules:
//! * **O-01** (High)   — unchecked `+`/`-`/`*` on a financial type. A
//!   loop-counter-style compound `+= 1` is demoted to Medium.
//! * **O-02** (Medium) — arithmetic used directly as an operand of a comparison
//!   ("checked against a threshold"); suggests `checked_*` for clarity. Mutually
//!   exclusive with O-01 on the same expression.
//! * **O-03** (Medium) — division/remainder by a non-literal (or literal-zero)
//!   divisor: possible division by zero.
//! * **O-04** (High)   — compound accumulation (`sum += x`) inside a
//!   dynamic-bound loop.
//! * **O-05** (Low)    — a cast that truncates a financial value to a narrower
//!   integer type.
//!
//! [`ArithExpr`]: crate::parser::ast::ArithExpr
//! [`CastExpr`]: crate::parser::ast::CastExpr

use super::{AnalysisRule, Analyzer};
use crate::parser::ast::{ArithExpr, ArithOp, Contract, ContractFn, SourcePos};
use crate::parser::ContractParser;
use crate::report::finding::Finding;
use crate::report::severity::Severity;

pub struct OverflowChecker;

impl OverflowChecker {
    /// Format a [`SourcePos`] as a `Contract:line:col` location string.
    fn location(contract: &Contract, pos: &SourcePos) -> String {
        if pos.line == 0 {
            contract.name.clone()
        } else {
            format!("{}:{}:{}", contract.name, pos.line, pos.column)
        }
    }

    /// True for a compound `+= 1` / `-= 1` — the shape of a manual loop counter,
    /// which the spec treats more leniently (Medium, not High) under O-01.
    fn is_unit_counter(e: &ArithExpr) -> bool {
        e.is_compound
            && matches!(e.op, ArithOp::Add | ArithOp::Sub)
            && (e.right == "1" || e.right == "1i128" || e.right == "1u128")
    }

    /// True for the additive/multiplicative operators O-01 cares about.
    fn is_overflowing_op(op: ArithOp) -> bool {
        matches!(op, ArithOp::Add | ArithOp::Sub | ArithOp::Mul)
    }

    fn analyze_fn(contract: &Contract, func: &ContractFn, out: &mut Vec<Finding>) {
        for e in &func.body_analysis.arithmetic_ops {
            Self::check_o04(contract, func, e, out);
            Self::check_o01_o02(contract, func, e, out);
            Self::check_o03(contract, func, e, out);
        }

        for c in &func.body_analysis.casts {
            out.push(Finding::new(
                Severity::Low,
                "O-05",
                format!(
                    "Function '{}' casts financial value '{}' to '{}' — truncates high bits",
                    func.name, c.from, c.to
                ),
                Self::location(contract, &c.position),
                format!(
                    "Guard the range before casting to {}, or keep the value as i128/u128",
                    c.to
                ),
            ));
        }
    }

    /// O-04: accumulation inside a dynamic-bound loop (`sum += x`). Reported
    /// before O-01 and, when it fires, suppresses O-01/O-02 for the same
    /// expression (handled in `check_o01_o02` via the same predicate).
    fn check_o04(contract: &Contract, func: &ContractFn, e: &ArithExpr, out: &mut Vec<Finding>) {
        if Self::is_loop_accumulation(e) {
            out.push(Finding::new(
                Severity::High,
                "O-04",
                format!(
                    "Function '{}' accumulates '{} {} {}' inside a dynamically-bounded loop — \
                     iterations may overflow",
                    func.name,
                    e.left,
                    e.op.symbol(),
                    e.right
                ),
                Self::location(contract, &e.position),
                format!(
                    "Use {} inside the loop and handle the overflow, or bound the iteration count",
                    e.op.checked_method()
                ),
            ));
        }
    }

    /// True when the expression is unchecked accumulation inside a dynamic loop.
    fn is_loop_accumulation(e: &ArithExpr) -> bool {
        !e.is_checked
            && e.in_loop
            && e.dynamic_loop
            && e.is_compound
            && Self::is_overflowing_op(e.op)
            && !Self::is_unit_counter(e)
    }

    /// O-01 (unchecked arithmetic) and O-02 (arithmetic compared to a
    /// threshold). These are mutually exclusive on a single expression, and
    /// neither fires when O-04 already claimed it.
    fn check_o01_o02(
        contract: &Contract,
        func: &ContractFn,
        e: &ArithExpr,
        out: &mut Vec<Finding>,
    ) {
        if e.is_checked
            || !Self::is_overflowing_op(e.op)
            || e.return_type != "i128"
            || Self::is_loop_accumulation(e)
        {
            return;
        }

        if e.compared {
            // O-02: `balance + amount` appears inside a comparison — partially
            // safe, but clearer with checked arithmetic.
            out.push(Finding::new(
                Severity::Medium,
                "O-02",
                format!(
                    "Function '{}' compares the result of '{} {} {}' against a threshold — \
                     partially safe",
                    func.name,
                    e.left,
                    e.op.symbol(),
                    e.right
                ),
                Self::location(contract, &e.position),
                format!(
                    "Use {} for an explicit, checked result",
                    e.op.checked_method()
                ),
            ));
            return;
        }

        // O-01: unchecked arithmetic on a financial type. A manual unit counter
        // (`i += 1`) is demoted to Medium.
        let severity = if Self::is_unit_counter(e) {
            Severity::Medium
        } else {
            Severity::High
        };
        out.push(Finding::new(
            severity,
            "O-01",
            format!(
                "Function '{}' performs unchecked '{} {} {}' on a financial type — possible \
                 overflow/underflow",
                func.name,
                e.left,
                e.op.symbol(),
                e.right
            ),
            Self::location(contract, &e.position),
            format!(
                "Use {}.{}({}) instead of the bare operator",
                e.left,
                e.op.checked_method(),
                e.right
            ),
        ));
    }

    /// O-03: division or remainder by a divisor that is not a provably-nonzero
    /// literal.
    fn check_o03(contract: &Contract, func: &ContractFn, e: &ArithExpr, out: &mut Vec<Finding>) {
        if e.is_checked || !matches!(e.op, ArithOp::Div | ArithOp::Mod) || e.divisor_checked {
            return;
        }
        out.push(Finding::new(
            Severity::Medium,
            "O-03",
            format!(
                "Function '{}' divides by unchecked divisor '{}' — possible division by zero",
                func.name, e.right
            ),
            Self::location(contract, &e.position),
            format!(
                "Check '{}' for zero before dividing, or use {}",
                e.right,
                e.op.checked_method()
            ),
        ));
    }
}

impl AnalysisRule for OverflowChecker {
    fn id(&self) -> &'static str {
        "overflow"
    }

    fn name(&self) -> &'static str {
        "Integer Overflow Checker"
    }

    fn description(&self) -> &'static str {
        "Detects unchecked integer arithmetic, division-by-zero, loop accumulation, and truncating casts on financial types"
    }

    fn analyze(&self, contract: &Contract) -> Vec<Finding> {
        let mut findings = Vec::new();
        for func in &contract.functions {
            Self::analyze_fn(contract, func, &mut findings);
        }
        findings
    }
}

/// Bridge to the source-level [`Analyzer`] pipeline used by the CLI. Files that
/// fail to parse yield no findings rather than aborting the run.
impl Analyzer for OverflowChecker {
    fn analyze(&self, source: &str, _file_path: &str) -> Vec<Finding> {
        let parser = ContractParser::new();
        match parser.parse_source(source) {
            Ok(contract) => AnalysisRule::analyze(self, &contract),
            Err(_) => Vec::new(),
        }
    }

    fn name(&self) -> &'static str {
        "overflow"
    }
}
