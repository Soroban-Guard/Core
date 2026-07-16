//! Reentrancy detection for Soroban contracts.
//!
//! In Soroban, execution is single-threaded, so reentrancy manifests as
//! *recursive invocation*: a contract makes a cross-contract call, and the
//! callee (or something further down the call chain) re-enters the original
//! contract before it has finished updating its own state. The classic
//! checks-effects-interactions violation — performing the external
//! *interaction* before applying the state *effects* — is the root cause.
//!
//! This module implements four rules over the parser's [`FnBodyAnalysis`],
//! comparing the source positions of storage accesses against cross-contract
//! calls:
//!
//! * **R-01** (Critical) — a storage write occurs *after* an external call.
//! * **R-02** (Medium)   — a read-only external call sits between a read and a
//!   later write of the same storage key (read-only reentrancy / stale read).
//! * **R-04** (High)     — two externally-calling functions share a storage key.
//! * **R-03** (Low)      — a function makes external calls but the contract has
//!   no reentrancy-guard storage key.
//!
//! [`FnBodyAnalysis`]: crate::parser::ast::FnBodyAnalysis

use std::collections::BTreeSet;

use super::AnalysisRule;
use crate::parser::ast::{Contract, ContractFn, SourcePos, StorageAccess};
use crate::report::finding::Finding;
use crate::report::severity::Severity;

pub struct ReentrancyDetector;

impl ReentrancyDetector {
    /// Format a [`SourcePos`] as a `line:col` location string. Falls back to the
    /// contract name when no position is available (line 0).
    fn location(contract: &Contract, pos: &SourcePos) -> String {
        if pos.line == 0 {
            contract.name.clone()
        } else {
            format!("{}:{}:{}", contract.name, pos.line, pos.column)
        }
    }

    /// Does the contract define any reentrancy-guard storage key? We look for a
    /// key whose name mentions `REENTRANCY`, `GUARD`, or `LOCK` (case-insensitive).
    fn has_guard(contract: &Contract) -> bool {
        contract.storage_keys.iter().any(|k| is_guard_key(&k.key))
    }

    /// R-01: for each cross-contract call, flag any storage write that happens
    /// *after* it (checks-effects-interactions violation). We report at most one
    /// finding per function, anchored at the earliest offending call, to avoid
    /// drowning the report in duplicates for a single hot function.
    fn check_state_after_call(contract: &Contract, func: &ContractFn, out: &mut Vec<Finding>) {
        let analysis = &func.body_analysis;
        // Earliest external call in the function, by source position.
        let earliest_call = analysis
            .cross_contract_calls
            .iter()
            .min_by(|a, b| a.position.cmp(&b.position));

        let Some(call) = earliest_call else {
            return;
        };

        let write_after = analysis
            .storage_writes
            .iter()
            .filter(|w| !is_guard_key(&w.key))
            .any(|w| w.position > call.position);

        if write_after {
            out.push(Finding::new(
                Severity::Critical,
                "R-01",
                format!(
                    "Function '{}' writes to storage after an external call — reentrancy risk",
                    func.name
                ),
                Self::location(contract, &call.position),
                "Move state updates before the external call, or use a reentrancy guard",
            ));
        }
    }

    /// R-02: read-only reentrancy. If a read-only external call sits between a
    /// storage read and a later write of the *same* key, a re-entering caller
    /// can observe the pre-write (stale) value. Flags the read-only call site.
    fn check_read_only_reentrancy(contract: &Contract, func: &ContractFn, out: &mut Vec<Finding>) {
        let analysis = &func.body_analysis;
        for call in analysis.cross_contract_calls.iter().filter(|c| c.read_only) {
            // A storage key that is read before the call and written after it.
            let stale_key = analysis
                .storage_reads
                .iter()
                .filter(|r| r.position < call.position)
                .find_map(|r| {
                    let written_after = analysis
                        .storage_writes
                        .iter()
                        .any(|w| w.key == r.key && w.position > call.position);
                    written_after.then(|| r.key.clone())
                });

            if let Some(key) = stale_key {
                out.push(Finding::new(
                    Severity::Medium,
                    "R-02",
                    format!(
                        "Function '{}' reads storage key '{}', makes a read-only external call, \
                         then updates that key — read-only reentrancy risk (stale read)",
                        func.name, key
                    ),
                    Self::location(contract, &call.position),
                    "Cache or re-validate the value after the call, or guard the function against reentrancy",
                ));
            }
        }
    }

    /// R-04: cross-function reentrancy. Collect the set of storage keys touched
    /// by each externally-calling function; any key shared by two or more such
    /// functions means a re-entrant call into a *sibling* function can corrupt
    /// shared state. Reported once per (function, shared-key) pair.
    fn check_cross_function(contract: &Contract, out: &mut Vec<Finding>) {
        let external_fns: Vec<(&ContractFn, BTreeSet<String>)> = contract
            .functions
            .iter()
            .filter(|f| !f.body_analysis.cross_contract_calls.is_empty())
            .map(|f| (f, storage_keys_of(f)))
            .collect();

        for (i, (func, keys)) in external_fns.iter().enumerate() {
            // Keys of this function that are also touched by some *other*
            // externally-calling function.
            let mut shared: Vec<&String> = keys
                .iter()
                .filter(|k| {
                    external_fns
                        .iter()
                        .enumerate()
                        .any(|(j, (_, other_keys))| j != i && other_keys.contains(*k))
                })
                .collect();
            shared.sort();

            for key in shared {
                let pos = func
                    .body_analysis
                    .cross_contract_calls
                    .iter()
                    .map(|c| &c.position)
                    .min()
                    .cloned()
                    .unwrap_or(SourcePos { line: 0, column: 0 });

                out.push(Finding::new(
                    Severity::High,
                    "R-04",
                    format!(
                        "Function '{}' makes an external call and shares storage key '{}' with \
                         another externally-calling function — cross-function reentrancy risk",
                        func.name, key
                    ),
                    Self::location(contract, &pos),
                    "Use a shared reentrancy guard across functions that touch this key",
                ));
            }
        }
    }

    /// R-03: no guard. If the contract has no reentrancy-guard storage key,
    /// report each function that makes external calls.
    fn check_missing_guard(contract: &Contract, func: &ContractFn, out: &mut Vec<Finding>) {
        if func.body_analysis.cross_contract_calls.is_empty() {
            return;
        }
        let pos = func
            .body_analysis
            .cross_contract_calls
            .iter()
            .map(|c| &c.position)
            .min()
            .cloned()
            .unwrap_or(SourcePos { line: 0, column: 0 });

        out.push(Finding::new(
            Severity::Low,
            "R-03",
            format!(
                "Function '{}' makes external calls but no reentrancy guard was found on the contract",
                func.name
            ),
            Self::location(contract, &pos),
            "Consider adding a reentrancy guard (e.g. a REENTRANCY_GUARD storage flag)",
        ));
    }
}

/// True when a storage key name looks like a reentrancy guard/lock flag. Writes
/// to such keys are the guard mechanism itself and must not be flagged as
/// "state updated after external call" (releasing a lock after the call is
/// correct usage).
fn is_guard_key(key: &str) -> bool {
    let upper = key.to_uppercase();
    upper.contains("REENTRANCY") || upper.contains("GUARD") || upper.contains("LOCK")
}

/// The union of storage keys read or written by a function.
fn storage_keys_of(func: &ContractFn) -> BTreeSet<String> {
    let a = &func.body_analysis;
    a.storage_reads
        .iter()
        .chain(a.storage_writes.iter())
        .map(|s: &StorageAccess| s.key.clone())
        .filter(|k| !is_guard_key(k))
        .collect()
}

impl AnalysisRule for ReentrancyDetector {
    fn id(&self) -> &'static str {
        "reentrancy"
    }

    fn name(&self) -> &'static str {
        "Reentrancy Detector"
    }

    fn description(&self) -> &'static str {
        "Detects checks-effects-interactions violations and reentrancy exposure in cross-contract calls"
    }

    fn analyze(&self, contract: &Contract) -> Vec<Finding> {
        let mut findings = Vec::new();
        let has_guard = Self::has_guard(contract);

        for func in &contract.functions {
            Self::check_state_after_call(contract, func, &mut findings);
            Self::check_read_only_reentrancy(contract, func, &mut findings);
            if !has_guard {
                Self::check_missing_guard(contract, func, &mut findings);
            }
        }

        Self::check_cross_function(contract, &mut findings);

        findings
    }
}


