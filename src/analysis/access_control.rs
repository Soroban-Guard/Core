use super::AnalysisRule;
use crate::parser::ast::{AuthKind, Contract, ContractFn, FnBodyAnalysis, FnVisibility, SourcePos};
use crate::report::finding::Finding;
use crate::report::severity::Severity;

const ADMIN_FN_NAMES: &[&str] = &[
    "admin",
    "owner",
    "manager",
    "set_",
    "update_",
    "configure",
    "upgrade",
    "pause",
    "emergency",
];

pub struct AccessControlDetector;

impl AccessControlDetector {
    fn location(contract: &Contract, pos: &SourcePos) -> String {
        if pos.line == 0 {
            contract.name.clone()
        } else {
            format!("{}:{}:{}", contract.name, pos.line, pos.column)
        }
    }

    fn has_auth(analysis: &FnBodyAnalysis) -> bool {
        !analysis.auth_checks.is_empty()
    }

    fn is_admin_fn(name: &str) -> bool {
        ADMIN_FN_NAMES.iter().any(|n| name.contains(n))
    }

    fn has_address_param(func: &ContractFn) -> bool {
        func.args.iter().any(|a| a.type_name == "Address")
    }

    fn is_constructor(func: &ContractFn) -> bool {
        func.name == "__constructor" || func.name.contains("init")
    }

    // A-01: Missing authorization on state-mutating function
    fn check_a01(contract: &Contract, func: &ContractFn, out: &mut Vec<Finding>) {
        if !func.body_analysis.has_storage_writes() || Self::has_auth(&func.body_analysis) {
            return;
        }

        let severity = if Self::is_admin_fn(&func.name) {
            Severity::Critical
        } else {
            Severity::High
        };
        let pos = &func.body_analysis.storage_writes[0].position;

        out.push(Finding::new(
            severity,
            "A-01",
            format!(
                "Function '{}' modifies state without authorization check",
                func.name
            ),
            Self::location(contract, pos),
            "Add require_auth() with the appropriate Address at the start of this function",
        ));
    }

    // A-02: Missing authorization on admin function
    fn check_a02(contract: &Contract, func: &ContractFn, out: &mut Vec<Finding>) {
        if !Self::is_admin_fn(&func.name) || Self::has_auth(&func.body_analysis) {
            return;
        }

        let pos = func
            .body_analysis
            .storage_writes
            .first()
            .map(|w| &w.position)
            .unwrap_or(&SourcePos { line: 0, column: 0 });

        out.push(Finding::new(
            Severity::High,
            "A-02",
            format!(
                "Admin function '{}' is missing authorization check",
                func.name
            ),
            Self::location(contract, pos),
            "Add require_auth() with the admin Address at the start of this function",
        ));
    }

    // A-03: Weak authorization — require_auth_for_args without Address params
    fn check_a03(contract: &Contract, func: &ContractFn, out: &mut Vec<Finding>) {
        if !Self::has_address_param(func) {
            return;
        }

        let has_require_auth = func
            .body_analysis
            .auth_checks
            .iter()
            .any(|a| a.kind == AuthKind::RequireAuth);

        let has_require_auth_for_args = func
            .body_analysis
            .auth_checks
            .iter()
            .any(|a| a.kind == AuthKind::RequireAuthForArgs);

        if has_require_auth_for_args && !has_require_auth {
            out.push(Finding::new(
                Severity::Medium,
                "A-03",
                format!(
                    "Function '{}' uses require_auth_for_args but does not authenticate Address parameters directly",
                    func.name
                ),
                Self::location(contract, &SourcePos { line: 0, column: 0 }),
                "Pass the Address parameter(s) to require_auth() or include them in require_auth_for_args",
            ));
        }
    }

    // A-04: "Anybody can call" — pub function without auth
    fn check_a04(contract: &Contract, func: &ContractFn, out: &mut Vec<Finding>) {
        let has_auth = Self::has_auth(&func.body_analysis);
        let has_storage_write = func.body_analysis.has_storage_writes();
        let has_address = Self::has_address_param(func);

        // Public function, no Address params, no auth — "anybody can call"
        if matches!(func.visibility, FnVisibility::Public) && !has_address && !has_auth {
            let (severity, suffix) = if has_storage_write {
                (Severity::High, " and modifies state")
            } else {
                (Severity::Info, "")
            };
            out.push(Finding::new(
                severity,
                "A-04",
                format!(
                    "Public function '{}' has no authorization check{} \u{2014} anybody can call",
                    func.name, suffix,
                ),
                Self::location(contract, &SourcePos { line: 0, column: 0 }),
                "Add require_auth() with the appropriate Address if this function should be restricted",
            ));
        }

        // Has Address params but no auth and writes storage
        if has_address && !has_auth && has_storage_write {
            let addr_param = func.args.iter().find(|a| a.type_name == "Address").unwrap();
            out.push(Finding::new(
                Severity::Medium,
                "A-04",
                format!(
                    "Function '{}' takes Address parameter '{}' but doesn't authenticate it",
                    func.name, addr_param.name,
                ),
                Self::location(contract, &SourcePos { line: 0, column: 0 }),
                "Use require_auth() with the Address parameter to ensure only that user can call",
            ));
        }
    }

    // A-05: Hardcoded admin address
    fn check_a05(contract: &Contract, out: &mut Vec<Finding>) {
        for func in &contract.functions {
            for (addr_str, pos) in &func.body_analysis.hardcoded_address_strs {
                out.push(Finding::new(
                    Severity::Medium,
                    "A-05",
                    format!(
                        "Hardcoded address '{}' in function '{}' \u{2014} consider making it configurable",
                        addr_str, func.name,
                    ),
                    Self::location(contract, pos),
                    "Use a configurable storage-based admin address instead of hardcoding",
                ));
            }
        }
    }

    fn should_skip(func: &ContractFn) -> bool {
        Self::is_constructor(func)
    }
}

impl AnalysisRule for AccessControlDetector {
    fn id(&self) -> &'static str {
        "access_control"
    }

    fn name(&self) -> &'static str {
        "Access Control Detector"
    }

    fn description(&self) -> &'static str {
        "Detects missing or weak authorization checks in contract functions"
    }

    fn analyze(&self, contract: &Contract) -> Vec<Finding> {
        let mut findings = Vec::new();

        for func in &contract.functions {
            if Self::should_skip(func) {
                continue;
            }

            Self::check_a01(contract, func, &mut findings);
            Self::check_a02(contract, func, &mut findings);
            Self::check_a03(contract, func, &mut findings);
            Self::check_a04(contract, func, &mut findings);
        }

        Self::check_a05(contract, &mut findings);

        findings
    }
}
