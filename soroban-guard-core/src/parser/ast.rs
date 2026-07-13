use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Contract {
    pub name: String,
    pub functions: Vec<ContractFn>,
    pub storage_keys: Vec<StorageAccess>,
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContractFn {
    pub name: String,
    pub args: Vec<FnArg>,
    pub return_type: String,
    pub visibility: FnVisibility,
    pub attributes: Vec<String>,
    pub is_init: bool,
    pub body_analysis: FnBodyAnalysis,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FnArg {
    pub name: String,
    pub type_name: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FnVisibility {
    Public,
    Private,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FnBodyAnalysis {
    pub cross_contract_calls: Vec<CrossContractCall>,
    pub storage_writes: Vec<StorageAccess>,
    pub storage_reads: Vec<StorageAccess>,
    pub auth_checks: Vec<AuthCheck>,
    pub arithmetic_ops: Vec<ArithExpr>,
    pub casts: Vec<CastExpr>,
    pub has_loops: bool,
    pub has_unsafe: bool,
    pub calls_external: bool,
    /// Hardcoded address string literals (e.g. `Address::from_str("G...")`).
    /// Each entry is the string value and its source position.
    pub hardcoded_address_strs: Vec<(String, SourcePos)>,
}

impl FnBodyAnalysis {
    pub fn new() -> Self {
        FnBodyAnalysis {
            cross_contract_calls: Vec::new(),
            storage_writes: Vec::new(),
            storage_reads: Vec::new(),
            auth_checks: Vec::new(),
            arithmetic_ops: Vec::new(),
            casts: Vec::new(),
            has_loops: false,
            has_unsafe: false,
            calls_external: false,
            hardcoded_address_strs: Vec::new(),
        }
    }
}

impl FnBodyAnalysis {
    pub fn has_storage_writes(&self) -> bool {
        !self.storage_writes.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CrossContractCall {
    pub target: String,
    pub function: String,
    pub args_count: usize,
    pub position: SourcePos,
    /// True when the call was made via `invoke_contract_read_only` (a call that
    /// cannot mutate the callee's state but can still surface stale reads — see
    /// read-only reentrancy, rule R-02).
    pub read_only: bool,
}

/// A source position. Ordered lexicographically by `(line, column)` so that
/// analyses can compare whether one construct occurs before another in the
/// function body (used by the reentrancy detector to order storage writes
/// relative to external calls).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SourcePos {
    pub line: usize,
    pub column: usize,
}

/// A binary arithmetic operator recorded by the parser for the overflow checker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArithOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Shl,
    Shr,
}

impl ArithOp {
    /// The source symbol for the operator (e.g. `Add` -> `"+"`).
    pub fn symbol(&self) -> &'static str {
        match self {
            ArithOp::Add => "+",
            ArithOp::Sub => "-",
            ArithOp::Mul => "*",
            ArithOp::Div => "/",
            ArithOp::Mod => "%",
            ArithOp::Shl => "<<",
            ArithOp::Shr => ">>",
        }
    }

    /// The `checked_*` method name that would make this operation safe
    /// (e.g. `Add` -> `"checked_add"`).
    pub fn checked_method(&self) -> &'static str {
        match self {
            ArithOp::Add => "checked_add",
            ArithOp::Sub => "checked_sub",
            ArithOp::Mul => "checked_mul",
            ArithOp::Div => "checked_div",
            ArithOp::Mod => "checked_rem",
            ArithOp::Shl => "checked_shl",
            ArithOp::Shr => "checked_shr",
        }
    }
}

/// A binary arithmetic expression discovered in a function body.
///
/// Because the parser is purely syntactic (no type inference), `return_type` is
/// a best-effort label — `"i128"`/`"u128"` when at least one operand is a known
/// financial identifier (a function argument or `let` binding annotated with an
/// integer type), otherwise `"unknown"`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArithExpr {
    pub op: ArithOp,
    pub left: String,
    pub right: String,
    pub return_type: String,
    /// True when the operation is a `checked_*`/`wrapping_*`/`overflowing_*`/
    /// `saturating_*` method call rather than a bare operator.
    pub is_checked: bool,
    /// True when the divisor (right operand) is provably a nonzero integer
    /// literal, so a division-by-zero cannot occur.
    pub divisor_checked: bool,
    /// True when this arithmetic appears as an operand of a comparison (e.g.
    /// `if balance + amount > max`) — the O-02 "compared against a threshold"
    /// pattern.
    pub compared: bool,
    /// True when the expression is a compound assignment (`+=`, `-=`, ...).
    pub is_compound: bool,
    /// True when the expression is inside a loop body.
    pub in_loop: bool,
    /// True when the enclosing loop has a dynamic (non-small-constant) bound.
    pub dynamic_loop: bool,
    pub position: SourcePos,
}

/// A numeric cast (`expr as T`) discovered in a function body. Only recorded
/// when the source references a known financial identifier and the target is a
/// narrower integer type (potential truncation).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CastExpr {
    pub from: String,
    pub from_type: String,
    pub to: String,
    pub position: SourcePos,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum StorageKeyType {
    Symbol,
    Bytes,
    String,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum StorageAccessType {
    Read,
    Write,
    Delete,
    Check,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum StorageType {
    Instance,
    Temporary,
    Persistent,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StorageAccess {
    pub key: String,
    pub key_type: StorageKeyType,
    pub access_type: StorageAccessType,
    pub storage_type: StorageType,
    /// Location of the access in the source. Used to order reads/writes relative
    /// to cross-contract calls when detecting reentrancy.
    pub position: SourcePos,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthCheck {
    pub kind: AuthKind,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AuthKind {
    RequireAuth,
    RequireAuthForArgs,
}
