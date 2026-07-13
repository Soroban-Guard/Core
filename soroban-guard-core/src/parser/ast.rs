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
    pub has_loops: bool,
    pub has_unsafe: bool,
    pub calls_external: bool,
}

impl FnBodyAnalysis {
    pub fn new() -> Self {
        FnBodyAnalysis {
            cross_contract_calls: Vec::new(),
            storage_writes: Vec::new(),
            storage_reads: Vec::new(),
            auth_checks: Vec::new(),
            has_loops: false,
            has_unsafe: false,
            calls_external: false,
        }
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
