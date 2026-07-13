use syn::visit::Visit;

use crate::parser::ast::{
    ArithExpr, ArithOp, AuthCheck, AuthKind, CastExpr, Contract, ContractFn, CrossContractCall,
    FnArg, FnBodyAnalysis, FnVisibility, SourcePos, StorageAccess, StorageAccessType,
    StorageKeyType,
};
use crate::parser::patterns;

fn type_to_string(ty: &syn::Type) -> String {
    quote::quote!(#ty).to_string()
}

fn expr_to_string(expr: &syn::Expr) -> String {
    match expr {
        syn::Expr::Path(p) => p.path.segments.iter().map(|s| s.ident.to_string()).collect::<Vec<_>>().join("::"),
        syn::Expr::Lit(l) => quote::quote!(#l).to_string(),
        other => quote::quote!(#other).to_string(),
    }
}

fn extract_method_chain(expr: &syn::Expr) -> Vec<String> {
    match expr {
        syn::Expr::MethodCall(mc) => {
            let mut chain = extract_method_chain(&mc.receiver);
            chain.push(mc.method.to_string());
            chain
        }
        syn::Expr::Path(p) => p
            .path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect(),
        _ => {
            let s = expr_to_string(expr);
            if s.is_empty() { vec![] } else { vec![s] }
        }
    }
}

fn extract_fn_args(sig: &syn::Signature) -> Vec<FnArg> {
    sig.inputs
        .iter()
        .filter_map(|arg| match arg {
            syn::FnArg::Typed(pat_type) => {
                let name = if let syn::Pat::Ident(pat_ident) = &*pat_type.pat {
                    pat_ident.ident.to_string()
                } else {
                    "_".to_string()
                };
                let type_name = type_to_string(&pat_type.ty);
                Some(FnArg { name, type_name })
            }
            syn::FnArg::Receiver(_) => None,
        })
        .collect()
}

fn extract_return_type(sig: &syn::Signature) -> String {
    match &sig.output {
        syn::ReturnType::Default => "()".to_string(),
        syn::ReturnType::Type(_, ty) => type_to_string(ty),
    }
}

fn extract_visibility(vis: &syn::Visibility) -> FnVisibility {
    match vis {
        syn::Visibility::Public(_) => FnVisibility::Public,
        _ => FnVisibility::Private,
    }
}

fn extract_attr_names(attrs: &[syn::Attribute]) -> Vec<String> {
    attrs
        .iter()
        .map(|a| a.path().segments.iter().map(|s| s.ident.to_string()).collect::<Vec<_>>().join("::"))
        .filter(|n| n != "contractimpl" && n != "contract")
        .collect()
}

fn extract_target_from_expr(expr: &syn::Expr) -> String {
    if let Some(s) = patterns::extract_string_literal(expr) {
        return s;
    }
    if let Some(s) = patterns::extract_symbol_name(expr) {
        return format!("Symbol({:?})", s);
    }
    expr_to_string(patterns::unwrap_expr(expr))
}

/// Extract the bare invoked-function name from a cross-contract call argument.
/// Unlike `extract_target_from_expr`, a `Symbol::new(&env, "transfer")` yields
/// the plain `transfer` rather than a `Symbol("transfer")` wrapper.
fn extract_invoked_fn_name(expr: &syn::Expr) -> String {
    patterns::extract_symbol_name(expr)
        .or_else(|| patterns::extract_string_literal(expr))
        .unwrap_or_else(|| expr_to_string(expr))
}

fn extract_key_from_expr(expr: &syn::Expr) -> (String, StorageKeyType) {
    if let Some(s) = patterns::extract_string_literal(expr) {
        return (s, StorageKeyType::String);
    }
    if let Some(s) = patterns::extract_symbol_name(expr) {
        return (s, StorageKeyType::Symbol);
    }
    let expr_str = expr_to_string(expr);
    if expr_str.starts_with("Bytes") {
        return (expr_str, StorageKeyType::Bytes);
    }
    (expr_str.clone(), StorageKeyType::Other(expr_str))
}

/// Count the number of arguments packed into a cross-contract call's argument
/// container. Soroban call sites pass these as a tuple `(&a, &b)`, an array
/// `[a, b]`, or a `vec![...]` macro; anything else counts as a single argument.
fn count_call_args(expr: &syn::Expr) -> usize {
    match patterns::unwrap_expr(expr) {
        syn::Expr::Tuple(t) => t.elems.len(),
        syn::Expr::Array(a) => a.elems.len(),
        syn::Expr::Macro(m) if m.mac.path.is_ident("vec") => {
            m.mac
                .parse_body_with(
                    syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated,
                )
                .map(|args| args.len())
                .unwrap_or(1)
        }
        _ => 1,
    }
}

/// True when a type string names a financial integer type (`i128`/`u128`).
/// These are the types Soroban contracts use for balances and amounts, where
/// silent wraparound in release builds is a security concern.
fn is_financial_type(ty: &str) -> bool {
    let t = ty.replace(' ', "");
    t == "i128" || t == "u128"
}

/// Extract the last path segment of a type string as a simple identifier,
/// stripping generics and leading reference markers (`&i128` -> `i128`).
fn simple_type_name(ty: &str) -> String {
    ty.trim_start_matches('&')
        .trim()
        .split('<')
        .next()
        .unwrap_or("")
        .split("::")
        .last()
        .unwrap_or("")
        .replace(' ', "")
}

/// Map a syn binary operator to our [`ArithOp`], returning `None` for
/// non-arithmetic operators (comparison, logical, etc.). Handles both plain
/// (`a + b`) and compound-assignment (`a += b`) forms.
fn arith_op_of(op: &syn::BinOp) -> Option<ArithOp> {
    use syn::BinOp;
    match op {
        BinOp::Add(_) | BinOp::AddAssign(_) => Some(ArithOp::Add),
        BinOp::Sub(_) | BinOp::SubAssign(_) => Some(ArithOp::Sub),
        BinOp::Mul(_) | BinOp::MulAssign(_) => Some(ArithOp::Mul),
        BinOp::Div(_) | BinOp::DivAssign(_) => Some(ArithOp::Div),
        BinOp::Rem(_) | BinOp::RemAssign(_) => Some(ArithOp::Mod),
        BinOp::Shl(_) | BinOp::ShlAssign(_) => Some(ArithOp::Shl),
        BinOp::Shr(_) | BinOp::ShrAssign(_) => Some(ArithOp::Shr),
        _ => None,
    }
}

/// True when the operator is a compound assignment (`+=`, `-=`, ...).
fn is_compound_assign(op: &syn::BinOp) -> bool {
    use syn::BinOp;
    matches!(
        op,
        BinOp::AddAssign(_)
            | BinOp::SubAssign(_)
            | BinOp::MulAssign(_)
            | BinOp::DivAssign(_)
            | BinOp::RemAssign(_)
            | BinOp::ShlAssign(_)
            | BinOp::ShrAssign(_)
    )
}

/// True when the operator is a comparison (`>`, `>=`, `<`, `<=`, `==`, `!=`).
/// Arithmetic nested inside a comparison is being checked against a threshold.
fn is_comparison(op: &syn::BinOp) -> bool {
    use syn::BinOp;
    matches!(
        op,
        BinOp::Gt(_) | BinOp::Ge(_) | BinOp::Lt(_) | BinOp::Le(_) | BinOp::Eq(_) | BinOp::Ne(_)
    )
}

/// A short source rendering of an operand expression, used only for messages
/// and suggestions.
fn render_operand(expr: &syn::Expr) -> String {
    quote::quote!(#expr).to_string().replace(' ', "")
}

/// True when the expression is a nonzero integer literal — a provably safe
/// divisor. `x / 100` cannot divide by zero; `x / n` (a variable) might.
fn is_nonzero_int_literal(expr: &syn::Expr) -> bool {
    if let syn::Expr::Lit(lit) = patterns::unwrap_expr(expr) {
        if let syn::Lit::Int(n) = &lit.lit {
            return n.base10_parse::<u128>().map(|v| v != 0).unwrap_or(false);
        }
    }
    false
}

/// A narrower integer type than i128/u128 — casting a financial value to one of
/// these truncates high bits. `usize`/`isize` are included as they are 32/64-bit
/// on WASM targets.
fn is_narrowing_int_type(ty: &str) -> bool {
    matches!(
        simple_type_name(ty).as_str(),
        "i8" | "i16" | "i32" | "i64" | "u8" | "u16" | "u32" | "u64" | "usize" | "isize"
    )
}

/// True when a `for`-loop iterator expression is a range `a..b` (or `a..=b`)
/// whose upper bound is a small integer literal (< 100). Such loops run a
/// bounded, statically-small number of times, so accumulation overflow is
/// unlikely. Everything else (variable bounds, large literals, iterators over
/// collections) is treated as dynamic.
fn is_small_constant_range(expr: &syn::Expr) -> bool {
    if let syn::Expr::Range(range) = patterns::unwrap_expr(expr) {
        if let Some(end) = &range.end {
            if let syn::Expr::Lit(lit) = patterns::unwrap_expr(end) {
                if let syn::Lit::Int(n) = &lit.lit {
                    return n.base10_parse::<u128>().map(|v| v < 100).unwrap_or(false);
                }
            }
        }
    }
    false
}

/// Collect the bare identifier names referenced anywhere in an expression.
/// Used to decide whether an arithmetic operand touches a financial value.
fn referenced_idents(expr: &syn::Expr) -> Vec<String> {
    struct IdentCollector(Vec<String>);
    impl<'ast> Visit<'ast> for IdentCollector {
        fn visit_expr_path(&mut self, p: &'ast syn::ExprPath) {
            if let Some(ident) = p.path.get_ident() {
                self.0.push(ident.to_string());
            }
        }
    }
    let mut c = IdentCollector(Vec::new());
    c.visit_expr(expr);
    c.0
}

pub fn parse_contract(source: &str) -> Result<Contract, String> {
    let syntax_tree: syn::File = syn::parse_file(source).map_err(|e| e.to_string())?;
    let mut visitor = ContractVisitor::new();
    visitor.visit_file(&syntax_tree);
    visitor.finalize()
}

pub struct ContractVisitor {
    contract_name: String,
    functions: Vec<ContractFn>,
    in_contractimpl: bool,
    current_fn_idx: Option<usize>,
    /// Identifiers known (syntactically) to hold a financial integer type
    /// (`i128`/`u128`), seeded from the current function's arguments and
    /// type-annotated `let` bindings. Reset when entering each function.
    financial_idents: std::collections::HashSet<String>,
    /// Depth of enclosing comparison expressions. When > 0, arithmetic is being
    /// compared against something (the O-02 threshold pattern).
    compare_depth: usize,
    /// Stack of enclosing loops; each entry records whether that loop has a
    /// dynamic (non-small-constant) bound. Empty when not inside a loop.
    loop_stack: Vec<bool>,
}

impl ContractVisitor {
    pub fn new() -> Self {
        ContractVisitor {
            contract_name: String::new(),
            functions: Vec::new(),
            in_contractimpl: false,
            current_fn_idx: None,
            financial_idents: std::collections::HashSet::new(),
            compare_depth: 0,
            loop_stack: Vec::new(),
        }
    }

    /// True when an expression references at least one identifier currently
    /// known to hold a financial integer type. This is the syntactic proxy for
    /// "this arithmetic operates on i128/u128" used throughout the overflow
    /// analysis.
    fn financial_touch(&self, expr: &syn::Expr) -> bool {
        referenced_idents(expr)
            .iter()
            .any(|id| self.financial_idents.contains(id))
    }

    pub fn finalize(mut self) -> Result<Contract, String> {
        if self.contract_name.is_empty() {
            self.contract_name = "Unknown".to_string();
        }

        let mut all_storage_keys = Vec::new();
        let mut dependencies = Vec::new();
        for func in &self.functions {
            for call in &func.body_analysis.cross_contract_calls {
                let dep = call.target.clone();
                if !dependencies.contains(&dep) {
                    dependencies.push(dep);
                }
            }
            for s in &func.body_analysis.storage_writes {
                all_storage_keys.push(s.clone());
            }
            for s in &func.body_analysis.storage_reads {
                all_storage_keys.push(s.clone());
            }
        }

        Ok(Contract {
            name: self.contract_name,
            functions: self.functions,
            storage_keys: all_storage_keys,
            dependencies,
        })
    }
}

impl<'ast> Visit<'ast> for ContractVisitor {
    fn visit_item_impl(&mut self, i: &'ast syn::ItemImpl) {
        let was_in = self.in_contractimpl;
        self.in_contractimpl = patterns::has_contractimpl_attr(&i.attrs);

        if self.in_contractimpl && self.contract_name.is_empty() {
            if let Some((_, path, _)) = &i.trait_ {
                self.contract_name = path.segments.iter().map(|s| s.ident.to_string()).collect::<Vec<_>>().join("::");
            } else {
                self.contract_name = type_to_string(&i.self_ty)
                    .trim_start_matches("impl ")
                    .to_string();
            }
        }

        syn::visit::visit_item_impl(self, i);
        self.in_contractimpl = was_in;
    }

    fn visit_impl_item_fn(&mut self, i: &'ast syn::ImplItemFn) {
        if !self.in_contractimpl {
            syn::visit::visit_impl_item_fn(self, i);
            return;
        }

        let fn_name = i.sig.ident.to_string();
        let is_init = fn_name == "__constructor";

        let func = ContractFn {
            name: fn_name.clone(),
            args: extract_fn_args(&i.sig),
            return_type: extract_return_type(&i.sig),
            visibility: extract_visibility(&i.vis),
            attributes: extract_attr_names(&i.attrs),
            is_init,
            body_analysis: FnBodyAnalysis::new(),
        };

        let idx = self.functions.len();
        self.functions.push(func);
        self.current_fn_idx = Some(idx);

        // Seed the financial-ident set from the function's arguments so that
        // arithmetic on `amount: i128` etc. can be recognised. Also reset the
        // comparison/loop context for the new function body.
        self.financial_idents.clear();
        self.compare_depth = 0;
        self.loop_stack.clear();
        for arg in &i.sig.inputs {
            if let syn::FnArg::Typed(pat_type) = arg {
                if is_financial_type(&type_to_string(&pat_type.ty)) {
                    if let syn::Pat::Ident(pat_ident) = &*pat_type.pat {
                        self.financial_idents.insert(pat_ident.ident.to_string());
                    }
                }
            }
        }

        syn::visit::visit_impl_item_fn(self, i);

        self.current_fn_idx = None;
        self.financial_idents.clear();
    }

    // `let x: i128 = ...;` — harvest the annotated type so later arithmetic on
    // `x` is recognised as financial. Bindings without an explicit type
    // annotation are not tracked (no inference).
    fn visit_local(&mut self, local: &'ast syn::Local) {
        if self.current_fn_idx.is_some() {
            if let syn::Pat::Type(pat_type) = &local.pat {
                if is_financial_type(&type_to_string(&pat_type.ty)) {
                    if let syn::Pat::Ident(pat_ident) = &*pat_type.pat {
                        self.financial_idents.insert(pat_ident.ident.to_string());
                    }
                }
            }
        }
        syn::visit::visit_local(self, local);
    }

    fn visit_expr_binary(&mut self, expr: &'ast syn::ExprBinary) {
        // A comparison marks any arithmetic nested inside its operands as
        // "compared against a threshold" (rule O-02). Track the depth so the
        // marking only applies within the comparison's operands.
        if is_comparison(&expr.op) {
            self.compare_depth += 1;
            syn::visit::visit_expr_binary(self, expr);
            self.compare_depth -= 1;
            return;
        }

        if let (Some(fn_idx), Some(op)) = (self.current_fn_idx, arith_op_of(&expr.op)) {
            let financial = self.financial_touch(&expr.left) || self.financial_touch(&expr.right);
            let return_type = if financial { "i128".to_string() } else { "unknown".to_string() };
            let span = syn::spanned::Spanned::span(&expr.op).start();
            let in_loop = !self.loop_stack.is_empty();
            let dynamic_loop = self.loop_stack.last().copied().unwrap_or(false);

            self.functions[fn_idx]
                .body_analysis
                .arithmetic_ops
                .push(ArithExpr {
                    op,
                    left: render_operand(&expr.left),
                    right: render_operand(&expr.right),
                    return_type,
                    is_checked: false,
                    divisor_checked: matches!(op, ArithOp::Div | ArithOp::Mod)
                        && is_nonzero_int_literal(&expr.right),
                    compared: self.compare_depth > 0,
                    is_compound: is_compound_assign(&expr.op),
                    in_loop,
                    dynamic_loop,
                    position: SourcePos {
                        line: span.line,
                        column: span.column,
                    },
                });
        }

        syn::visit::visit_expr_binary(self, expr);
    }

    fn visit_expr_cast(&mut self, expr: &'ast syn::ExprCast) {
        if let Some(fn_idx) = self.current_fn_idx {
            let to_type = type_to_string(&expr.ty);
            if is_narrowing_int_type(&to_type) && self.financial_touch(&expr.expr) {
                let span = expr.as_token.span.start();
                self.functions[fn_idx].body_analysis.casts.push(CastExpr {
                    from: render_operand(&expr.expr),
                    from_type: "i128/u128".to_string(),
                    to: simple_type_name(&to_type),
                    position: SourcePos {
                        line: span.line,
                        column: span.column,
                    },
                });
            }
        }
        syn::visit::visit_expr_cast(self, expr);
    }

    fn visit_expr_method_call(&mut self, expr: &'ast syn::ExprMethodCall) {
        let method_name = expr.method.to_string();
        let chain = extract_method_chain(&syn::Expr::MethodCall(expr.clone()));

        if let Some(fn_idx) = self.current_fn_idx {
            let func = &mut self.functions[fn_idx];
            let analysis = &mut func.body_analysis;

            // Record safe/explicit arithmetic method calls:
            // `.checked_add()`, `.wrapping_sub()`, `.overflowing_mul()`,
            // `.saturating_add()`, etc. These are marked `is_checked = true` so
            // the overflow detector skips them (O-01). The receiver being
            // financial is not required — these methods only exist on integers.
            if let Some((op, kind)) = patterns::classify_arith_method(&method_name) {
                let span = expr.method.span().start();
                let right = expr.args.first().map(render_operand).unwrap_or_default();
                analysis.arithmetic_ops.push(ArithExpr {
                    op,
                    left: render_operand(&expr.receiver),
                    right,
                    return_type: "i128".to_string(),
                    is_checked: kind.is_checked(),
                    divisor_checked: true,
                    compared: self.compare_depth > 0,
                    is_compound: false,
                    in_loop: !self.loop_stack.is_empty(),
                    dynamic_loop: self.loop_stack.last().copied().unwrap_or(false),
                    position: SourcePos {
                        line: span.line,
                        column: span.column,
                    },
                });
            }

            // Check for storage operations: env.storage().<type>().<op>(...)
            // The op (get/set/has/del) must be the method being invoked on *this*
            // node — i.e. the last link in the chain. Without this guard, a
            // trailing combinator such as `.get(&k).unwrap()` re-matches when we
            // visit the outer `.unwrap()` call (whose receiver chain still
            // contains `storage`/`get`), registering a bogus access with the
            // wrong (or missing) key argument.
            if let Some(storage_idx) = chain.iter().position(|s| s == "storage") {
                if storage_idx + 2 == chain.len() - 1 {
                    let storage_type_seg = &chain[storage_idx + 1];
                    let op_seg = &chain[storage_idx + 2];

                    if let Some(storage_type) = patterns::detect_storage_type(storage_type_seg) {
                        if let Some(access_type) = patterns::detect_storage_access_type(op_seg) {
                            let (key_desc, key_type) = expr
                                .args
                                .first()
                                .map(|a| extract_key_from_expr(a))
                                .unwrap_or_else(|| ("unknown".to_string(), StorageKeyType::Other("unknown".to_string())));

                            let value_type = if access_type == StorageAccessType::Write {
                                expr.args.get(1).map(|a| {
                                    let s = quote::quote!(#a).to_string();
                                    // Strip leading & and whitespace for cleaner output
                                    s.trim_start_matches('&').trim().to_string()
                                })
                            } else {
                                None
                            };

                            let span = expr.method.span().start();
                            let access = StorageAccess {
                                key: key_desc,
                                key_type,
                                access_type: access_type.clone(),
                                storage_type: storage_type.clone(),
                                position: SourcePos {
                                    line: span.line,
                                    column: span.column,
                                },
                                value_type,
                            };

                            match access_type {
                                StorageAccessType::Read | StorageAccessType::Check => {
                                    analysis.storage_reads.push(access);
                                }
                                StorageAccessType::Write | StorageAccessType::Delete => {
                                    analysis.storage_writes.push(access);
                                }
                            }
                        }
                    }
                }
            }

            // Check for cross-contract calls: env.invoke_contract(...) or env.invoke_contract_read_only(...)
            if patterns::method_is_invoke_contract(&method_name) {
                let span = expr.method.span().start();
                let pos = SourcePos {
                    line: span.line,
                    column: span.column,
                };
                let mut args_iter = expr.args.iter();



                let target = args_iter
                    .next()
                    .map(|a| extract_target_from_expr(a))
                    .unwrap_or_default();

                let function = args_iter
                    .next()
                    .map(|a| extract_invoked_fn_name(a))
                    .unwrap_or_default();

                // The remaining argument (if any) is the container holding the
                // invoked function's arguments — typically a tuple `(&a, &b)`
                // or a `vec![&env, ...]`. Count its elements.
                let args_count = args_iter
                    .next()
                    .map(count_call_args)
                    .unwrap_or(0);

                analysis.cross_contract_calls.push(CrossContractCall {
                    target,
                    function,
                    args_count,
                    position: pos,
                    read_only: method_name == "invoke_contract_read_only",
                });
                analysis.calls_external = true;
            }

            // Check for typed-client cross-contract calls:
            // `TokenClient::new(&env, &addr).transfer(&from, &to, &amount)`.
            // Here the method being invoked IS the cross-contract function and the
            // receiver is the `*Client::new(..)` constructor.
            if let Some(target) = patterns::detect_client_new(&expr.receiver) {
                let span = expr.method.span().start();
                analysis.cross_contract_calls.push(CrossContractCall {
                    target,
                    function: method_name.clone(),
                    args_count: expr.args.len(),
                    position: SourcePos {
                        line: span.line,
                        column: span.column,
                    },
                    read_only: false,
                });
                analysis.calls_external = true;
            }

            // Check for require_auth method calls: addr.require_auth() or env.require_auth(&addr)
            if patterns::method_is_require_auth(&method_name) && method_name != "require_auth_for_args" {
                let target = if chain.len() >= 2 && chain[0] == "env" {
                    expr.args
                        .first()
                        .map(|a| extract_target_from_expr(a))
                        .unwrap_or_default()
                } else {
                    chain.first().cloned().unwrap_or_default()
                };

                analysis.auth_checks.push(AuthCheck {
                    kind: AuthKind::RequireAuth,
                    target,
                });
            }

            // Check for require_auth_for_args method calls
            if patterns::method_is_require_auth_for_args(&method_name) {
                let target = if chain.len() >= 2 && chain[0] == "env" {
                    expr.args
                        .first()
                        .map(|a| extract_target_from_expr(a))
                        .unwrap_or_default()
                } else {
                    chain.first().cloned().unwrap_or_default()
                };

                analysis.auth_checks.push(AuthCheck {
                    kind: AuthKind::RequireAuthForArgs,
                    target,
                });
            }
        }

        syn::visit::visit_expr_method_call(self, expr);
    }

    fn visit_expr_call(&mut self, expr: &'ast syn::ExprCall) {
        if let Some(fn_idx) = self.current_fn_idx {
            let func = &mut self.functions[fn_idx];
            let analysis = &mut func.body_analysis;

            if let syn::Expr::Path(p) = &*expr.func {
                let path_str = p
                    .path
                    .segments
                    .iter()
                    .map(|s| s.ident.to_string())
                    .collect::<Vec<_>>()
                    .join("::");

                // Check for standalone require_auth(...) call
                if patterns::is_require_auth(&p.path) {
                    let target = expr
                        .args
                        .first()
                        .map(|a| extract_target_from_expr(a))
                        .unwrap_or_default();
                    analysis.auth_checks.push(AuthCheck {
                        kind: AuthKind::RequireAuth,
                        target,
                    });
                }

                // Check for standalone require_auth_for_args(...) call
                if patterns::is_require_auth_for_args(&p.path) {
                    let target = expr
                        .args
                        .first()
                        .map(|a| extract_target_from_expr(a))
                        .unwrap_or_default();
                    analysis.auth_checks.push(AuthCheck {
                        kind: AuthKind::RequireAuthForArgs,
                        target,
                    });
                }

                // Check for hardcoded addresses: Address::from_str("G...") etc.
                if path_str == "Address::from_str" || path_str == "Address::from_string" {
                    for arg in &expr.args {
                        if let syn::Expr::Lit(lit) = patterns::unwrap_expr(arg) {
                            if let syn::Lit::Str(s) = &lit.lit {
                                let span = syn::spanned::Spanned::span(&*expr.func).start();
                                analysis.hardcoded_address_strs.push((
                                    s.value(),
                                    SourcePos {
                                        line: span.line,
                                        column: span.column,
                                    },
                                ));
                            }
                        }
                    }
                }

                // Check for Symbol::new(&env, "name") pattern
                if path_str == "Symbol::new" || path_str == "symbol::new" {
                    // This is handled by extract_symbol_name
                }
            }
        }

        syn::visit::visit_expr_call(self, expr);
    }

    fn visit_expr_for_loop(&mut self, expr: &'ast syn::ExprForLoop) {
        if let Some(fn_idx) = self.current_fn_idx {
            self.functions[fn_idx].body_analysis.has_loops = true;
        }
        // A `for _ in 0..N` range with a small constant upper bound (< 100) is
        // considered static; anything else (a variable bound, a large range, an
        // iterator) is dynamic and can accumulate enough to overflow.
        let dynamic = !is_small_constant_range(&expr.expr);
        self.loop_stack.push(dynamic);
        syn::visit::visit_expr_for_loop(self, expr);
        self.loop_stack.pop();
    }

    fn visit_expr_while(&mut self, expr: &'ast syn::ExprWhile) {
        if let Some(fn_idx) = self.current_fn_idx {
            self.functions[fn_idx].body_analysis.has_loops = true;
        }
        // A `while` loop always has a dynamic (condition-driven) bound.
        self.loop_stack.push(true);
        syn::visit::visit_expr_while(self, expr);
        self.loop_stack.pop();
    }

    fn visit_expr_loop(&mut self, expr: &'ast syn::ExprLoop) {
        if let Some(fn_idx) = self.current_fn_idx {
            self.functions[fn_idx].body_analysis.has_loops = true;
        }
        // A bare `loop { }` is unbounded — always dynamic.
        self.loop_stack.push(true);
        syn::visit::visit_expr_loop(self, expr);
        self.loop_stack.pop();
    }

    fn visit_expr_unsafe(&mut self, _u: &'ast syn::ExprUnsafe) {
        if let Some(fn_idx) = self.current_fn_idx {
            self.functions[fn_idx].body_analysis.has_unsafe = true;
        }
        syn::visit::visit_expr_unsafe(self, _u);
    }
}
