use syn::visit::Visit;

use crate::parser::ast::{
    AuthCheck, AuthKind, Contract, ContractFn, CrossContractCall, FnArg, FnBodyAnalysis,
    FnVisibility, SourcePos, StorageAccess, StorageAccessType, StorageKeyType,
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
}

impl ContractVisitor {
    pub fn new() -> Self {
        ContractVisitor {
            contract_name: String::new(),
            functions: Vec::new(),
            in_contractimpl: false,
            current_fn_idx: None,
        }
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

        syn::visit::visit_impl_item_fn(self, i);

        self.current_fn_idx = None;
    }

    fn visit_expr_method_call(&mut self, expr: &'ast syn::ExprMethodCall) {
        let method_name = expr.method.to_string();
        let chain = extract_method_chain(&syn::Expr::MethodCall(expr.clone()));

        if let Some(fn_idx) = self.current_fn_idx {
            let func = &mut self.functions[fn_idx];
            let analysis = &mut func.body_analysis;

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

                // Check for Symbol::new(&env, "name") pattern
                if path_str == "Symbol::new" || path_str == "symbol::new" {
                    // This is handled by extract_symbol_name
                }
            }
        }

        syn::visit::visit_expr_call(self, expr);
    }

    fn visit_expr_for_loop(&mut self, _expr: &'ast syn::ExprForLoop) {
        if let Some(fn_idx) = self.current_fn_idx {
            self.functions[fn_idx].body_analysis.has_loops = true;
        }
    }

    fn visit_expr_while(&mut self, _expr: &'ast syn::ExprWhile) {
        if let Some(fn_idx) = self.current_fn_idx {
            self.functions[fn_idx].body_analysis.has_loops = true;
        }
    }

    fn visit_expr_loop(&mut self, _expr: &'ast syn::ExprLoop) {
        if let Some(fn_idx) = self.current_fn_idx {
            self.functions[fn_idx].body_analysis.has_loops = true;
        }
    }

    fn visit_expr_unsafe(&mut self, _u: &'ast syn::ExprUnsafe) {
        if let Some(fn_idx) = self.current_fn_idx {
            self.functions[fn_idx].body_analysis.has_unsafe = true;
        }
        syn::visit::visit_expr_unsafe(self, _u);
    }
}
