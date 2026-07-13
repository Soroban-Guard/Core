use crate::parser::ast::{StorageAccessType, StorageType};
use syn::{Attribute, Expr, Path};

pub fn has_contractimpl_attr(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| attr.path().is_ident("contractimpl"))
}

pub fn has_contract_attr(attrs: &[Attribute]) -> Option<String> {
    for attr in attrs {
        if attr.path().is_ident("contract") {
            if let Ok(meta) = attr.parse_args::<syn::Ident>() {
                return Some(meta.to_string());
            }
        }
    }
    None
}

pub fn is_require_auth(path: &Path) -> bool {
    path.is_ident("require_auth")
}

pub fn is_require_auth_for_args(path: &Path) -> bool {
    path.is_ident("require_auth_for_args")
}

pub fn method_is_require_auth(name: &str) -> bool {
    name == "require_auth"
}

pub fn method_is_require_auth_for_args(name: &str) -> bool {
    name == "require_auth_for_args"
}

pub fn method_is_invoke_contract(name: &str) -> bool {
    matches!(name, "invoke_contract" | "invoke_contract_read_only")
}

pub fn method_is_storage(name: &str) -> bool {
    name == "storage"
}

pub fn detect_storage_type(name: &str) -> Option<StorageType> {
    match name {
        "instance" => Some(StorageType::Instance),
        "temporary" => Some(StorageType::Temporary),
        "persistent" => Some(StorageType::Persistent),
        _ => None,
    }
}

pub fn detect_storage_access_type(name: &str) -> Option<StorageAccessType> {
    match name {
        "set" => Some(StorageAccessType::Write),
        "get" => Some(StorageAccessType::Read),
        "del" => Some(StorageAccessType::Delete),
        "has" => Some(StorageAccessType::Check),
        _ => None,
    }
}

/// Strip surrounding references, parentheses, and invisible groups so that
/// `&Symbol::new(..)`, `(Symbol::new(..))`, etc. are matched by the same logic
/// as the bare expression.
pub fn unwrap_expr(expr: &Expr) -> &Expr {
    match expr {
        Expr::Reference(r) => unwrap_expr(&r.expr),
        Expr::Paren(p) => unwrap_expr(&p.expr),
        Expr::Group(g) => unwrap_expr(&g.expr),
        other => other,
    }
}

/// Detect a Soroban generated-client constructor: `SomethingClient::new(&env, &addr)`.
/// Returns the target contract address expression (the last argument, usually the
/// address) as a string when the pattern matches. These constructors are how
/// contracts make typed cross-contract calls, e.g.
/// `TokenClient::new(&env, &token).transfer(..)`.
pub fn detect_client_new(expr: &Expr) -> Option<String> {
    if let Expr::Call(call) = unwrap_expr(expr) {
        if let Expr::Path(path) = &*call.func {
            let segments = &path.path.segments;
            // Path shaped like `<Type>::new`, where the type name ends in `Client`.
            if segments.len() >= 2 {
                let last = &segments[segments.len() - 1].ident;
                let type_ident = &segments[segments.len() - 2].ident;
                if last == "new" && type_ident.to_string().ends_with("Client") {
                    // The contract address is conventionally the final argument.
                    return call
                        .args
                        .last()
                        .map(|a| match unwrap_expr(a) {
                            Expr::Path(p) => p
                                .path
                                .segments
                                .iter()
                                .map(|s| s.ident.to_string())
                                .collect::<Vec<_>>()
                                .join("::"),
                            other => quote::quote!(#other).to_string(),
                        })
                        .or_else(|| Some(type_ident.to_string()));
                }
            }
        }
    }
    None
}

pub fn extract_string_literal(expr: &Expr) -> Option<String> {
    match unwrap_expr(expr) {
        Expr::Lit(lit) => {
            if let syn::Lit::Str(s) = &lit.lit {
                return Some(s.value());
            }
            None
        }
        _ => None,
    }
}

pub fn extract_symbol_name(expr: &Expr) -> Option<String> {
    match unwrap_expr(expr) {
        Expr::Call(call) => {
            if let Expr::Path(path) = &*call.func {
                // Match `Symbol::new(..)` / `symbol::new(..)` and bare `Symbol(..)`.
                let is_symbol_ctor = path
                    .path
                    .segments
                    .first()
                    .map(|s| s.ident == "Symbol" || s.ident == "symbol")
                    .unwrap_or(false);
                if is_symbol_ctor {
                    // The symbol name is the first string-literal argument
                    // (e.g. `Symbol::new(&env, "name")`).
                    return call.args.iter().find_map(extract_string_literal);
                }
            }
            None
        }
        // `symbol_short!("name")` macro invocation.
        Expr::Macro(m) => {
            if m.mac.path.is_ident("symbol_short") {
                if let Ok(lit) = m.mac.parse_body::<syn::LitStr>() {
                    return Some(lit.value());
                }
            }
            None
        }
        _ => None,
    }
}

pub fn extract_bytesn_size(ty: &syn::Type) -> Option<usize> {
    if let syn::Type::Path(type_path) = ty {
        let segments = &type_path.path.segments;
        if segments.len() == 1 && segments[0].ident == "BytesN" {
            if let syn::PathArguments::AngleBracketed(args) = &segments[0].arguments {
                if let Some(syn::GenericArgument::Const(syn::Expr::Lit(lit))) = args.args.first() {
                    if let syn::Lit::Int(n) = &lit.lit {
                        return n.base10_parse::<usize>().ok();
                    }
                }
            }
        }
    }
    None
}
