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

pub fn extract_string_literal(expr: &Expr) -> Option<String> {
    match expr {
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
    match expr {
        Expr::Call(call) => {
            if let Expr::Path(path) = &*call.func {
                if path.path.is_ident("Symbol") || path.path.is_ident("symbol") {
                    if let Some(arg) = call.args.first() {
                        return extract_string_literal(arg);
                    }
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
