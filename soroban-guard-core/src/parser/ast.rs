use syn::Item;

#[derive(Debug, Clone)]
pub struct ContractAst {
    pub items: Vec<Item>,
    pub source: String,
}

impl ContractAst {
    pub fn new(source: String, items: Vec<Item>) -> Self {
        ContractAst { items, source }
    }
}
