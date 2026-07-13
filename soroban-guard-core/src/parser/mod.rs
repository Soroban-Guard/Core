pub mod ast;
pub mod patterns;
pub mod visitors;

use crate::error::{Result, SorobanGuardError};
use ast::Contract;

pub struct ContractParser;

impl ContractParser {
    pub fn new() -> Self {
        ContractParser
    }

    pub fn parse_file(&self, path: &str) -> Result<Contract> {
        let source = std::fs::read_to_string(path)
            .map_err(|e| SorobanGuardError::FileNotFound(format!("{}: {}", path, e)))?;
        self.parse_source(&source)
    }

    pub fn parse_source(&self, source: &str) -> Result<Contract> {
        visitors::parse_contract(source)
            .map_err(|e| SorobanGuardError::Parse(e))
    }
}

impl Default for ContractParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_soroban_contract() -> &'static str {
        r#"
        #![no_std]
        use soroban_sdk::{contract, contractimpl, Address, Env, Symbol, Vec};

        #[contract]
        pub struct Vault;

        #[contractimpl]
        impl Vault {
            pub fn __constructor(env: Env, owner: Address) {
                env.storage().instance().set(&Symbol::new(&env, "owner"), &owner);
            }

            pub fn deposit(env: Env, from: Address, amount: i128) {
                from.require_auth();
                let balance = env.storage().instance().get(&Symbol::new(&env, "balance")).unwrap_or(0);
                env.storage().instance().set(&Symbol::new(&env, "balance"), &(balance + amount));
            }

            pub fn withdraw(env: Env, to: Address, amount: i128) -> i128 {
                to.require_auth();
                let balance = env.storage().instance().get(&Symbol::new(&env, "balance")).unwrap_or(0);
                if balance >= amount {
                    env.storage().instance().set(&Symbol::new(&env, "balance"), &(balance - amount));
                    amount
                } else {
                    0
                }
            }

            pub fn transfer(env: Env, token_id: Address, to: Address, amount: i128) {
                env.invoke_contract(&token_id, &Symbol::new(&env, "transfer"), (&to, &amount));
            }

            pub fn check_balance(env: Env) -> i128 {
                env.storage().instance().get(&Symbol::new(&env, "balance")).unwrap_or(0)
            }
        }
        "#
    }

    #[test]
    fn test_parse_soroban_contract() {
        let parser = ContractParser::new();
        let contract = parser.parse_source(sample_soroban_contract()).expect("Failed to parse contract");

        assert_eq!(contract.name, "Vault");
        assert_eq!(contract.functions.len(), 5);

        let constructor = &contract.functions[0];
        assert_eq!(constructor.name, "__constructor");
        assert!(constructor.is_init);
        assert_eq!(constructor.args.len(), 2);
        assert_eq!(constructor.args[0].name, "env");
        assert_eq!(constructor.args[0].type_name, "Env");
        assert_eq!(constructor.args[1].name, "owner");
        assert_eq!(constructor.args[1].type_name, "Address");

        let deposit = &contract.functions[1];
        assert_eq!(deposit.name, "deposit");
        assert!(!deposit.is_init);
        assert_eq!(deposit.args.len(), 3);
        assert_eq!(deposit.return_type, "()");

        let transfer = &contract.functions[3];
        assert_eq!(transfer.name, "transfer");
        assert_eq!(transfer.body_analysis.cross_contract_calls.len(), 1);

        let xcc = &transfer.body_analysis.cross_contract_calls[0];
        assert_eq!(xcc.function, "transfer");
        assert_eq!(xcc.args_count, 2);
    }

    #[test]
    fn test_storage_operations_detected() {
        let parser = ContractParser::new();
        let contract = parser.parse_source(sample_soroban_contract()).expect("Failed to parse");

        let deposit = &contract.functions[1];
        assert!(deposit.body_analysis.storage_reads.len() >= 1);
        assert!(deposit.body_analysis.storage_writes.len() >= 1);

        let check_balance = &contract.functions[4];
        assert!(check_balance.body_analysis.storage_reads.len() >= 1);
        assert_eq!(check_balance.body_analysis.storage_writes.len(), 0);
    }

    #[test]
    fn test_auth_checks_detected() {
        let parser = ContractParser::new();
        let contract = parser.parse_source(sample_soroban_contract()).expect("Failed to parse");

        let deposit = &contract.functions[1];
        assert_eq!(deposit.body_analysis.auth_checks.len(), 1);
        assert_eq!(deposit.body_analysis.auth_checks[0].target, "from");

        let withdraw = &contract.functions[2];
        assert_eq!(withdraw.body_analysis.auth_checks.len(), 1);
        assert_eq!(withdraw.body_analysis.auth_checks[0].target, "to");
    }

    #[test]
    fn test_empty_source() {
        let parser = ContractParser::new();
        let result = parser.parse_source("fn main() {}");
        assert!(result.is_ok());
        let contract = result.unwrap();
        assert_eq!(contract.functions.len(), 0);
    }

    #[test]
    fn test_invalid_source() {
        let parser = ContractParser::new();
        let result = parser.parse_source("invalid syntax !!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_non_contract_rust() {
        let parser = ContractParser::new();
        let result = parser.parse_source(
            r#"
            fn add(a: u32, b: u32) -> u32 {
                a + b
            }
            "#,
        );
        assert!(result.is_ok());
        let contract = result.unwrap();
        assert_eq!(contract.name, "Unknown");
        assert_eq!(contract.functions.len(), 0);
    }

    #[test]
    fn test_client_new_cross_contract_call() {
        let parser = ContractParser::new();
        let contract = parser
            .parse_source(
                r#"
                #[contractimpl]
                impl Pool {
                    pub fn swap(env: Env, token: Address, from: Address, amount: i128) {
                        TokenClient::new(&env, &token).transfer(&from, &env.current_contract_address(), &amount);
                    }
                }
                "#,
            )
            .expect("Failed to parse");

        assert_eq!(contract.functions.len(), 1);
        let swap = &contract.functions[0];
        let calls = &swap.body_analysis.cross_contract_calls;
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].function, "transfer");
        assert_eq!(calls[0].target, "token");
        assert_eq!(calls[0].args_count, 3);
        assert!(swap.body_analysis.calls_external);
        assert!(contract.dependencies.contains(&"token".to_string()));
    }
}
