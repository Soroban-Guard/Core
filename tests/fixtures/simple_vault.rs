#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct SimpleVault;

#[contractimpl]
impl SimpleVault {
    pub fn __constructor(env: Env, owner: Address) {
        env.storage().instance().set(&Symbol::new(&env, "owner"), &owner);
    }

    pub fn deposit(env: Env, from: Address, amount: i128) {
        from.require_auth();
        let balance = env.storage().instance()
            .get::<Symbol, i128>(&Symbol::new(&env, "balance"))
            .unwrap_or(0);
        env.storage().instance().set(
            &Symbol::new(&env, "balance"),
            &(balance + amount),
        );
    }

    pub fn withdraw(env: Env, to: Address, amount: i128) -> i128 {
        to.require_auth();
        let balance = env.storage().instance()
            .get::<Symbol, i128>(&Symbol::new(&env, "balance"))
            .unwrap_or(0);
        if balance >= amount {
            env.storage().instance().set(
                &Symbol::new(&env, "balance"),
                &(balance - amount),
            );
            amount
        } else {
            0
        }
    }

    pub fn transfer(env: Env, token_id: Address, to: Address, amount: i128) {
        env.invoke_contract(&token_id, &Symbol::new(&env, "transfer"), (&to, &amount));
    }

    pub fn check_balance(env: Env) -> i128 {
        env.storage().instance()
            .get::<Symbol, i128>(&Symbol::new(&env, "balance"))
            .unwrap_or(0)
    }
}
