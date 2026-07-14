#![no_std]
use soroban_sdk::{contract, contractimpl, symbol, Address, Env, Symbol};

#[contract]
pub struct AdminContract;

#[contractimpl]
impl AdminContract {
    pub fn __constructor(env: Env, admin: Address) {
        env.storage().instance().set(&symbol!("admin"), &admin);
    }

    // A-01: NO require_auth — should flag (state write without auth)
    pub fn withdraw_all(env: Env, to: Address) {
        let balance = env.storage().instance().get(&symbol!("balance")).unwrap_or(0i128);
        env.storage().instance().set(&symbol!("balance"), &0i128);
    }

    // A-02: Admin function name, no auth
    pub fn set_admin(env: Env, new_admin: Address) {
        env.storage().instance().set(&symbol!("admin"), &new_admin);
    }

    // A-03: Has Address param but uses require_auth_for_args without including it
    pub fn transfer(env: Env, caller: Address, to: Address, amount: i128) {
        caller.require_auth_for_args(&[&amount]);
        let balance: i128 = env.storage().instance().get(&symbol!("balance")).unwrap_or(0);
        if balance >= amount {
            env.storage().instance().set(&symbol!("balance"), &(balance - amount));
        }
    }

    // A-04: Public function, no Address params, no auth, modifies state
    pub fn reset(env: Env) {
        env.storage().instance().set(&symbol!("balance"), &0i128);
    }

    // A-05: Hardcoded admin address
    pub fn hardcoded_admin(env: Env) {
        let _admin = Address::from_str(&env, "GA7QYNF7SOWQ3GLR2BGM4DZP6K6V6YFQ7D6YFQ7D6YFQ7D6YFQ7D6YFQ");
    }

    // Properly guarded — should NOT flag
    pub fn guarded_withdraw(env: Env, caller: Address, amount: i128) {
        caller.require_auth();
        let balance: i128 = env.storage().instance().get(&symbol!("balance")).unwrap_or(0);
        if balance >= amount {
            env.storage().instance().set(&symbol!("balance"), &(balance - amount));
        }
    }

    // View function — no state write, no auth, public — Info only
    pub fn check_balance(env: Env) -> i128 {
        env.storage().instance().get(&symbol!("balance")).unwrap_or(0)
    }
}
