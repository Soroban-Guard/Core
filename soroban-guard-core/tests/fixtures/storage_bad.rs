#![no_std]
use soroban_sdk::{contract, contractimpl, symbol, Address, Env, Symbol};

#[contract]
pub struct BadStorage;

#[contractimpl]
impl BadStorage {
    pub fn __constructor(env: Env, admin: Address) {
        // S-05: No VERSION key present
        env.storage().instance().set(&symbol!("admin"), &admin);
    }

    // S-01: Short key "a"
    pub fn set_a(env: Env, val: i128) {
        env.storage().instance().set(&symbol!("a"), &val);
    }

    // S-02: Generic key "balance"
    pub fn set_balance(env: Env, val: i128) {
        env.storage().instance().set(&symbol!("balance"), &val);
    }

    // S-03: Mixed types at key "mixed" — i128 vs Address
    pub fn set_mixed_i128(env: Env, val: i128) {
        env.storage().instance().set(&symbol!("mixed"), &val);
    }

    pub fn set_mixed_address(env: Env, addr: Address) {
        env.storage().instance().set(&symbol!("mixed"), &addr);
    }

    // S-04: Same key in instance and temporary
    pub fn set_instance_val(env: Env, val: i128) {
        env.storage().instance().set(&symbol!("shared_key"), &val);
    }

    pub fn set_temporary_val(env: Env, val: i128) {
        env.storage().temporary().set(&symbol!("shared_key"), &val);
    }

    // Safe: descriptive key, single type
    pub fn set_v1_balance(env: Env, val: i128) {
        env.storage().instance().set(&symbol!("v1_balance"), &val);
    }
}
