#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct VulnerableVault;

#[contractimpl]
impl VulnerableVault {
    // Short single-character keys — S-01
    // No VERSION key — S-05
    pub fn __constructor(env: Env) {
        env.storage().instance().set(&Symbol::new(&env, "a"), &0i128);
        env.storage().instance().set(&Symbol::new(&env, "b"), &Address::from_string(&Symbol::new(&env, "admin")));
    }

    // Unchecked arithmetic — O-01
    pub fn deposit(env: Env, from: Address, amount: i128) {
        from.require_auth();
        let balance: i128 = env.storage().instance().get(&Symbol::new(&env, "a")).unwrap_or(0);
        env.storage().instance().set(&Symbol::new(&env, "a"), &(balance + amount));
    }

    // Missing auth — A-01/A-04
    // Unchecked arithmetic — O-01
    pub fn withdraw(env: Env, to: Address, amount: i128) {
        let balance: i128 = env.storage().instance().get(&Symbol::new(&env, "a")).unwrap_or(0);
        env.storage().instance().set(&Symbol::new(&env, "a"), &(balance - amount));
        env.invoke_contract::<()>(&to, &Symbol::new(&env, "transfer"), (&amount,));
    }

    // State write after external call — R-01
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        let balance: i128 = env.storage().instance().get(&Symbol::new(&env, "a")).unwrap_or(0);
        env.invoke_contract::<()>(&to, &Symbol::new(&env, "transfer"), (&amount,));
        env.storage().instance().set(&Symbol::new(&env, "a"), &(balance - amount));
    }

    // No auth on admin-sounding function — A-02
    pub fn set_admin(env: Env, new_admin: Address) {
        env.storage().instance().set(&Symbol::new(&env, "b"), &new_admin);
    }

    // Admin function without auth — A-02
    pub fn configure(env: Env, config: i128) {
        env.storage().instance().set(&Symbol::new(&env, "c"), &config);
    }

    // Unchecked state update via upgrade — A-02 (upgrade keyword)
    pub fn upgrade(env: Env, new_code: Address) {
        env.deployer().update_current_contract_wasm(&new_code);
    }

    // Instance/temporary confusion on key "a" — S-04
    pub fn get_balance(env: Env) -> i128 {
        let balance: i128 = env.storage().instance().get(&Symbol::new(&env, "a")).unwrap_or(0);
        env.storage().temporary().set(&Symbol::new(&env, "a"), &balance);
        balance
    }
}
