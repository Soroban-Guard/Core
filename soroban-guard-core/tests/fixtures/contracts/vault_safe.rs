#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct SafeVault;

#[contractimpl]
impl SafeVault {
    pub fn __constructor(env: Env, admin: Address) {
        env.storage().instance().set(&Symbol::new(&env, "VERSION"), &1u32);
        env.storage().instance().set(&Symbol::new(&env, "v1_admin"), &admin);
        env.storage().instance().set(&Symbol::new(&env, "v1_balance"), &0i128);
    }

    pub fn deposit(env: Env, from: Address, amount: i128) {
        from.require_auth();
        let balance: i128 = env.storage().instance().get(&Symbol::new(&env, "v1_balance")).unwrap_or(0);
        env.storage().instance().set(&Symbol::new(&env, "v1_balance"), &balance.checked_add(amount).unwrap());
    }

    pub fn withdraw(env: Env, to: Address, amount: i128) {
        to.require_auth();
        let balance: i128 = env.storage().instance().get(&Symbol::new(&env, "v1_balance")).unwrap_or(0);
        env.storage().instance().set(&Symbol::new(&env, "v1_balance"), &balance.checked_sub(amount).unwrap());
        env.invoke_contract::<()>(&to, &Symbol::new(&env, "transfer"), (&amount,));
    }

    pub fn balance(env: Env) -> i128 {
        env.storage().instance().get(&Symbol::new(&env, "v1_balance")).unwrap_or(0)
    }
}
