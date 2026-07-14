#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct LendingPool;

#[contractimpl]
impl LendingPool {
    pub fn __constructor(env: Env, admin: Address) {
        env.storage().instance().set(&Symbol::new(&env, "VERSION"), &1u32);
        env.storage().instance().set(&Symbol::new(&env, "v1_admin"), &admin);
    }

    pub fn deposit(env: Env, from: Address, amount: i128) {
        from.require_auth();
        let balance: i128 = env.storage().instance().get(&Symbol::new(&env, "v1_deposits")).unwrap_or(0);
        env.storage().instance().set(&Symbol::new(&env, "v1_deposits"), &balance.checked_add(amount).unwrap());
    }

    pub fn borrow(env: Env, borrower: Address, amount: i128) {
        borrower.require_auth();
        let total_borrowed: i128 = env.storage().instance().get(&Symbol::new(&env, "v1_borrowed")).unwrap_or(0);
        let collateral: i128 = env.storage().instance().get(&Symbol::new(&env, "v1_collateral")).unwrap_or(0);
        if collateral >= amount {
            env.storage().instance().set(&Symbol::new(&env, "v1_borrowed"), &(total_borrowed + amount));
            env.invoke_contract::<()>(&borrower, &Symbol::new(&env, "transfer"), (&amount,));
        }
    }

    pub fn repay(env: Env, from: Address, amount: i128) {
        from.require_auth();
        let balance: i128 = env.storage().instance().get(&Symbol::new(&env, "v1_deposits")).unwrap_or(0);
        env.storage().instance().set(&Symbol::new(&env, "v1_deposits"), &balance.checked_add(amount).unwrap());
    }

    pub fn liquidate(env: Env, caller: Address, target: Address) {
        let borrowed: i128 = env.storage().instance().get(&Symbol::new(&env, "v1_borrowed")).unwrap_or(0);
        let collateral: i128 = env.storage().instance().get(&Symbol::new(&env, "v1_collateral")).unwrap_or(0);
        if collateral < borrowed {
            env.invoke_contract::<()>(&target, &Symbol::new(&env, "transfer"), (&collateral,));
            env.storage().instance().set(&Symbol::new(&env, "v1_borrowed"), &0i128);
        }
    }
}
