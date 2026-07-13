#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct AmmPair;

#[contractimpl]
impl AmmPair {
    pub fn __constructor(env: Env, token_a: Address, token_b: Address) {
        env.storage().instance().set(&Symbol::new(&env, "VERSION"), &1u32);
        env.storage().instance().set(&Symbol::new(&env, "v1_token_a"), &token_a);
        env.storage().instance().set(&Symbol::new(&env, "v1_token_b"), &token_b);
        env.storage().instance().set(&Symbol::new(&env, "v1_reserve_a"), &0i128);
        env.storage().instance().set(&Symbol::new(&env, "v1_reserve_b"), &0i128);
    }

    pub fn add_liquidity(env: Env, to: Address, amount_a: i128, amount_b: i128) {
        let reserve_a: i128 = env.storage().instance().get(&Symbol::new(&env, "v1_reserve_a")).unwrap_or(0);
        let reserve_b: i128 = env.storage().instance().get(&Symbol::new(&env, "v1_reserve_b")).unwrap_or(0);
        env.invoke_contract::<()>(&to, &Symbol::new(&env, "transfer"), (&amount_a, &amount_b));
        env.storage().instance().set(&Symbol::new(&env, "v1_reserve_a"), &(reserve_a + amount_a));
        env.storage().instance().set(&Symbol::new(&env, "v1_reserve_b"), &(reserve_b + amount_b));
    }

    pub fn swap(env: Env, to: Address, amount_in: i128, min_out: i128) {
        let reserve_a: i128 = env.storage().instance().get(&Symbol::new(&env, "v1_reserve_a")).unwrap_or(0);
        let reserve_b: i128 = env.storage().instance().get(&Symbol::new(&env, "v1_reserve_b")).unwrap_or(0);
        let amount_out = (reserve_b * amount_in) / (reserve_a + amount_in);
        if amount_out < min_out {
            panic!("insufficient output");
        }
        env.invoke_contract::<()>(&to, &Symbol::new(&env, "transfer"), (&amount_out,));
        env.storage().instance().set(&Symbol::new(&env, "v1_reserve_a"), &(reserve_a + amount_in));
    }

    pub fn get_reserves(env: Env) -> (i128, i128) {
        let a = env.storage().instance().get(&Symbol::new(&env, "v1_reserve_a")).unwrap_or(0);
        let b = env.storage().instance().get(&Symbol::new(&env, "v1_reserve_b")).unwrap_or(0);
        (a, b)
    }
}
