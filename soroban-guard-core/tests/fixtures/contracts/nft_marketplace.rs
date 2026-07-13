#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct NFTMarketplace;

#[contractimpl]
impl NFTMarketplace {
    pub fn __constructor(env: Env, admin: Address) {
        env.storage().instance().set(&Symbol::new(&env, "VERSION"), &1u32);
        env.storage().instance().set(&Symbol::new(&env, "admin"), &admin);
    }

    pub fn list(env: Env, seller: Address, token_id: Symbol, price: i128) {
        seller.require_auth();
        let key = Symbol::new(&env, "listing");
        env.storage().instance().set(&key, &(token_id, seller.clone(), price));
    }

    pub fn buy(env: Env, buyer: Address, token_id: Symbol, price: i128) {
        buyer.require_auth();
        let fee = price / 100;
        env.storage().instance().set(&Symbol::new(&env, "fee"), &fee);
        env.invoke_contract::<()>(&token_id, &Symbol::new(&env, "transfer"), (&buyer,));
    }

    pub fn set_fee(env: Env, new_fee: i128) {
        env.storage().instance().set(&Symbol::new(&env, "fee"), &new_fee);
    }

    pub fn total_listings(env: Env) -> u32 {
        env.storage().instance().get(&Symbol::new(&env, "count")).unwrap_or(0)
    }
}
