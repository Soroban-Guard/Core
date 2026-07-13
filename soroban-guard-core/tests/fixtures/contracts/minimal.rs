#![no_std]
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct Minimal;

#[contractimpl]
impl Minimal {
    pub fn greet(env: Env) -> Symbol {
        Symbol::new(&env, "hello")
    }
}
