#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct SafeVault;

#[contractimpl]
impl SafeVault {
    // SAFE: state is updated before the external call (checks-effects-interactions).
    pub fn withdraw(env: Env, token: Address, to: Address, amount: i128) {
        let balance: i128 = env
            .storage()
            .instance()
            .get(&Symbol::new(&env, "balance"))
            .unwrap();

        // State update BEFORE the external call.
        env.storage()
            .instance()
            .set(&Symbol::new(&env, "balance"), &(balance - amount));

        env.invoke_contract::<()>(&token, &Symbol::new(&env, "transfer"), (&to, &amount));
    }
}
