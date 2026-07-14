#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct VulnerableVault;

#[contractimpl]
impl VulnerableVault {
    // VULNERABLE: external call happens before the balance is updated.
    pub fn withdraw(env: Env, token: Address, to: Address, amount: i128) {
        let balance: i128 = env
            .storage()
            .instance()
            .get(&Symbol::new(&env, "balance"))
            .unwrap();

        // External call BEFORE state update.
        env.invoke_contract::<()>(&token, &Symbol::new(&env, "transfer"), (&to, &amount));

        // State update AFTER the external call — too late.
        env.storage()
            .instance()
            .set(&Symbol::new(&env, "balance"), &(balance - amount));
    }
}
