#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct GuardedVault;

#[contractimpl]
impl GuardedVault {
    // Uses a REENTRANCY_GUARD storage flag, so R-03 should not fire. State is
    // updated before the external call, so R-01 should not fire either.
    pub fn withdraw(env: Env, token: Address, to: Address, amount: i128) {
        let locked: bool = env
            .storage()
            .instance()
            .get(&Symbol::new(&env, "REENTRANCY_GUARD"))
            .unwrap_or(false);
        if locked {
            panic!("reentrancy");
        }
        env.storage()
            .instance()
            .set(&Symbol::new(&env, "REENTRANCY_GUARD"), &true);

        let balance: i128 = env
            .storage()
            .instance()
            .get(&Symbol::new(&env, "balance"))
            .unwrap();
        env.storage()
            .instance()
            .set(&Symbol::new(&env, "balance"), &(balance - amount));

        env.invoke_contract::<()>(&token, &Symbol::new(&env, "transfer"), (&to, &amount));

        env.storage()
            .instance()
            .set(&Symbol::new(&env, "REENTRANCY_GUARD"), &false);
    }
}
