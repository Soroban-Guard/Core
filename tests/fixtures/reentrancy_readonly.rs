#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct ReadOnlyReentrant;

#[contractimpl]
impl ReadOnlyReentrant {
    // Reads `balance`, makes a read-only external call, then writes `balance`.
    // A re-entering caller can observe the stale pre-write value during the call.
    pub fn rebalance(env: Env, oracle: Address, to: Address, amount: i128) {
        let balance: i128 = env
            .storage()
            .instance()
            .get(&Symbol::new(&env, "balance"))
            .unwrap();

        // Read-only external call in the middle.
        env.invoke_contract_read_only::<i128>(&oracle, &Symbol::new(&env, "price"), (&to,));

        env.storage()
            .instance()
            .set(&Symbol::new(&env, "balance"), &(balance - amount));
    }
}
