#![no_std]
use soroban_sdk::{contract, contractimpl, Env, Symbol};

#[contract]
pub struct VulnerableMath;

#[contractimpl]
impl VulnerableMath {
    // Unchecked subtraction on i128 balances (O-01 High), and an unchecked
    // multiplication (O-01 High).
    pub fn withdraw(env: Env, amount: i128) -> i128 {
        let balance: i128 = env
            .storage()
            .instance()
            .get(&Symbol::new(&env, "balance"))
            .unwrap();
        let fee: i128 = amount * 2;
        balance - amount - fee
    }

    // Division by a caller-supplied divisor with no zero check (O-03 Medium).
    pub fn price_per_share(total: i128, shares: i128) -> i128 {
        total / shares
    }

    // Loop accumulation with a dynamic bound (O-04 High).
    pub fn sum_rewards(count: u32, per_item: i128) -> i128 {
        let mut total: i128 = 0;
        for _ in 0..count {
            total += per_item;
        }
        total
    }

    // Truncating cast from i128 to u32 (O-05 Low).
    pub fn as_small(amount: i128) -> u32 {
        amount as u32
    }
}
