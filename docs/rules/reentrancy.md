# Reentrancy Rules (R-01 to R-04)

Reentrancy vulnerabilities occur when a contract makes an external call before updating its own state, allowing the callee to re-enter and exploit stale state.

## R-01 — State write after external call (Critical)

**Severity: Critical**

State is written after a cross-contract call, enabling reentrancy.

```rust
// VULNERABLE
pub fn withdraw(env: Env, to: Address, amount: i128) {
    let balance = env.storage().instance().get(&Symbol::new(&env, "balance"));
    env.invoke_contract::<()>(&to, &Symbol::new(&env, "transfer"), (&amount,));
    env.storage().instance().set(&Symbol::new(&env, "balance"), &(balance - amount));
}
```

```rust
// SAFE
pub fn withdraw(env: Env, to: Address, amount: i128) {
    let balance = env.storage().instance().get(&Symbol::new(&env, "balance"));
    env.storage().instance().set(&Symbol::new(&env, "balance"), &(balance - amount));
    env.invoke_contract::<()>(&to, &Symbol::new(&env, "transfer"), (&amount,));
}
```

## R-02 — Read-only reentrancy (Medium)

**Severity: Medium**

A read-only external call occurs between a storage read and write of the same key.

## R-03 — Missing reentrancy guard (Low)

**Severity: Low**

The contract makes external calls but has no reentrancy guard (no storage key containing `REENTRANCY`, `GUARD`, or `LOCK`). Scoring bonus: **+5 points** if no R-03 finding (guard present).

## R-04 — Cross-function reentrancy (High)

**Severity: High**

Two functions make external calls and share a storage key — re-entering through a sibling function can corrupt shared state.
