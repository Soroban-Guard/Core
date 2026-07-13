# Storage Rules (S-01 to S-05)

Storage collision and key management rules.

## S-01 — Short storage key (Medium)

**Severity: Medium**

Key name is <= 2 characters — may collide with other contracts sharing the same storage namespace.

```rust
// VULNERABLE - short key
env.storage().instance().set(&Symbol::new(&env, "a"), &value);

// SAFE - descriptive key with prefix
env.storage().instance().set(&Symbol::new(&env, "v1_balance"), &value);
```

## S-02 — Generic storage key (Low)

**Severity: Low**

Key name is a common word (`balance`, `owner`, `admin`, `config`, `total`, `count`, `name`, `symbol`).

## S-03 — Mixed value types at same key (High)

**Severity: High**

Same key written with different Rust types — causes runtime type errors.

```rust
// VULNERABLE - mixed types
env.storage().instance().set(&Symbol::new(&env, "data"), &1i128);
// Later...
env.storage().instance().set(&Symbol::new(&env, "data"), &Address::from_string(&sym));
```

## S-04 — Instance/temporary confusion (High)

**Severity: High**

Same key accessed via both `instance()` and `temporary()` storage — leads to unexpected value retrieval.

```rust
// VULNERABLE
env.storage().instance().set(&Symbol::new(&env, "x"), &1i128);
env.storage().temporary().set(&Symbol::new(&env, "x"), &2i128);
```

## S-05 — Missing version key (Info)

**Severity: Info**

No storage key containing `"version"` — upgrade could cause storage collisions. Scoring bonus: **+3 points** if no S-05 finding (version key present).
