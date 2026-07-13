# Access Control Rules (A-01 to A-05)

Access control vulnerabilities where functions lack proper authorization checks.

## A-01 — Missing authorization on state mutation (Critical/High)

**Severity: Critical** (if admin-named) or **High**

Function modifies state without calling `require_auth()`.

```rust
// VULNERABLE
pub fn set_balance(env: Env, amount: i128) {
    env.storage().instance().set(&Symbol::new(&env, "balance"), &amount);
}

// SAFE
pub fn set_balance(env: Env, admin: Address, amount: i128) {
    admin.require_auth();
    env.storage().instance().set(&Symbol::new(&env, "balance"), &amount);
}
```

## A-02 — Missing auth on admin function (High)

**Severity: High**

Admin-sounding function (`admin`, `owner`, `set_`, `update_`, `configure`, `upgrade`, `pause`, `emergency`) has no auth check.

## A-03 — Weak authorization pattern (Medium)

**Severity: Medium**

Uses `require_auth_for_args` without also calling `require_auth()` on an Address parameter.

## A-04 — Public function without auth (High/Medium/Info)

**Severity: High** (writes state), **Medium** (has Address param), **Info** (read-only)

Public function with no authorization at all.

## A-05 — Hardcoded admin address (Medium)

**Severity: Medium**

Address string literal used in `Address::from_str()` or `Address::from_string()`.

```rust
// VULNERABLE
let admin = Address::from_string(&Symbol::new(&env, "GCVXG...ABCD"));

// SAFE
let admin = env.storage().instance().get(&Symbol::new(&env, "admin")).unwrap();
```
