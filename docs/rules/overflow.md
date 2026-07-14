# Overflow Rules (O-01 to O-05)

Integer overflow/underflow vulnerabilities in financial arithmetic on `i128`/`u128` types.

## O-01 — Unchecked arithmetic on financial type (High)

**Severity: High** (Medium for simple unit counters like `i += 1`)

Bare `+`, `-`, `*` on `i128`/`u128` without `checked_*` or `saturating_*`.

```rust
// VULNERABLE
let new_balance = balance + amount;

// SAFE
let new_balance = balance.checked_add(amount).unwrap();
```

## O-02 — Arithmetic compared against threshold (Medium)

**Severity: Medium**

Arithmetic result used directly in a comparison — partially safe but clearer with checked methods.

## O-03 — Division by unchecked divisor (Medium)

**Severity: Medium**

Division or modulo by a non-literal or zero-literal divisor.

```rust
// VULNERABLE
let share = total / divisor;

// SAFE
if divisor != 0 {
    let share = total / divisor;
}
```

## O-04 — Loop accumulation overflow (High)

**Severity: High**

Compound accumulation (`sum += x`) inside a dynamically-bounded loop.

```rust
// VULNERABLE
for i in 0..count {
    total += amounts.get(i).unwrap_or(0);
}
```

## O-05 — Truncating cast (Low)

**Severity: Low**

Cast from `i128`/`u128` to a narrower integer type.

```rust
// VULNERABLE
let small = big_value as u32;

// SAFE
if big_value <= u32::MAX as i128 {
    let small = big_value as u32;
}
```
