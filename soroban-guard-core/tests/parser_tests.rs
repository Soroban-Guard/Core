use soroban_guard_core::parser::{ast::*, ContractParser};

#[test]
fn test_parse_vault_fixture() {
    let parser = ContractParser::new();
    let contract = parser
        .parse_file("tests/fixtures/simple_vault.rs")
        .expect("Failed to parse fixture file");

    assert_eq!(contract.name, "SimpleVault");
    assert_eq!(contract.functions.len(), 5);

    // Verify constructor
    let constructor = &contract.functions[0];
    assert_eq!(constructor.name, "__constructor");
    assert!(constructor.is_init);
    assert_eq!(constructor.args.len(), 2);
    assert!(constructor.body_analysis.storage_writes.len() >= 1);

    // Verify deposit function
    let deposit = &contract.functions[1];
    assert_eq!(deposit.name, "deposit");
    assert_eq!(deposit.args.len(), 3);
    assert_eq!(deposit.args[0].name, "env");
    assert_eq!(deposit.args[1].name, "from");
    assert_eq!(deposit.args[2].name, "amount");
    assert_eq!(deposit.return_type, "()");

    // Verify auth check on deposit
    assert_eq!(deposit.body_analysis.auth_checks.len(), 1);
    assert_eq!(deposit.body_analysis.auth_checks[0].kind, AuthKind::RequireAuth);

    // Verify storage ops in deposit
    assert!(deposit.body_analysis.storage_reads.len() >= 1);
    assert!(deposit.body_analysis.storage_writes.len() >= 1);

    // Verify cross-contract call in transfer
    let transfer = &contract.functions[3];
    assert_eq!(transfer.name, "transfer");
    assert_eq!(transfer.body_analysis.cross_contract_calls.len(), 1);
    let xcc = &transfer.body_analysis.cross_contract_calls[0];
    assert_eq!(xcc.function, "transfer");
    assert_eq!(xcc.target, "token_id");
    assert_eq!(xcc.args_count, 2);
    // Source position should be resolved to the real call site, not a 0/0 stub.
    assert!(xcc.position.line > 0);
    assert!(transfer.body_analysis.calls_external);

    // The token contract dependency should be recorded on the contract.
    assert!(contract.dependencies.contains(&"token_id".to_string()));

    // check_balance only reads storage — no writes, no auth, no calls.
    let check_balance = &contract.functions[4];
    assert_eq!(check_balance.name, "check_balance");
    assert!(check_balance.body_analysis.storage_reads.len() >= 1);
    assert_eq!(check_balance.body_analysis.storage_writes.len(), 0);
    assert_eq!(check_balance.body_analysis.auth_checks.len(), 0);

    // Storage keys are aggregated at the contract level.
    assert!(contract
        .storage_keys
        .iter()
        .any(|k| k.key == "balance" && matches!(k.key_type, StorageKeyType::Symbol)));
}
