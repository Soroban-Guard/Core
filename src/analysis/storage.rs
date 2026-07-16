use std::collections::HashMap;

use super::AnalysisRule;
use crate::parser::ast::{Contract, SourcePos, StorageAccess, StorageType};
use crate::report::finding::Finding;
use crate::report::severity::Severity;

const GENERIC_KEY_NAMES: &[&str] = &[
    "balance", "owner", "admin", "config", "total", "count", "name", "symbol",
];

pub struct StorageCollisionDetector;

impl StorageCollisionDetector {
    fn location(contract: &Contract, pos: &SourcePos) -> String {
        if pos.line == 0 {
            contract.name.clone()
        } else {
            format!("{}:{}:{}", contract.name, pos.line, pos.column)
        }
    }

    fn is_short_key(key: &str) -> bool {
        key.len() <= 2 && key != "id"
    }

    fn is_generic_key(key: &str) -> bool {
        GENERIC_KEY_NAMES.contains(&key)
    }

    /// Group all storage accesses by key name across all functions.
    fn build_key_map(contract: &Contract) -> HashMap<String, Vec<(String, &StorageAccess)>> {
        let mut map: HashMap<String, Vec<(String, &StorageAccess)>> = HashMap::new();
        for func in &contract.functions {
            for access in &func.body_analysis.storage_writes {
                map.entry(access.key.clone())
                    .or_default()
                    .push((func.name.clone(), access));
            }
            for access in &func.body_analysis.storage_reads {
                map.entry(access.key.clone())
                    .or_default()
                    .push((func.name.clone(), access));
            }
        }
        map
    }

    // S-01: Short symbol keys (<= 2 chars)
    fn check_s01(
        contract: &Contract,
        key_map: &HashMap<String, Vec<(String, &StorageAccess)>>,
        out: &mut Vec<Finding>,
    ) {
        for (key, usages) in key_map {
            if Self::is_short_key(key) {
                let pos = &usages[0].1.position;
                out.push(Finding::new(
                    Severity::Medium,
                    "S-01",
                    format!(
                        "Short storage key '{}' may collide with other contracts",
                        key
                    ),
                    Self::location(contract, pos),
                    "Use descriptive namespaced keys like 'v1_contract_balance'",
                ));
            }
        }
    }

    // S-02: Generic storage key names
    fn check_s02(
        contract: &Contract,
        key_map: &HashMap<String, Vec<(String, &StorageAccess)>>,
        out: &mut Vec<Finding>,
    ) {
        for (key, usages) in key_map {
            if Self::is_generic_key(key) {
                let pos = &usages[0].1.position;
                out.push(Finding::new(
                    Severity::Low,
                    "S-02",
                    format!(
                        "Generic storage key '{}' \u{2014} consider adding a namespace prefix",
                        key
                    ),
                    Self::location(contract, pos),
                    "Prefix with contract version: 'v1_{contract_name}_{key}'",
                ));
            }
        }
    }

    // S-03: Mixed value types at the same key
    fn check_s03(
        contract: &Contract,
        key_map: &HashMap<String, Vec<(String, &StorageAccess)>>,
        out: &mut Vec<Finding>,
    ) {
        for (key, usages) in key_map {
            // Collect distinct value types from write operations
            let value_types: Vec<&(String, &StorageAccess)> = usages
                .iter()
                .filter(|(_, a)| a.value_type.is_some())
                .collect();

            if value_types.len() < 2 {
                continue;
            }

            // Check if there are different value expressions
            let mut seen_types: Vec<(&String, &StorageAccess)> = Vec::new();
            for ut in &value_types {
                let vt = ut.1.value_type.as_deref().unwrap_or("");
                if seen_types
                    .iter()
                    .all(|(_, a)| a.value_type.as_deref() != Some(vt))
                {
                    seen_types.push((&ut.0, ut.1));
                }
            }

            if seen_types.len() >= 2 {
                let (func_a, access_a) = seen_types[0];
                let (func_b, access_b) = seen_types[1];
                let type_a = access_a.value_type.as_deref().unwrap_or("unknown");
                let type_b = access_b.value_type.as_deref().unwrap_or("unknown");

                out.push(Finding::new(
                    Severity::High,
                    "S-03",
                    format!(
                        "Storage key '{}' written with different value types: '{}' in '{}' and '{}' in '{}'",
                        key, type_a, func_a, type_b, func_b,
                    ),
                    Self::location(contract, &access_a.position),
                    "Use the same Rust type for all writes to this key, or rename one of the keys",
                ));
            }
        }
    }

    // S-04: Instance/temporary confusion for the same key
    fn check_s04(
        contract: &Contract,
        key_map: &HashMap<String, Vec<(String, &StorageAccess)>>,
        out: &mut Vec<Finding>,
    ) {
        for (key, usages) in key_map {
            let has_instance = usages
                .iter()
                .any(|(_, a)| a.storage_type == StorageType::Instance);
            let has_temporary = usages
                .iter()
                .any(|(_, a)| a.storage_type == StorageType::Temporary);

            if has_instance && has_temporary {
                let pos = &usages[0].1.position;
                out.push(Finding::new(
                    Severity::High,
                    "S-04",
                    format!(
                        "Key '{}' accessed via both instance and temporary storage",
                        key,
                    ),
                    Self::location(contract, pos),
                    "Choose one storage type for this key",
                ));
            }
        }
    }

    // S-05: Missing version key
    fn check_s05(contract: &Contract, out: &mut Vec<Finding>) {
        let has_version = contract.storage_keys.iter().any(|k| {
            let lower = k.key.to_lowercase();
            lower.contains("version") || lower.contains("storage_version")
        });

        if !has_version {
            out.push(Finding::new(
                Severity::Info,
                "S-05",
                "No version key found \u{2014} upgrade could cause storage collisions",
                contract.name.clone(),
                "Store a VERSION key and use it as prefix for all other keys",
            ));
        }
    }
}

impl AnalysisRule for StorageCollisionDetector {
    fn id(&self) -> &'static str {
        "storage"
    }

    fn name(&self) -> &'static str {
        "Storage Collision Detector"
    }

    fn description(&self) -> &'static str {
        "Detects storage key collisions, short/generic keys, mixed types, and storage-type confusion"
    }

    fn analyze(&self, contract: &Contract) -> Vec<Finding> {
        let mut findings = Vec::new();
        let key_map = Self::build_key_map(contract);

        Self::check_s01(contract, &key_map, &mut findings);
        Self::check_s02(contract, &key_map, &mut findings);
        Self::check_s03(contract, &key_map, &mut findings);
        Self::check_s04(contract, &key_map, &mut findings);
        Self::check_s05(contract, &mut findings);

        findings
    }
}
