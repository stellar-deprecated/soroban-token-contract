use crate::public_types::Identifier;
use crate::storage_types::{AllowanceDataKey, DataKey};
use stellar_contract_sdk::Env;

pub fn read_allowance(e: &Env, from: Identifier, spender: Identifier) -> u64 {
    let key = DataKey::Allowance(AllowanceDataKey { from, spender });
    if e.has_contract_data(key.clone()) {
        e.get_contract_data(key)
    } else {
        0
    }
}

pub fn write_allowance(e: &Env, from: Identifier, spender: Identifier, amount: u64) {
    let key = DataKey::Allowance(AllowanceDataKey { from, spender });
    e.put_contract_data(key, amount);
}

pub fn spend_allowance(e: &Env, from: Identifier, spender: Identifier, amount: u64) {
    let allowance = read_allowance(e, from.clone(), spender.clone());
    if allowance < amount {
        panic!();
    }
    write_allowance(e, from, spender, allowance - amount);
}
