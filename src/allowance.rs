use crate::public_types::Identifier;
use crate::storage_types::{AllowanceDataKey, DataKey};
use soroban_sdk::{BigInt, Env};

pub fn read_allowance(e: &Env, from: Identifier, spender: Identifier) -> BigInt {
    let key = DataKey::Allowance(AllowanceDataKey { from, spender });
    if e.contract_data().has(key.clone()) {
        e.contract_data().get(key)
    } else {
        BigInt::from_u32(e, 0)
    }
}

pub fn write_allowance(e: &Env, from: Identifier, spender: Identifier, amount: BigInt) {
    let key = DataKey::Allowance(AllowanceDataKey { from, spender });
    e.contract_data().set(key, amount);
}

pub fn spend_allowance(e: &Env, from: Identifier, spender: Identifier, amount: BigInt) {
    let allowance = read_allowance(e, from.clone(), spender.clone());
    if allowance < amount {
        panic!("insufficient allowance");
    }
    write_allowance(e, from, spender, allowance - amount);
}
