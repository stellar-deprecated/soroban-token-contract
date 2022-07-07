use crate::public_types::Identifier;
use crate::storage_types::{AllowanceDataKey, DataKey};
use stellar_contract_sdk::{BigInt, Env};

pub fn read_allowance(e: &Env, from: Identifier, spender: Identifier) -> BigInt {
    let key = DataKey::Allowance(AllowanceDataKey { from, spender });
    if e.has_contract_data(key.clone()) {
        e.get_contract_data(key)
    } else {
        BigInt::from_u32(e, 0)
    }
}

pub fn write_allowance(e: &Env, from: Identifier, spender: Identifier, amount: BigInt) {
    let key = DataKey::Allowance(AllowanceDataKey { from, spender });
    e.put_contract_data(key, amount);
}

pub fn spend_allowance(e: &Env, from: Identifier, spender: Identifier, amount: BigInt) {
    let allowance = read_allowance(e, from.clone(), spender.clone());
    if allowance < amount {
        panic!();
    }
    write_allowance(e, from, spender, allowance - amount);
}
