use crate::public_types::Identifier;
use crate::storage_types::DataKey;
use stellar_contract_sdk::{BigInt, Env};

pub fn read_nonce(e: &Env, id: Identifier) -> BigInt {
    let key = DataKey::Nonce(id);
    if e.has_contract_data(key.clone()) {
        e.get_contract_data(key.clone())
    } else {
        0
    }
}

pub fn read_and_increment_nonce(e: &Env, id: Identifier) -> BigInt {
    let key = DataKey::Nonce(id.clone());
    let nonce = read_nonce(e, id);
    e.put_contract_data(key, nonce + 1);
    nonce
}
