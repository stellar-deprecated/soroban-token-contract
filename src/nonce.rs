use crate::public_types::Identifier;
use crate::storage_types::DataKey;
use stellar_contract_sdk::{BigInt, Env};

pub fn read_nonce(e: &Env, id: Identifier) -> BigInt {
    let key = DataKey::Nonce(id);
    if e.contract_data().has(key.clone()) {
        e.contract_data().get(key.clone())
    } else {
        BigInt::from_u32(e, 0)
    }
}

pub fn read_and_increment_nonce(e: &Env, id: Identifier) -> BigInt {
    let key = DataKey::Nonce(id.clone());
    let nonce = read_nonce(e, id);
    e.contract_data().set(key, nonce.clone() + BigInt::from_u32(e, 1));
    nonce
}
