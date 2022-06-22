use super::storage_types::DataKey;
use super::{Env, Identifier};

pub fn read_and_increment_nonce(e: &Env, id: Identifier) -> u64 {
    let key = DataKey::Nonce(id);
    let nonce = if e.has_contract_data(key.clone()) {
        e.get_contract_data(key.clone())
    } else {
        0
    };
    e.put_contract_data(key, nonce + 1);
    nonce
}
