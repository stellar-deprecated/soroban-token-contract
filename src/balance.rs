use super::storage_types::DataKey;
use super::{Env, Identifier};

pub fn read_balance(e: &Env, id: Identifier) -> u64 {
    let key = DataKey::Balance(id);
    if e.has_contract_data(key.clone()) {
        e.get_contract_data(key)
    } else {
        0
    }
}

fn write_balance(e: &Env, id: Identifier, amount: u64) {
    let key = DataKey::Balance(id);
    e.put_contract_data(key, amount);
}

pub fn receive_balance(e: &Env, id: Identifier, amount: u64) {
    let balance = read_balance(e, id.clone());
    let is_frozen = read_state(e, id.clone());
    if is_frozen || u64::MAX - balance < amount {
        panic!();
    }
    write_balance(e, id, balance + amount);
}

pub fn spend_balance(e: &Env, id: Identifier, amount: u64) {
    let balance = read_balance(e, id.clone());
    let is_frozen = read_state(e, id.clone());
    if is_frozen || balance < amount {
        panic!();
    }
    write_balance(e, id, balance - amount);
}

pub fn read_state(e: &Env, id: Identifier) -> bool {
    let key = DataKey::State(id);
    if e.has_contract_data(key.clone()) {
        e.get_contract_data(key)
    } else {
        false
    }
}

pub fn write_state(e: &Env, id: Identifier, is_frozen: bool) {
    let key = DataKey::State(id);
    e.put_contract_data(key, is_frozen);
}
