use crate::public_types::Identifier;
use crate::storage_types::DataKey;
use stellar_contract_sdk::{BigInt, Env};

pub fn read_balance(e: &Env, id: Identifier) -> BigInt {
    let key = DataKey::Balance(id);
    if e.has_contract_data(key.clone()) {
        e.get_contract_data(key)
    } else {
        BigInt::from_u32(e, 0)
    }
}

fn write_balance(e: &Env, id: Identifier, amount: BigInt) {
    let key = DataKey::Balance(id);
    e.put_contract_data(key, amount);
}

pub fn receive_balance(e: &Env, id: Identifier, amount: BigInt) {
    let balance = read_balance(e, id.clone());
    let is_frozen = read_state(e, id.clone());
    if is_frozen {
        panic!("can't receive when frozen");
    }
    write_balance(e, id, balance + amount);
}

pub fn spend_balance(e: &Env, id: Identifier, amount: BigInt) {
    let balance = read_balance(e, id.clone());
    let is_frozen = read_state(e, id.clone());
    if is_frozen {
        panic!("can't spend when frozen");
    }
    if balance < amount {
        panic!("insufficient balance");
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
