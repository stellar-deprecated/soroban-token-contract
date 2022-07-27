use crate::public_types::Identifier;
use crate::storage_types::DataKey;
use stellar_contract_sdk::{BigInt, Env};

pub fn read_balance(e: &Env, id: Identifier) -> BigInt {
    let key = DataKey::Balance(id);
    if e.contract_data().has(key.clone()) {
        e.contract_data().get(key)
    } else {
        BigInt::from_u32(e, 0)
    }
}

fn write_balance(e: &Env, id: Identifier, amount: BigInt) {
    let key = DataKey::Balance(id);
    e.contract_data().set(key, amount);
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
    if e.contract_data().has(key.clone()) {
        e.contract_data().get(key)
    } else {
        false
    }
}

pub fn write_state(e: &Env, id: Identifier, is_frozen: bool) {
    let key = DataKey::State(id);
    e.contract_data().set(key, is_frozen);
}
