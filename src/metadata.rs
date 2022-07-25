use crate::storage_types::DataKey;
use stellar_contract_sdk::{Env, Vec};

pub fn read_decimal(e: &Env) -> u8 {
    let key = DataKey::Decimals;
    //TODO:should we return a default if entry doesn't exist
    e.get_contract_data(key.clone())
}

pub fn write_decimal(e: &Env, d: u8) {
    let key = DataKey::Decimals;
    e.put_contract_data(key, d)
}

pub fn read_name(e: &Env) -> Vec<u8> {
    let key = DataKey::Name;
    e.get_contract_data(key.clone())
}

pub fn write_name(e: &Env, d: Vec<u8>) {
    let key = DataKey::Name;
    e.put_contract_data(key, d)
}

pub fn read_symbol(e: &Env) -> Vec<u8> {
    let key = DataKey::Symbol;
    e.get_contract_data(key.clone())
}

pub fn write_symbol(e: &Env, d: Vec<u8>) {
    let key = DataKey::Symbol;
    e.put_contract_data(key, d)
}
