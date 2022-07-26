use crate::storage_types::DataKey;
use stellar_contract_sdk::{Binary, Env};

pub fn read_decimal(e: &Env) -> u32 {
    let key = DataKey::Decimals;
    e.get_contract_data(key.clone())
}

pub fn write_decimal(e: &Env, d: u8) {
    let key = DataKey::Decimals;
    e.put_contract_data(key, u32::from(d))
}

pub fn read_name(e: &Env) -> Binary {
    let key = DataKey::Name;
    e.get_contract_data(key.clone())
}

pub fn write_name(e: &Env, d: Binary) {
    let key = DataKey::Name;
    e.put_contract_data(key, d)
}

pub fn read_symbol(e: &Env) -> Binary {
    let key = DataKey::Symbol;
    e.get_contract_data(key.clone())
}

pub fn write_symbol(e: &Env, d: Binary) {
    let key = DataKey::Symbol;
    e.put_contract_data(key, d)
}
