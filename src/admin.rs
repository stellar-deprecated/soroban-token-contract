use crate::storage_types::DataKey;
use soroban_authorization_contract::public_types::{Identifier, KeyedAuthorization};
use soroban_sdk::Env;

pub fn has_administrator(e: &Env) -> bool {
    let key = DataKey::Admin;
    e.contract_data().has(key)
}

fn read_administrator(e: &Env) -> Identifier {
    let key = DataKey::Admin;
    e.contract_data().get_unchecked(key).unwrap()
}

pub fn write_administrator(e: &Env, id: Identifier) {
    let key = DataKey::Admin;
    e.contract_data().set(key, id);
}

pub fn check_admin(e: &Env, auth: &KeyedAuthorization) {
    let auth_id = auth.get_identifier(&e);
    if auth_id != read_administrator(&e) {
        panic!("not authorized by admin")
    }
}
