use crate::public_types::{
    Authorization, Identifier, KeyedAccountAuthorization, KeyedAuthorization, KeyedEd25519Signature,
};
use crate::storage_types::DataKey;
use soroban_sdk::Env;

pub fn has_administrator(e: &Env) -> bool {
    let key = DataKey::Admin;
    e.contract_data().has(key)
}

fn read_administrator(e: &Env) -> Identifier {
    let key = DataKey::Admin;
    e.contract_data().get_unchecked(key).unwrap()
}

pub fn to_administrator_authorization(e: &Env, auth: Authorization) -> KeyedAuthorization {
    let admin = read_administrator(e);
    match (admin, auth) {
        (Identifier::Contract(admin_id), Authorization::Contract) => {
            if admin_id != e.get_invoking_contract() {
                panic!("admin is not invoking contract");
            }
            KeyedAuthorization::Contract
        }
        (Identifier::Ed25519(admin_id), Authorization::Ed25519(signature)) => {
            KeyedAuthorization::Ed25519(KeyedEd25519Signature {
                public_key: admin_id,
                signature,
            })
        }
        (Identifier::Account(admin_id), Authorization::Account(signatures)) => {
            KeyedAuthorization::Account(KeyedAccountAuthorization {
                public_key: admin_id,
                signatures,
            })
        }
        _ => panic!("unknown identifier type"),
    }
}

pub fn write_administrator(e: &Env, id: Identifier) {
    let key = DataKey::Admin;
    e.contract_data().set(key, id);
}
