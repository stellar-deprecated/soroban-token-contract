use crate::public_types::{
    Authorization, Identifier, KeyedAccountAuthorization, KeyedAuthorization,
    KeyedEd25519Authorization,
};
use crate::storage_types::DataKey;
use stellar_contract_sdk::Env;

pub fn has_administrator(e: &Env) -> bool {
    let key = DataKey::Administrator;
    e.has_contract_data(key)
}

fn read_administrator(e: &Env) -> Identifier {
    let key = DataKey::Administrator;
    e.get_contract_data(key)
}

pub fn to_administrator_authorization(e: &Env, auth: Authorization) -> KeyedAuthorization {
    let admin = read_administrator(e);
    match (admin, auth) {
        (Identifier::Contract(admin_id), Authorization::Contract) => {
            if admin_id != e.get_invoking_contract() {
                panic!();
            }
            KeyedAuthorization::Contract
        }
        (Identifier::Ed25519(admin_id), Authorization::Ed25519(ea)) => {
            KeyedAuthorization::Ed25519(KeyedEd25519Authorization {
                public_key: admin_id,
                auth: ea,
            })
        }
        (Identifier::Account(admin_id), Authorization::Account(aa)) => {
            KeyedAuthorization::Account(KeyedAccountAuthorization {
                public_key: admin_id,
                auth: aa,
            })
        }
        _ => panic!(),
    }
}

pub fn write_administrator(e: &Env, id: Identifier) {
    let key = DataKey::Administrator;
    e.put_contract_data(key, id);
}
