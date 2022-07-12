use crate::nonce::read_and_increment_nonce;
use crate::public_types::{
    Identifier, KeyedAccountAuthorization, KeyedAuthorization, KeyedEd25519Authorization, Message,
    MessageV0, U256,
};
use stellar_contract_sdk::{Env, EnvVal};

#[repr(u32)]
pub enum Domain {
    Approve = 0,
    Transfer = 1,
    TransferFrom = 2,
    Burn = 3,
    Freeze = 4,
    Mint = 5,
    SetAdministrator = 6,
    Unfreeze = 7,
}

fn check_ed25519_auth(
    e: &Env,
    auth: KeyedEd25519Authorization,
    domain: Domain,
    parameters: EnvVal,
) {
    let msg = MessageV0 {
        nonce: read_and_increment_nonce(&e, Identifier::Ed25519(auth.public_key.clone())),
        domain: domain as u32,
        parameters: parameters.try_into().unwrap(),
    };
    let msg_bin = e.compute_hash_sha256(e.serialize_to_binary(Message::V0(msg)));

    e.verify_sig_ed25519(auth.auth.signature.into(), auth.public_key.into(), msg_bin);
}

fn check_account_auth(
    e: &Env,
    auth: KeyedAccountAuthorization,
    domain: Domain,
    parameters: EnvVal,
) {
    use stellar_contract_sdk::Binary;
    let acc_id: Binary = auth.public_key.clone().into();

    let msg = MessageV0 {
        nonce: read_and_increment_nonce(&e, Identifier::Account(auth.public_key)),
        domain: domain as u32,
        parameters: parameters.try_into().unwrap(),
    };
    let msg_bin = e.compute_hash_sha256(e.serialize_to_binary(Message::V0(msg)));

    let threshold = e.account_get_medium_threshold(acc_id.clone());
    let mut weight = 0u32;

    let sigs = &auth.auth.signatures;
    let mut prev_pk: Option<U256> = None;
    for sig in sigs.iter().map(|x| x.unwrap()) {
        // Cannot take multiple signatures from the same key
        if let Some(prev) = prev_pk {
            if prev >= sig.public_key {
                panic!()
            }
        }

        e.verify_sig_ed25519(
            sig.signature.into(),
            sig.public_key.clone().into(),
            msg_bin.clone(),
        );
        // TODO: Check for overflow
        weight += e.account_get_signer_weight(acc_id.clone(), sig.public_key.clone().into());

        prev_pk = Some(sig.public_key);
    }

    if weight < threshold {
        panic!()
    }
}

pub fn check_auth(e: &Env, auth: KeyedAuthorization, domain: Domain, parameters: EnvVal) {
    match auth {
        KeyedAuthorization::Contract => {
            e.get_invoking_contract();
        }
        KeyedAuthorization::Ed25519(kea) => check_ed25519_auth(e, kea, domain, parameters),
        KeyedAuthorization::Account(kaa) => check_account_auth(e, kaa, domain, parameters),
    }
}
