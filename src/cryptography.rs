use crate::nonce::read_and_increment_nonce;
use crate::public_types::{
    Identifier, KeyedAccountAuthorization, KeyedAuthorization, KeyedEd25519Authorization, Message,
    MessageV0, U256,
};
use soroban_sdk::serde::Serialize;
use soroban_sdk::{Account, Env, EnvVal};

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
    let msg_bin = Message::V0(msg).serialize(e);

    e.verify_sig_ed25519(auth.public_key.into(), msg_bin, auth.signature.into());
}

fn check_account_auth(
    e: &Env,
    auth: KeyedAccountAuthorization,
    domain: Domain,
    parameters: EnvVal,
) {
    let acc = Account::from_public_key(&auth.public_key).unwrap();

    let msg = MessageV0 {
        nonce: read_and_increment_nonce(&e, Identifier::Account(auth.public_key)),
        domain: domain as u32,
        parameters: parameters.try_into().unwrap(),
    };
    let msg_bin = Message::V0(msg).serialize(e);

    let threshold = acc.medium_threshold();
    let mut weight = 0u32;

    let sigs = &auth.auth.signatures;
    let mut prev_pk: Option<U256> = None;
    for sig in sigs.iter().map(Result::unwrap) {
        // Cannot take multiple signatures from the same key
        if let Some(prev) = prev_pk {
            if prev >= sig.public_key {
                panic!("signature out of order")
            }
        }

        e.verify_sig_ed25519(
            sig.public_key.clone().into(),
            msg_bin.clone(),
            sig.signature.into(),
        );
        // TODO: Check for overflow
        weight += acc.signer_weight(&sig.public_key);

        prev_pk = Some(sig.public_key);
    }

    if weight < threshold {
        panic!("insufficient signing weight")
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
