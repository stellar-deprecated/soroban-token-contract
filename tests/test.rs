use ed25519_dalek::Keypair;
use external::MessageWithoutNonce as ContractFn;
use rand::thread_rng;
use stellar_contract_sdk::Env;
use stellar_token_contract::external;

fn generate_keypair() -> Keypair {
    Keypair::generate(&mut thread_rng())
}

fn make_auth(kp: &Keypair, msg: &external::Message) -> external::Authorization {
    use external::{Authorization, Ed25519Authorization};
    let signature = msg.sign(kp).unwrap();
    Authorization::Ed25519(Ed25519Authorization {
        nonce: msg.0.clone(),
        signature,
    })
}

fn make_keyed_auth(kp: &Keypair, msg: &external::Message) -> external::KeyedAuthorization {
    use external::{Ed25519Authorization, KeyedAuthorization, KeyedEd25519Authorization};
    let signature = msg.sign(kp).unwrap();
    KeyedAuthorization::Ed25519(KeyedEd25519Authorization {
        public_key: kp.public.to_bytes(),
        auth: Ed25519Authorization {
            nonce: msg.0.clone(),
            signature,
        },
    })
}

fn sign_ed25519_then_do(e: &mut Env, contract_id: &[u8; 32], kp: &Keypair, cf: ContractFn) {
    let nonce = external::nonce(e, contract_id, &(kp.into()));
    let msg = external::Message(nonce, cf);
    match &msg.1 {
        ContractFn::Approve(id, amount) => {
            external::approve(e, contract_id, &make_keyed_auth(kp, &msg), id, amount);
        }
        ContractFn::Transfer(to, amount) => {
            external::xfer(e, contract_id, &make_keyed_auth(kp, &msg), to, amount);
        }
        ContractFn::TransferFrom(from, to, amount) => {
            external::xfer_from(e, contract_id, &make_keyed_auth(kp, &msg), from, to, amount);
        }
        ContractFn::Burn(from, amount) => {
            external::burn(e, contract_id, &make_auth(kp, &msg), from, amount);
        }
        ContractFn::Freeze(id) => {
            external::freeze(e, contract_id, &make_auth(kp, &msg), id);
        }
        ContractFn::Mint(to, amount) => {
            external::mint(e, contract_id, &make_auth(kp, &msg), to, amount);
        }
        ContractFn::SetAdministrator(id) => {
            external::set_admin(e, contract_id, &make_auth(kp, &msg), id);
        }
        ContractFn::Unfreeze(id) => {
            external::unfreeze(e, contract_id, &make_auth(kp, &msg), id);
        }
    }
}

#[test]
fn test() {
    use external::{allowance, balance, is_frozen, nonce};

    let mut e = Env::with_empty_recording_storage();
    let contract_id: [u8; 32] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
        0, 1,
    ];
    external::register_test_contract(&e, &contract_id);

    let admin1 = generate_keypair();
    let admin2 = generate_keypair();
    let id1 = generate_keypair();
    let id2 = generate_keypair();
    let id3 = generate_keypair();

    external::initialize(&mut e, &contract_id, &(&admin1).into());

    sign_ed25519_then_do(
        &mut e,
        &contract_id,
        &admin1,
        ContractFn::Mint((&id1).into(), 1000u64.into()),
    );
    assert_eq!(
        balance(&mut e, &contract_id, &(&id1).into()),
        1000u64.into()
    );
    assert_eq!(nonce(&mut e, &contract_id, &(&admin1).into()), 1u64.into());

    sign_ed25519_then_do(
        &mut e,
        &contract_id,
        &id2,
        ContractFn::Approve((&id3).into(), 500u64.into()),
    );
    assert_eq!(
        allowance(&mut e, &contract_id, &(&id2).into(), &(&id3).into()),
        500u64.into()
    );
    assert_eq!(nonce(&mut e, &contract_id, &(&id2).into()), 1u64.into());

    sign_ed25519_then_do(
        &mut e,
        &contract_id,
        &id1,
        ContractFn::Transfer((&id2).into(), 600u64.into()),
    );
    assert_eq!(balance(&mut e, &contract_id, &(&id1).into()), 400u64.into());
    assert_eq!(balance(&mut e, &contract_id, &(&id2).into()), 600u64.into());
    assert_eq!(nonce(&mut e, &contract_id, &(&id1).into()), 1u64.into());

    sign_ed25519_then_do(
        &mut e,
        &contract_id,
        &id3,
        ContractFn::TransferFrom((&id2).into(), (&id1).into(), 400u64.into()),
    );
    assert_eq!(
        allowance(&mut e, &contract_id, &(&id2).into(), &(&id3).into()),
        100u64.into()
    );
    assert_eq!(balance(&mut e, &contract_id, &(&id1).into()), 800u64.into());
    assert_eq!(balance(&mut e, &contract_id, &(&id2).into()), 200u64.into());
    assert_eq!(nonce(&mut e, &contract_id, &(&id3).into()), 1u64.into());

    sign_ed25519_then_do(
        &mut e,
        &contract_id,
        &id1,
        ContractFn::Transfer((&id3).into(), 300u64.into()),
    );
    assert_eq!(balance(&mut e, &contract_id, &(&id1).into()), 500u64.into());
    assert_eq!(balance(&mut e, &contract_id, &(&id3).into()), 300u64.into());
    assert_eq!(nonce(&mut e, &contract_id, &(&id1).into()), 2u64.into());

    sign_ed25519_then_do(
        &mut e,
        &contract_id,
        &admin1,
        ContractFn::SetAdministrator((&admin2).into()),
    );
    assert_eq!(nonce(&mut e, &contract_id, &(&id1).into()), 2u64.into());

    sign_ed25519_then_do(
        &mut e,
        &contract_id,
        &admin2,
        ContractFn::Freeze((&id2).into()),
    );
    assert_eq!(is_frozen(&mut e, &contract_id, &(&id2).into()), true);
    assert_eq!(nonce(&mut e, &contract_id, &(&admin2).into()), 1u64.into());

    sign_ed25519_then_do(
        &mut e,
        &contract_id,
        &admin2,
        ContractFn::Unfreeze((&id3).into()),
    );
    assert_eq!(is_frozen(&mut e, &contract_id, &(&id3).into()), false);
    assert_eq!(nonce(&mut e, &contract_id, &(&admin2).into()), 2u64.into());

    sign_ed25519_then_do(
        &mut e,
        &contract_id,
        &admin2,
        ContractFn::Burn((&id3).into(), 100u64.into()),
    );
    assert_eq!(balance(&mut e, &contract_id, &(&id3).into()), 200u64.into());
    assert_eq!(nonce(&mut e, &contract_id, &(&admin2).into()), 3u64.into());
}
