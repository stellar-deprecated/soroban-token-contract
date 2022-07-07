#![cfg(test)]

use std::vec::Vec as ExternalVec;

use crate::contract;
use crate::cryptography::Domain;
use crate::public_types::{
    Authorization, Ed25519Authorization, Identifier, KeyedAuthorization, KeyedEd25519Authorization,
    U256, U512,
};
use ed25519_dalek::{Keypair, Signer};
use rand::thread_rng;
use stellar_contract_sdk::{BigInt, Binary, Env, FixedLengthBinary, VariableLengthBinary};
use stellar_xdr::{ScMap, ScMapEntry, ScObject, ScStatic, ScVal, ScVec, WriteXdr};

fn str_to_symbol(s: &str) -> ScVal {
    use std::vec::Vec;
    let v: Vec<u8> = s.as_bytes().iter().cloned().collect();
    ScVal::Symbol(v.try_into().unwrap())
}

fn generate_keypair() -> Keypair {
    Keypair::generate(&mut thread_rng())
}

fn binary_from_keypair(e: &Env, kp: &Keypair) -> U256 {
    let mut bin = Binary::new(e);
    for byte in kp.public.to_bytes() {
        bin.push(byte);
    }
    bin.try_into().unwrap()
}

struct ExternalMessageV0 {
    nonce: u64,
    domain: Domain,
    parameters: ScVec,
}

impl From<ExternalMessageV0> for ScVal {
    fn from(msg: ExternalMessageV0) -> Self {
        let mut msg_vec = ExternalVec::new();
        msg_vec.push(ScMapEntry {
            key: str_to_symbol("domain"),
            val: ScVal::U32(msg.domain as u32),
        });
        msg_vec.push(ScMapEntry {
            key: str_to_symbol("nonce"),
            val: ScVal::Object(Some(ScObject::U64(msg.nonce))),
        });
        msg_vec.push(ScMapEntry {
            key: str_to_symbol("parameters"),
            val: ScVal::Object(Some(ScObject::Vec(msg.parameters))),
        });
        ScVal::Object(Some(ScObject::Map(ScMap(msg_vec.try_into().unwrap()))))
    }
}

enum ExternalMessage {
    V0(ExternalMessageV0),
}

// TODO: Why is this ScObject and not ScVal?
impl From<ExternalMessage> for ScObject {
    fn from(msg: ExternalMessage) -> Self {
        let mut msg_vec = ExternalVec::new();
        match msg {
            ExternalMessage::V0(v0) => {
                msg_vec.push(ScVal::U32(0));
                msg_vec.push(v0.into());
            }
        };
        ScObject::Vec(ScVec(msg_vec.try_into().unwrap()))
    }
}

fn sign(e: &Env, kp: &Keypair, msg: ExternalMessageV0) -> U512 {
    use sha2::Digest;

    let mut buf = ExternalVec::<u8>::new();
    let msg: ScObject = ExternalMessage::V0(msg).into();
    msg.write_xdr(&mut buf).unwrap();

    let mut bin = Binary::new(e);
    for b in kp.sign(sha2::Sha256::digest(&buf).as_slice()).to_bytes() {
        bin.push(b);
    }
    bin.try_into().unwrap()
}

fn do_initialize(e: &Env, admin: &Identifier) {
    contract::initialize(e.clone(), admin.clone());
}

fn do_approve(e: &Env, kp: &Keypair, spender: &Identifier, amount: u64) {
    let from_bin = binary_from_keypair(e, kp);
    let from_id = Identifier::Ed25519(from_bin.clone());

    let nonce = contract::nonce(e.clone(), from_id);
    let msg = ExternalMessageV0 {
        nonce,
        domain: Domain::Approve,
        parameters: ScVec(
            vec![
                spender.clone().into(),
                ScVal::Object(Some(ScObject::U64(amount))),
            ]
            .try_into()
            .unwrap(),
        ),
    };

    let auth = KeyedAuthorization::Ed25519(KeyedEd25519Authorization {
        public_key: from_bin,
        auth: Ed25519Authorization {
            nonce,
            signature: sign(e, kp, msg),
        },
    });
    contract::approve(e.clone(), auth, spender.clone(), amount);
}

fn do_transfer(e: &Env, kp: &Keypair, to: &Identifier, amount: u64) {
    let from_bin = binary_from_keypair(e, kp);
    let from_id = Identifier::Ed25519(from_bin.clone());

    let nonce = contract::nonce(e.clone(), from_id);
    let msg = ExternalMessageV0 {
        nonce,
        domain: Domain::Transfer,
        parameters: ScVec(
            vec![
                to.clone().into(),
                ScVal::Object(Some(ScObject::U64(amount))),
            ]
            .try_into()
            .unwrap(),
        ),
    };

    let auth = KeyedAuthorization::Ed25519(KeyedEd25519Authorization {
        public_key: from_bin,
        auth: Ed25519Authorization {
            nonce,
            signature: sign(e, kp, msg),
        },
    });
    contract::xfer(e.clone(), auth, to.clone(), amount);
}

fn do_transfer_from(e: &Env, kp: &Keypair, from: &Identifier, to: &Identifier, amount: u64) {
    let spender_bin = binary_from_keypair(e, kp);
    let spender_id = Identifier::Ed25519(spender_bin.clone());

    let nonce = contract::nonce(e.clone(), spender_id);
    let msg = ExternalMessageV0 {
        nonce,
        domain: Domain::TransferFrom,
        parameters: ScVec(
            vec![
                from.clone().into(),
                to.clone().into(),
                ScVal::Object(Some(ScObject::U64(amount))),
            ]
            .try_into()
            .unwrap(),
        ),
    };

    let auth = KeyedAuthorization::Ed25519(KeyedEd25519Authorization {
        public_key: spender_bin,
        auth: Ed25519Authorization {
            nonce,
            signature: sign(e, kp, msg),
        },
    });
    contract::xfer_from(e.clone(), auth, from.clone(), to.clone(), amount);
}

fn do_burn(e: &Env, kp: &Keypair, from: &Identifier, amount: u64) {
    let admin = Identifier::Ed25519(binary_from_keypair(e, kp));

    let nonce = contract::nonce(e.clone(), admin);
    let msg = ExternalMessageV0 {
        nonce,
        domain: Domain::Burn,
        parameters: ScVec(
            vec![
                from.clone().into(),
                ScVal::Object(Some(ScObject::U64(amount))),
            ]
            .try_into()
            .unwrap(),
        ),
    };

    let auth = Authorization::Ed25519(Ed25519Authorization {
        nonce,
        signature: sign(e, kp, msg),
    });
    contract::burn(e.clone(), auth, from.clone(), amount);
}

fn do_freeze(e: &Env, kp: &Keypair, id: &Identifier) {
    let admin = Identifier::Ed25519(binary_from_keypair(e, kp));

    let nonce = contract::nonce(e.clone(), admin);
    let msg = ExternalMessageV0 {
        nonce,
        domain: Domain::Freeze,
        parameters: ScVec(
            vec![id.clone().into(), ScVal::Static(ScStatic::Void)]
                .try_into()
                .unwrap(),
        ),
    };

    let auth = Authorization::Ed25519(Ed25519Authorization {
        nonce,
        signature: sign(e, kp, msg),
    });
    contract::freeze(e.clone(), auth, id.clone());
}

fn do_mint(e: &Env, kp: &Keypair, to: &Identifier, amount: u64) {
    let admin = Identifier::Ed25519(binary_from_keypair(e, kp));

    let nonce = contract::nonce(e.clone(), admin);
    let msg = ExternalMessageV0 {
        nonce,
        domain: Domain::Mint,
        parameters: ScVec(
            vec![
                to.clone().into(),
                ScVal::Object(Some(ScObject::U64(amount))),
            ]
            .try_into()
            .unwrap(),
        ),
    };

    let auth = Authorization::Ed25519(Ed25519Authorization {
        nonce,
        signature: sign(e, kp, msg),
    });
    contract::mint(e.clone(), auth, to.clone(), amount);
}

fn do_set_admin(e: &Env, kp: &Keypair, new_admin: &Identifier) {
    let admin = Identifier::Ed25519(binary_from_keypair(e, kp));

    let nonce = contract::nonce(e.clone(), admin);
    let msg = ExternalMessageV0 {
        nonce,
        domain: Domain::SetAdministrator,
        parameters: ScVec(
            vec![new_admin.clone().into(), ScVal::Static(ScStatic::Void)]
                .try_into()
                .unwrap(),
        ),
    };

    let auth = Authorization::Ed25519(Ed25519Authorization {
        nonce,
        signature: sign(e, kp, msg),
    });
    contract::set_admin(e.clone(), auth, new_admin.clone());
}

fn do_unfreeze(e: &Env, kp: &Keypair, id: &Identifier) {
    let admin = Identifier::Ed25519(binary_from_keypair(e, kp));

    let nonce = contract::nonce(e.clone(), admin);
    let msg = ExternalMessageV0 {
        nonce,
        domain: Domain::Unfreeze,
        parameters: ScVec(
            vec![id.clone().into(), ScVal::Static(ScStatic::Void)]
                .try_into()
                .unwrap(),
        ),
    };

    let auth = Authorization::Ed25519(Ed25519Authorization {
        nonce,
        signature: sign(e, kp, msg),
    });
    contract::unfreeze(e.clone(), auth, id.clone());
}

impl From<Identifier> for ScVal {
    fn from(id: Identifier) -> Self {
        let mut vec = ExternalVec::new();
        match id {
            Identifier::Ed25519(u256) => {
                let mut bin = ExternalVec::new();
                for i in 0..u256.len() {
                    bin.push(u256.get(i));
                }

                vec.push(ScVal::U32(1));
                vec.push(ScVal::Object(Some(ScObject::Binary(
                    bin.try_into().unwrap(),
                ))));
            }
            _ => todo!(),
        };
        ScVal::Object(Some(ScObject::Vec(ScVec(vec.try_into().unwrap()))))
    }
}

#[test]
fn test_every_function() {
    let e = Env::with_empty_recording_storage();
    let _fg = e.push_test_frame(binary_from_keypair(&e, &generate_keypair()));

    let admin_kp1 = generate_keypair();
    let admin_id1 = Identifier::Ed25519(binary_from_keypair(&e, &admin_kp1));
    let admin_kp2 = generate_keypair();
    let admin_id2 = Identifier::Ed25519(binary_from_keypair(&e, &admin_kp2));

    let kp1 = generate_keypair();
    let id1 = Identifier::Ed25519(binary_from_keypair(&e, &kp1));
    let kp2 = generate_keypair();
    let id2 = Identifier::Ed25519(binary_from_keypair(&e, &kp2));
    let kp3 = generate_keypair();
    let id3 = Identifier::Ed25519(binary_from_keypair(&e, &kp3));

    do_initialize(&e, &admin_id1);

    do_mint(&e, &admin_kp1, &id1, 1000);
    assert_eq!(contract::balance(e.clone(), id1.clone()), 1000);
    assert_eq!(contract::nonce(e.clone(), admin_id1.clone()), 1);

    do_approve(&e, &kp2, &id3, 500);
    assert_eq!(contract::allowance(e.clone(), id2.clone(), id3.clone()), 500);
    assert_eq!(contract::nonce(e.clone(), id2.clone()), 1);

    do_transfer(&e, &kp1, &id2, 600);
    assert_eq!(contract::balance(e.clone(), id1.clone()), 400);
    assert_eq!(contract::balance(e.clone(), id2.clone()), 600);
    assert_eq!(contract::nonce(e.clone(), id1.clone()), 1);

    do_transfer_from(&e, &kp3, &id2, &id1, 400);
    assert_eq!(contract::allowance(e.clone(), id2.clone(), id3.clone()), 100);
    assert_eq!(contract::balance(e.clone(), id1.clone()), 800);
    assert_eq!(contract::balance(e.clone(), id2.clone()), 200);
    assert_eq!(contract::nonce(e.clone(), id3.clone()), 1);

    do_transfer(&e, &kp1, &id3, 300);
    assert_eq!(contract::balance(e.clone(), id1.clone()), 500);
    assert_eq!(contract::balance(e.clone(), id3.clone()), 300);
    assert_eq!(contract::nonce(e.clone(), id1.clone()), 2);

    do_set_admin(&e, &admin_kp1, &admin_id2);
    assert_eq!(contract::nonce(e.clone(), admin_id1.clone()), 2);

    do_freeze(&e, &admin_kp2, &id2);
    assert_eq!(contract::is_frozen(e.clone(), id2.clone()), true);
    assert_eq!(contract::nonce(e.clone(), admin_id2.clone()), 1);

    do_unfreeze(&e, &admin_kp2, &id3);
    assert_eq!(contract::is_frozen(e.clone(), id3.clone()), false);
    assert_eq!(contract::nonce(e.clone(), admin_id2.clone()), 2);

    do_burn(&e, &admin_kp2, &id3, 100);
    assert_eq!(contract::balance(e.clone(), id3.clone()), 200);
    assert_eq!(contract::nonce(e.clone(), admin_id2.clone()), 3);
}
