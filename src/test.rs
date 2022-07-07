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
use stellar_contract_sdk::{Binary, Env, FixedLengthBinary, VariableLengthBinary};
use stellar_xdr::{ScBigInt, ScMap, ScMapEntry, ScObject, ScStatic, ScVal, ScVec, WriteXdr};

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

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExternalBigInt(num_bigint::BigInt);

impl<T> From<T> for ExternalBigInt
where
    num_bigint::BigInt: From<T>,
{
    fn from(x: T) -> Self {
        ExternalBigInt(x.into())
    }
}

impl From<ExternalBigInt> for ScVal {
    fn from(ebi: ExternalBigInt) -> Self {
        use num_bigint::Sign;
        let scbi = match ebi.0.to_bytes_be() {
            (Sign::NoSign, _) => ScBigInt::Zero,
            (Sign::Plus, data) => ScBigInt::Positive(data.try_into().unwrap()),
            (Sign::Minus, data) => ScBigInt::Negative(data.try_into().unwrap()),
        };
        ScVal::Object(Some(ScObject::BigInt(scbi)))
    }
}

fn bigint_from_external(e: &Env, ebi: &ExternalBigInt) -> stellar_contract_sdk::BigInt {
    stellar_contract_sdk::BigInt::from_u64(e, (&ebi.0).try_into().unwrap())
}

struct ExternalMessageV0 {
    nonce: ExternalBigInt,
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
            val: msg.nonce.into(),
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

fn do_nonce(e: &Env, id: &Identifier) -> ExternalBigInt {
    let nonce: u64 = contract::nonce(e.clone(), id.clone()).try_into().unwrap();
    ExternalBigInt(num_bigint::BigInt::from(nonce))
}

fn do_allowance(e: &Env, from: &Identifier, spender: &Identifier) -> ExternalBigInt {
    let allowance: u64 = contract::allowance(e.clone(), from.clone(), spender.clone())
        .try_into()
        .unwrap();
    ExternalBigInt(num_bigint::BigInt::from(allowance))
}

fn do_approve(e: &Env, kp: &Keypair, spender: &Identifier, amount: ExternalBigInt) {
    let from_bin = binary_from_keypair(e, kp);
    let from_id = Identifier::Ed25519(from_bin.clone());

    let nonce = do_nonce(e, &from_id);
    let msg = ExternalMessageV0 {
        nonce: nonce.clone(),
        domain: Domain::Approve,
        parameters: ScVec(
            vec![spender.clone().into(), amount.clone().into()]
                .try_into()
                .unwrap(),
        ),
    };

    let auth = KeyedAuthorization::Ed25519(KeyedEd25519Authorization {
        public_key: from_bin,
        auth: Ed25519Authorization {
            nonce: bigint_from_external(e, &nonce),
            signature: sign(e, kp, msg),
        },
    });
    contract::approve(
        e.clone(),
        auth,
        spender.clone(),
        bigint_from_external(e, &amount),
    );
}

fn do_balance(e: &Env, id: &Identifier) -> ExternalBigInt {
    let balance: u64 = contract::balance(e.clone(), id.clone()).try_into().unwrap();
    ExternalBigInt(num_bigint::BigInt::from(balance))
}

fn do_transfer(e: &Env, kp: &Keypair, to: &Identifier, amount: ExternalBigInt) {
    let from_bin = binary_from_keypair(e, kp);
    let from_id = Identifier::Ed25519(from_bin.clone());

    let nonce = do_nonce(e, &from_id);
    let msg = ExternalMessageV0 {
        nonce: nonce.clone(),
        domain: Domain::Transfer,
        parameters: ScVec(
            vec![to.clone().into(), amount.clone().into()]
                .try_into()
                .unwrap(),
        ),
    };

    let auth = KeyedAuthorization::Ed25519(KeyedEd25519Authorization {
        public_key: from_bin,
        auth: Ed25519Authorization {
            nonce: bigint_from_external(e, &nonce),
            signature: sign(e, kp, msg),
        },
    });
    contract::xfer(
        e.clone(),
        auth,
        to.clone(),
        bigint_from_external(e, &amount),
    );
}

fn do_transfer_from(
    e: &Env,
    kp: &Keypair,
    from: &Identifier,
    to: &Identifier,
    amount: ExternalBigInt,
) {
    let spender_bin = binary_from_keypair(e, kp);
    let spender_id = Identifier::Ed25519(spender_bin.clone());

    let nonce = do_nonce(e, &spender_id);
    let msg = ExternalMessageV0 {
        nonce: nonce.clone(),
        domain: Domain::TransferFrom,
        parameters: ScVec(
            vec![
                from.clone().into(),
                to.clone().into(),
                amount.clone().into(),
            ]
            .try_into()
            .unwrap(),
        ),
    };

    let auth = KeyedAuthorization::Ed25519(KeyedEd25519Authorization {
        public_key: spender_bin,
        auth: Ed25519Authorization {
            nonce: bigint_from_external(e, &nonce),
            signature: sign(e, kp, msg),
        },
    });
    contract::xfer_from(
        e.clone(),
        auth,
        from.clone(),
        to.clone(),
        bigint_from_external(e, &amount),
    );
}

fn do_burn(e: &Env, kp: &Keypair, from: &Identifier, amount: ExternalBigInt) {
    let admin = Identifier::Ed25519(binary_from_keypair(e, kp));

    let nonce = do_nonce(e, &admin);
    let msg = ExternalMessageV0 {
        nonce: nonce.clone(),
        domain: Domain::Burn,
        parameters: ScVec(
            vec![from.clone().into(), amount.clone().into()]
                .try_into()
                .unwrap(),
        ),
    };

    let auth = Authorization::Ed25519(Ed25519Authorization {
        nonce: bigint_from_external(e, &nonce),
        signature: sign(e, kp, msg),
    });
    contract::burn(
        e.clone(),
        auth,
        from.clone(),
        bigint_from_external(e, &amount),
    );
}

fn do_freeze(e: &Env, kp: &Keypair, id: &Identifier) {
    let admin = Identifier::Ed25519(binary_from_keypair(e, kp));

    let nonce = do_nonce(e, &admin);
    let msg = ExternalMessageV0 {
        nonce: nonce.clone(),
        domain: Domain::Freeze,
        parameters: ScVec(
            vec![id.clone().into(), ScVal::Static(ScStatic::Void)]
                .try_into()
                .unwrap(),
        ),
    };

    let auth = Authorization::Ed25519(Ed25519Authorization {
        nonce: bigint_from_external(e, &nonce),
        signature: sign(e, kp, msg),
    });
    contract::freeze(e.clone(), auth, id.clone());
}

fn do_mint(e: &Env, kp: &Keypair, to: &Identifier, amount: ExternalBigInt) {
    let admin = Identifier::Ed25519(binary_from_keypair(e, kp));

    let nonce = do_nonce(e, &admin);
    let msg = ExternalMessageV0 {
        nonce: nonce.clone(),
        domain: Domain::Mint,
        parameters: ScVec(
            vec![to.clone().into(), amount.clone().into()]
                .try_into()
                .unwrap(),
        ),
    };

    let auth = Authorization::Ed25519(Ed25519Authorization {
        nonce: bigint_from_external(e, &nonce),
        signature: sign(e, kp, msg),
    });
    contract::mint(
        e.clone(),
        auth,
        to.clone(),
        bigint_from_external(e, &amount),
    );
}

fn do_set_admin(e: &Env, kp: &Keypair, new_admin: &Identifier) {
    let admin = Identifier::Ed25519(binary_from_keypair(e, kp));

    let nonce = do_nonce(e, &admin);
    let msg = ExternalMessageV0 {
        nonce: nonce.clone(),
        domain: Domain::SetAdministrator,
        parameters: ScVec(
            vec![new_admin.clone().into(), ScVal::Static(ScStatic::Void)]
                .try_into()
                .unwrap(),
        ),
    };

    let auth = Authorization::Ed25519(Ed25519Authorization {
        nonce: bigint_from_external(e, &nonce),
        signature: sign(e, kp, msg),
    });
    contract::set_admin(e.clone(), auth, new_admin.clone());
}

fn do_unfreeze(e: &Env, kp: &Keypair, id: &Identifier) {
    let admin = Identifier::Ed25519(binary_from_keypair(e, kp));

    let nonce = do_nonce(e, &admin);
    let msg = ExternalMessageV0 {
        nonce: nonce.clone(),
        domain: Domain::Unfreeze,
        parameters: ScVec(
            vec![id.clone().into(), ScVal::Static(ScStatic::Void)]
                .try_into()
                .unwrap(),
        ),
    };

    let auth = Authorization::Ed25519(Ed25519Authorization {
        nonce: bigint_from_external(e, &nonce),
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

    do_mint(&e, &admin_kp1, &id1, 1000u64.into());
    assert_eq!(do_balance(&e, &id1), 1000u64.into());
    assert_eq!(do_nonce(&e, &admin_id1), 1u64.into());

    do_approve(&e, &kp2, &id3, 500u64.into());
    assert_eq!(do_allowance(&e, &id2, &id3), 500u64.into());
    assert_eq!(do_nonce(&e, &id2), 1u64.into());

    do_transfer(&e, &kp1, &id2, 600u64.into());
    assert_eq!(do_balance(&e, &id1), 400u64.into());
    assert_eq!(do_balance(&e, &id2), 600u64.into());
    assert_eq!(do_nonce(&e, &id1), 1u64.into());

    do_transfer_from(&e, &kp3, &id2, &id1, 400u64.into());
    assert_eq!(do_allowance(&e, &id2, &id3), 100u64.into());
    assert_eq!(do_balance(&e, &id1), 800u64.into());
    assert_eq!(do_balance(&e, &id2), 200u64.into());
    assert_eq!(do_nonce(&e, &id3), 1u64.into());

    do_transfer(&e, &kp1, &id3, 300u64.into());
    assert_eq!(do_balance(&e, &id1), 500u64.into());
    assert_eq!(do_balance(&e, &id3), 300u64.into());
    assert_eq!(do_nonce(&e, &id1), 2u64.into());

    do_set_admin(&e, &admin_kp1, &admin_id2);
    assert_eq!(do_nonce(&e, &admin_id1), 2u64.into());

    do_freeze(&e, &admin_kp2, &id2);
    assert_eq!(contract::is_frozen(e.clone(), id2.clone()), true);
    assert_eq!(do_nonce(&e, &admin_id2), 1u64.into());

    do_unfreeze(&e, &admin_kp2, &id3);
    assert_eq!(contract::is_frozen(e.clone(), id3.clone()), false);
    assert_eq!(do_nonce(&e, &admin_id2), 2u64.into());

    do_burn(&e, &admin_kp2, &id3, 100u64.into());
    assert_eq!(do_balance(&e, &id3), 200u64.into());
    assert_eq!(do_nonce(&e, &admin_id2), 3u64.into());
}
