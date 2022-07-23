#![cfg(feature = "testutils")]

use std::vec::Vec;

use ed25519_dalek::{Keypair, Signer};
use num_bigint::BigInt;
use stellar_contract_sdk::xdr::{HostFunction, ScMap, ScMapEntry, ScObject, ScVal, WriteXdr};
use stellar_contract_sdk::{Binary, Env, VariableLengthBinary};

use crate::public_types::Identifier;

pub type U256 = [u8; 32];
pub type U512 = [u8; 64];

#[derive(Clone)]
pub struct KeyedEd25519Authorization {
    pub public_key: U256,
    pub signature: U512,
}

impl TryInto<ScVal> for &KeyedEd25519Authorization {
    type Error = ();
    fn try_into(self) -> Result<ScVal, Self::Error> {
        let mut map = Vec::new();
        map.push(ScMapEntry {
            key: "public_key".try_into()?,
            val: (&self.public_key).try_into()?,
        });
        map.push(ScMapEntry {
            key: "signature".try_into()?,
            val: (&self.signature).try_into()?,
        });
        Ok(ScVal::Object(Some(ScObject::Map(ScMap(map.try_into()?)))))
    }
}

// TODO: Add other branches
#[derive(Clone)]
pub enum Authorization {
    Ed25519(U512),
}

impl TryInto<ScVal> for &Authorization {
    type Error = ();
    fn try_into(self) -> Result<ScVal, Self::Error> {
        match self {
            Authorization::Ed25519(x) => ("Ed25519", x).try_into(),
        }
    }
}

// TODO: Add other branches
#[derive(Clone)]
pub enum KeyedAuthorization {
    Ed25519(KeyedEd25519Authorization),
}

impl TryInto<ScVal> for &KeyedAuthorization {
    type Error = ();
    fn try_into(self) -> Result<ScVal, Self::Error> {
        match self {
            KeyedAuthorization::Ed25519(x) => ("Ed25519", x).try_into(),
        }
    }
}

pub enum MessageWithoutNonce {
    Approve(Identifier, BigInt),
    Transfer(Identifier, BigInt),
    TransferFrom(Identifier, Identifier, BigInt),
    Burn(Identifier, BigInt),
    Freeze(Identifier),
    Mint(Identifier, BigInt),
    SetAdministrator(Identifier),
    Unfreeze(Identifier),
}

pub struct Message(pub BigInt, pub MessageWithoutNonce);

impl TryInto<ScVal> for &Message {
    type Error = ();
    fn try_into(self) -> Result<ScVal, Self::Error> {
        let mut map = Vec::new();
        match self {
            Message(nonce, MessageWithoutNonce::Approve(id, amount)) => {
                map.push(ScMapEntry {
                    key: "domain".try_into()?,
                    val: 0u32.into(),
                });
                map.push(ScMapEntry {
                    key: "nonce".try_into()?,
                    val: nonce.try_into()?,
                });
                map.push(ScMapEntry {
                    key: "parameters".try_into()?,
                    val: (id, amount).try_into()?,
                });
            }
            Message(nonce, MessageWithoutNonce::Transfer(to, amount)) => {
                map.push(ScMapEntry {
                    key: "domain".try_into()?,
                    val: 1u32.into(),
                });
                map.push(ScMapEntry {
                    key: "nonce".try_into()?,
                    val: nonce.try_into()?,
                });
                map.push(ScMapEntry {
                    key: "parameters".try_into()?,
                    val: (to, amount).try_into()?,
                });
            }
            Message(nonce, MessageWithoutNonce::TransferFrom(from, to, amount)) => {
                map.push(ScMapEntry {
                    key: "domain".try_into()?,
                    val: 2u32.into(),
                });
                map.push(ScMapEntry {
                    key: "nonce".try_into()?,
                    val: nonce.try_into()?,
                });
                map.push(ScMapEntry {
                    key: "parameters".try_into()?,
                    val: (from, to, amount).try_into()?,
                });
            }
            Message(nonce, MessageWithoutNonce::Burn(from, amount)) => {
                map.push(ScMapEntry {
                    key: "domain".try_into()?,
                    val: 3u32.into(),
                });
                map.push(ScMapEntry {
                    key: "nonce".try_into()?,
                    val: nonce.try_into()?,
                });
                map.push(ScMapEntry {
                    key: "parameters".try_into()?,
                    val: (from, amount).try_into()?,
                });
            }
            Message(nonce, MessageWithoutNonce::Freeze(id)) => {
                map.push(ScMapEntry {
                    key: "domain".try_into()?,
                    val: 4u32.into(),
                });
                map.push(ScMapEntry {
                    key: "nonce".try_into()?,
                    val: nonce.try_into()?,
                });
                map.push(ScMapEntry {
                    key: "parameters".try_into()?,
                    val: (id,).try_into()?,
                });
            }
            Message(nonce, MessageWithoutNonce::Mint(to, amount)) => {
                map.push(ScMapEntry {
                    key: "domain".try_into()?,
                    val: 5u32.into(),
                });
                map.push(ScMapEntry {
                    key: "nonce".try_into()?,
                    val: nonce.try_into()?,
                });
                map.push(ScMapEntry {
                    key: "parameters".try_into()?,
                    val: (to, amount).try_into()?,
                });
            }
            Message(nonce, MessageWithoutNonce::SetAdministrator(id)) => {
                map.push(ScMapEntry {
                    key: "domain".try_into()?,
                    val: 6u32.into(),
                });
                map.push(ScMapEntry {
                    key: "nonce".try_into()?,
                    val: nonce.try_into()?,
                });
                map.push(ScMapEntry {
                    key: "parameters".try_into()?,
                    val: (id,).try_into()?,
                });
            }
            Message(nonce, MessageWithoutNonce::Unfreeze(id)) => {
                map.push(ScMapEntry {
                    key: "domain".try_into()?,
                    val: 7u32.into(),
                });
                map.push(ScMapEntry {
                    key: "nonce".try_into()?,
                    val: nonce.try_into()?,
                });
                map.push(ScMapEntry {
                    key: "parameters".try_into()?,
                    val: (id,).try_into()?,
                });
            }
        };
        let scmap = ScVal::Object(Some(ScObject::Map(ScMap(map.try_into().map_err(|_| ())?))));
        ("V0", scmap).try_into()
    }
}

impl Message {
    pub fn sign(&self, kp: &Keypair) -> Result<U512, ()> {
        let mut buf = Vec::<u8>::new();
        let val: ScVal = self.try_into()?;
        val.write_xdr(&mut buf).map_err(|_| ())?;
        Ok(kp.sign(&buf).to_bytes())
    }
}

pub fn register_test_contract(e: &Env, contract_id: &U256) {
    let mut bin = Binary::new(e);
    for b in contract_id {
        bin.push(*b);
    }

    e.register_contract(bin.into(), crate::contract::Token {});
}

pub fn initialize(e: &mut Env, contract_id: &U256, admin: &Identifier) {
    e.invoke_contract(
        HostFunction::Call,
        (contract_id, "initialize", admin).try_into().unwrap(),
    );
}

pub fn nonce(e: &mut Env, contract_id: &U256, id: &Identifier) -> BigInt {
    e.invoke_contract(
        HostFunction::Call,
        (contract_id, "nonce", id).try_into().unwrap(),
    )
    .try_into()
    .unwrap()
}

pub fn allowance(
    e: &mut Env,
    contract_id: &U256,
    from: &Identifier,
    spender: &Identifier,
) -> BigInt {
    e.invoke_contract(
        HostFunction::Call,
        (contract_id, "allowance", from, spender)
            .try_into()
            .unwrap(),
    )
    .try_into()
    .unwrap()
}

pub fn approve(
    e: &mut Env,
    contract_id: &U256,
    from: &KeyedAuthorization,
    spender: &Identifier,
    amount: &BigInt,
) {
    e.invoke_contract(
        HostFunction::Call,
        (contract_id, "approve", from, spender, amount)
            .try_into()
            .unwrap(),
    );
}

pub fn balance(e: &mut Env, contract_id: &U256, id: &Identifier) -> BigInt {
    e.invoke_contract(
        HostFunction::Call,
        (contract_id, "balance", id).try_into().unwrap(),
    )
    .try_into()
    .unwrap()
}

pub fn is_frozen(e: &mut Env, contract_id: &U256, id: &Identifier) -> bool {
    e.invoke_contract(
        HostFunction::Call,
        (contract_id, "is_frozen", id).try_into().unwrap(),
    )
    .try_into()
    .unwrap()
}

pub fn xfer(
    e: &mut Env,
    contract_id: &U256,
    from: &KeyedAuthorization,
    to: &Identifier,
    amount: &BigInt,
) {
    e.invoke_contract(
        HostFunction::Call,
        (contract_id, "xfer", from, to, amount).try_into().unwrap(),
    );
}

pub fn xfer_from(
    e: &mut Env,
    contract_id: &U256,
    spender: &KeyedAuthorization,
    from: &Identifier,
    to: &Identifier,
    amount: &BigInt,
) {
    e.invoke_contract(
        HostFunction::Call,
        (contract_id, "xfer_from", spender, from, to, amount)
            .try_into()
            .unwrap(),
    );
}

pub fn burn(
    e: &mut Env,
    contract_id: &U256,
    admin: &Authorization,
    from: &Identifier,
    amount: &BigInt,
) {
    e.invoke_contract(
        HostFunction::Call,
        (contract_id, "burn", admin, from, amount)
            .try_into()
            .unwrap(),
    );
}

pub fn freeze(e: &mut Env, contract_id: &U256, admin: &Authorization, id: &Identifier) {
    e.invoke_contract(
        HostFunction::Call,
        (contract_id, "freeze", admin, id).try_into().unwrap(),
    );
}

pub fn mint(
    e: &mut Env,
    contract_id: &U256,
    admin: &Authorization,
    to: &Identifier,
    amount: &BigInt,
) {
    e.invoke_contract(
        HostFunction::Call,
        (contract_id, "mint", admin, to, amount).try_into().unwrap(),
    );
}

pub fn set_admin(e: &mut Env, contract_id: &U256, admin: &Authorization, new_admin: &Identifier) {
    e.invoke_contract(
        HostFunction::Call,
        (contract_id, "set_admin", admin, new_admin)
            .try_into()
            .unwrap(),
    );
}

pub fn unfreeze(e: &mut Env, contract_id: &U256, admin: &Authorization, id: &Identifier) {
    e.invoke_contract(
        HostFunction::Call,
        (contract_id, "unfreeze", admin, id).try_into().unwrap(),
    );
}
