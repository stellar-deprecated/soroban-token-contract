#![cfg(feature = "external")]
#![allow(dead_code)]

use std::vec::Vec;

use ed25519_dalek::{Keypair, Signer};
use num_bigint::{BigInt, Sign};
use sha2::Digest;
use stellar_contract_sdk::{Binary, Env, VariableLengthBinary};
use stellar_xdr::{
    HostFunction, ScBigInt, ScMap, ScMapEntry, ScObject, ScStatic, ScVal, ScVec, WriteXdr,
};

impl From<&Keypair> for Identifier {
    fn from(kp: &Keypair) -> Self {
        Identifier::Ed25519(kp.public.to_bytes())
    }
}

pub trait ToScVal {
    fn to_scval(&self) -> Result<ScVal, ()>;
}

pub trait ToScVec {
    fn to_scvec(&self) -> Result<ScVec, ()>;
}

pub trait FromScVal<T>: Sized {
    fn from_scval(&self) -> Result<T, ()>;
}

impl ToScVal for ScVal {
    fn to_scval(&self) -> Result<ScVal, ()> {
        Ok(self.clone())
    }
}

impl ToScVal for u32 {
    fn to_scval(&self) -> Result<ScVal, ()> {
        Ok(ScVal::U32(*self))
    }
}

impl FromScVal<u32> for ScVal {
    fn from_scval(&self) -> Result<u32, ()> {
        match self {
            ScVal::U32(x) => Ok(*x),
            _ => Err(()),
        }
    }
}

impl ToScVal for &str {
    fn to_scval(&self) -> Result<ScVal, ()> {
        let bytes: Vec<u8> = self.as_bytes().iter().cloned().collect();
        Ok(ScVal::Symbol(bytes.try_into().map_err(|_| ())?))
    }
}

impl FromScVal<bool> for ScVal {
    fn from_scval(&self) -> Result<bool, ()> {
        match self {
            ScVal::Static(ScStatic::False) => Ok(false),
            ScVal::Static(ScStatic::True) => Ok(true),
            _ => Err(()),
        }
    }
}

impl<const N: usize> ToScVal for &[u8; N] {
    fn to_scval(&self) -> Result<ScVal, ()> {
        let bytes: Vec<u8> = self.iter().cloned().collect();
        Ok(ScVal::Object(Some(ScObject::Binary(
            bytes.try_into().map_err(|_| ())?,
        ))))
    }
}

impl ToScVal for &BigInt {
    fn to_scval(&self) -> Result<ScVal, ()> {
        let scbi = match self.to_bytes_be() {
            (Sign::NoSign, _) => ScBigInt::Zero,
            (Sign::Plus, bytes) => ScBigInt::Positive(bytes.try_into().map_err(|_| ())?),
            (Sign::Minus, bytes) => ScBigInt::Negative(bytes.try_into().map_err(|_| ())?),
        };
        Ok(ScVal::Object(Some(ScObject::BigInt(scbi))))
    }
}

impl FromScVal<BigInt> for ScVal {
    fn from_scval(&self) -> Result<BigInt, ()> {
        match self {
            ScVal::Object(Some(ScObject::BigInt(ScBigInt::Zero))) => Ok(0u32.into()),
            ScVal::Object(Some(ScObject::BigInt(ScBigInt::Positive(bytes)))) => {
                Ok(BigInt::from_bytes_be(Sign::Plus, bytes))
            }
            ScVal::Object(Some(ScObject::BigInt(ScBigInt::Negative(bytes)))) => {
                Ok(BigInt::from_bytes_be(Sign::Minus, bytes))
            }
            _ => Err(()),
        }
    }
}

macro_rules! tuple_to_scval {
    ($($i:tt $t:ident),+) => {
        impl<$($t: ToScVal),+> ToScVal for ($($t,)+) {
            fn to_scval(&self) -> Result<ScVal, ()> {
                let vec = vec![$(self.$i.to_scval()?),+];
                Ok(ScVal::Object(Some(ScObject::Vec(ScVec(vec.try_into()?)))))
            }
        }

        impl<$($t: ToScVal),+> ToScVec for ($($t,)+) {
            fn to_scvec(&self) -> Result<ScVec, ()> {
                let vec = vec![$(self.$i.to_scval()?),+];
                Ok(ScVec(vec.try_into()?))
            }
        }
    }
}

tuple_to_scval!(0 T0);
tuple_to_scval!(0 T0, 1 T1);
tuple_to_scval!(0 T0, 1 T1, 2 T2);
tuple_to_scval!(0 T0, 1 T1, 2 T2, 3 T3);
tuple_to_scval!(0 T0, 1 T1, 2 T2, 3 T3, 4 T4);
tuple_to_scval!(0 T0, 1 T1, 2 T2, 3 T3, 4 T4, 5 T5);

pub type U256 = [u8; 32];
pub type U512 = [u8; 64];

pub enum Identifier {
    Contract(U256),
    Ed25519(U256),
    Account(U256),
}

impl ToScVal for &Identifier {
    fn to_scval(&self) -> Result<ScVal, ()> {
        match self {
            Identifier::Contract(x) => ("Contract", x).to_scval(),
            Identifier::Ed25519(x) => ("Ed25519", x).to_scval(),
            Identifier::Account(x) => ("Account", x).to_scval(),
        }
    }
}

#[derive(Clone)]
pub struct Ed25519Authorization {
    pub nonce: BigInt,
    pub signature: U512,
}

impl ToScVal for &Ed25519Authorization {
    fn to_scval(&self) -> Result<ScVal, ()> {
        let mut map = Vec::new();
        map.push(ScMapEntry {
            key: "nonce".to_scval()?,
            val: (&self.nonce).to_scval()?,
        });
        map.push(ScMapEntry {
            key: "signature".to_scval()?,
            val: (&self.signature).to_scval()?,
        });
        Ok(ScVal::Object(Some(ScObject::Map(ScMap(map.try_into()?)))))
    }
}

#[derive(Clone)]
pub struct KeyedEd25519Authorization {
    pub public_key: U256,
    pub auth: Ed25519Authorization,
}

impl ToScVal for &KeyedEd25519Authorization {
    fn to_scval(&self) -> Result<ScVal, ()> {
        let mut map = Vec::new();
        map.push(ScMapEntry {
            key: "public_key".to_scval()?,
            val: (&self.public_key).to_scval()?,
        });
        map.push(ScMapEntry {
            key: "auth".to_scval()?,
            val: (&self.auth).to_scval()?,
        });
        Ok(ScVal::Object(Some(ScObject::Map(ScMap(map.try_into()?)))))
    }
}

// TODO: Add other branches
#[derive(Clone)]
pub enum Authorization {
    Ed25519(Ed25519Authorization),
}

impl ToScVal for &Authorization {
    fn to_scval(&self) -> Result<ScVal, ()> {
        match self {
            Authorization::Ed25519(x) => ("Ed25519", x).to_scval(),
        }
    }
}

// TODO: Add other branches
#[derive(Clone)]
pub enum KeyedAuthorization {
    Ed25519(KeyedEd25519Authorization),
}

impl ToScVal for &KeyedAuthorization {
    fn to_scval(&self) -> Result<ScVal, ()> {
        match self {
            KeyedAuthorization::Ed25519(x) => ("Ed25519", x).to_scval(),
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

impl ToScVal for Message {
    fn to_scval(&self) -> Result<ScVal, ()> {
        let mut map = Vec::new();
        match self {
            Message(nonce, MessageWithoutNonce::Approve(id, amount)) => {
                map.push(ScMapEntry {
                    key: "domain".to_scval()?,
                    val: 0u32.to_scval()?,
                });
                map.push(ScMapEntry {
                    key: "nonce".to_scval()?,
                    val: nonce.to_scval()?,
                });
                map.push(ScMapEntry {
                    key: "parameters".to_scval()?,
                    val: (id, amount).to_scval()?,
                });
            }
            Message(nonce, MessageWithoutNonce::Transfer(to, amount)) => {
                map.push(ScMapEntry {
                    key: "domain".to_scval()?,
                    val: 1u32.to_scval()?,
                });
                map.push(ScMapEntry {
                    key: "nonce".to_scval()?,
                    val: nonce.to_scval()?,
                });
                map.push(ScMapEntry {
                    key: "parameters".to_scval()?,
                    val: (to, amount).to_scval()?,
                });
            }
            Message(nonce, MessageWithoutNonce::TransferFrom(from, to, amount)) => {
                map.push(ScMapEntry {
                    key: "domain".to_scval()?,
                    val: 2u32.to_scval()?,
                });
                map.push(ScMapEntry {
                    key: "nonce".to_scval()?,
                    val: nonce.to_scval()?,
                });
                map.push(ScMapEntry {
                    key: "parameters".to_scval()?,
                    val: (from, to, amount).to_scval()?,
                });
            }
            Message(nonce, MessageWithoutNonce::Burn(from, amount)) => {
                map.push(ScMapEntry {
                    key: "domain".to_scval()?,
                    val: 3u32.to_scval()?,
                });
                map.push(ScMapEntry {
                    key: "nonce".to_scval()?,
                    val: nonce.to_scval()?,
                });
                map.push(ScMapEntry {
                    key: "parameters".to_scval()?,
                    val: (from, amount).to_scval()?,
                });
            }
            Message(nonce, MessageWithoutNonce::Freeze(id)) => {
                map.push(ScMapEntry {
                    key: "domain".to_scval()?,
                    val: 4u32.to_scval()?,
                });
                map.push(ScMapEntry {
                    key: "nonce".to_scval()?,
                    val: nonce.to_scval()?,
                });
                map.push(ScMapEntry {
                    key: "parameters".to_scval()?,
                    val: (id,).to_scval()?,
                });
            }
            Message(nonce, MessageWithoutNonce::Mint(to, amount)) => {
                map.push(ScMapEntry {
                    key: "domain".to_scval()?,
                    val: 5u32.to_scval()?,
                });
                map.push(ScMapEntry {
                    key: "nonce".to_scval()?,
                    val: nonce.to_scval()?,
                });
                map.push(ScMapEntry {
                    key: "parameters".to_scval()?,
                    val: (to, amount).to_scval()?,
                });
            }
            Message(nonce, MessageWithoutNonce::SetAdministrator(id)) => {
                map.push(ScMapEntry {
                    key: "domain".to_scval()?,
                    val: 6u32.to_scval()?,
                });
                map.push(ScMapEntry {
                    key: "nonce".to_scval()?,
                    val: nonce.to_scval()?,
                });
                map.push(ScMapEntry {
                    key: "parameters".to_scval()?,
                    val: (id,).to_scval()?,
                });
            }
            Message(nonce, MessageWithoutNonce::Unfreeze(id)) => {
                map.push(ScMapEntry {
                    key: "domain".to_scval()?,
                    val: 7u32.to_scval()?,
                });
                map.push(ScMapEntry {
                    key: "nonce".to_scval()?,
                    val: nonce.to_scval()?,
                });
                map.push(ScMapEntry {
                    key: "parameters".to_scval()?,
                    val: (id,).to_scval()?,
                });
            }
        };
        let scmap = ScVal::Object(Some(ScObject::Map(ScMap(map.try_into().map_err(|_| ())?))));
        ("V0", scmap).to_scval()
    }
}

impl Message {
    pub fn sign(&self, kp: &Keypair) -> Result<U512, ()> {
        let mut buf = Vec::<u8>::new();
        self.to_scval()?.write_xdr(&mut buf).map_err(|_| ())?;
        Ok(kp.sign(sha2::Sha256::digest(&buf).as_slice()).to_bytes())
    }
}

macro_rules! contract_fn {
    ($name:ident, $f:ident, $n:tt, $($i:tt),+) => {
        pub fn $name(e: Env, args: &[RawVal]) -> RawVal {
            if args.len() != $n {
                panic!()
            } else {
                crate::contract::$f(e, $(args[$i]),+)
            }
        }
    }
}

mod contract_fns {
    use stellar_contract_sdk::{Env, RawVal};

    contract_fn!(initialize, __initialize, 1, 0);
    contract_fn!(nonce, __nonce, 1, 0);
    contract_fn!(allowance, __allowance, 2, 0, 1);
    contract_fn!(approve, __approve, 3, 0, 1, 2);
    contract_fn!(balance, __balance, 1, 0);
    contract_fn!(is_frozen, __is_frozen, 1, 0);
    contract_fn!(xfer, __xfer, 3, 0, 1, 2);
    contract_fn!(xfer_from, __xfer_from, 4, 0, 1, 2, 3);
    contract_fn!(burn, __burn, 3, 0, 1, 2);
    contract_fn!(freeze, __freeze, 2, 0, 1);
    contract_fn!(mint, __mint, 3, 0, 1, 2);
    contract_fn!(set_admin, __set_admin, 2, 0, 1);
    contract_fn!(unfreeze, __unfreeze, 2, 0, 1);
}

pub fn register_test_contract(e: &Env, contract_id: &U256) {
    let mut bin = Binary::new(e);
    for b in contract_id {
        bin.push(*b);
    }

    let mut tc = stellar_contract_sdk::TestContract::new();
    tc.add_function("initialize", &contract_fns::initialize);
    tc.add_function("nonce", &contract_fns::nonce);
    tc.add_function("allowance", &contract_fns::allowance);
    tc.add_function("approve", &contract_fns::approve);
    tc.add_function("balance", &contract_fns::balance);
    tc.add_function("is_frozen", &contract_fns::is_frozen);
    tc.add_function("xfer", &contract_fns::xfer);
    tc.add_function("xfer_from", &contract_fns::xfer_from);
    tc.add_function("burn", &contract_fns::burn);
    tc.add_function("freeze", &contract_fns::freeze);
    tc.add_function("mint", &contract_fns::mint);
    tc.add_function("set_admin", &contract_fns::set_admin);
    tc.add_function("unfreeze", &contract_fns::unfreeze);
    e.register_contract(bin.into(), tc);
}

pub fn initialize(e: &mut Env, contract_id: &U256, admin: &Identifier) {
    e.invoke_contract(
        HostFunction::Call,
        (contract_id, "initialize", admin).to_scvec().unwrap(),
    );
}

pub fn nonce(e: &mut Env, contract_id: &U256, id: &Identifier) -> BigInt {
    e.invoke_contract(
        HostFunction::Call,
        (contract_id, "nonce", id).to_scvec().unwrap(),
    )
    .from_scval()
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
            .to_scvec()
            .unwrap(),
    )
    .from_scval()
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
            .to_scvec()
            .unwrap(),
    );
}

pub fn balance(e: &mut Env, contract_id: &U256, id: &Identifier) -> BigInt {
    e.invoke_contract(
        HostFunction::Call,
        (contract_id, "balance", id).to_scvec().unwrap(),
    )
    .from_scval()
    .unwrap()
}

pub fn is_frozen(e: &mut Env, contract_id: &U256, id: &Identifier) -> bool {
    e.invoke_contract(
        HostFunction::Call,
        (contract_id, "is_frozen", id).to_scvec().unwrap(),
    )
    .from_scval()
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
        (contract_id, "xfer", from, to, amount).to_scvec().unwrap(),
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
            .to_scvec()
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
            .to_scvec()
            .unwrap(),
    );
}

pub fn freeze(e: &mut Env, contract_id: &U256, admin: &Authorization, id: &Identifier) {
    e.invoke_contract(
        HostFunction::Call,
        (contract_id, "freeze", admin, id).to_scvec().unwrap(),
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
        (contract_id, "mint", admin, to, amount).to_scvec().unwrap(),
    );
}

pub fn set_admin(e: &mut Env, contract_id: &U256, admin: &Authorization, new_admin: &Identifier) {
    e.invoke_contract(
        HostFunction::Call,
        (contract_id, "set_admin", admin, new_admin)
            .to_scvec()
            .unwrap(),
    );
}

pub fn unfreeze(e: &mut Env, contract_id: &U256, admin: &Authorization, id: &Identifier) {
    e.invoke_contract(
        HostFunction::Call,
        (contract_id, "unfreeze", admin, id).to_scvec().unwrap(),
    );
}
