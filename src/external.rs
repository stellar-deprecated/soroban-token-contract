#![cfg(test)]
#![allow(dead_code)]

use std::vec::Vec;

use ed25519_dalek::{Keypair, Signer};
use num_bigint::{BigInt, Sign};
use sha2::Digest;
use stellar_xdr::{ScBigInt, ScObject, ScVal, ScVec, WriteXdr};

trait ToScVal {
    fn to_scval(&self) -> Result<ScVal, ()>;
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

macro_rules! tuple_to_scval {
    ($($i:tt $t:ident),+) => {
        impl<$($t: ToScVal),+> ToScVal for ($($t,)+) {
            fn to_scval(&self) -> Result<ScVal, ()> {
                let vec = vec![$(self.$i.to_scval()?),+];
                Ok(ScVal::Object(Some(ScObject::Vec(ScVec(vec.try_into()?)))))
            }
        }
    }
}

tuple_to_scval!(0 T0);
tuple_to_scval!(0 T0, 1 T1);
tuple_to_scval!(0 T0, 1 T1, 2 T2);

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
