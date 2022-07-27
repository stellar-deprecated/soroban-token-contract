#![cfg(feature = "testutils")]

use crate::public_types::{
    Authorization, Identifier, KeyedAuthorization, KeyedEd25519Authorization, Message, MessageV0,
};
use ed25519_dalek::Keypair;
use stellar_contract_sdk::testutils::ed25519::Sign;
use stellar_contract_sdk::{BigInt, Binary, Env, EnvVal, FixedBinary, IntoEnvVal, TryIntoVal, Vec};

pub fn register_test_contract(e: &Env, contract_id: &[u8; 32]) {
    let contract_id = Binary::from_array(e, *contract_id);
    e.register_contract(contract_id, crate::contract::Token {});
}

pub use crate::contract::__allowance::call_external as allowance;
pub use crate::contract::__approve::call_external as approve;
pub use crate::contract::__balance::call_external as balance;
pub use crate::contract::__burn::call_external as burn;
pub use crate::contract::__decimals::call_external as decimals;
pub use crate::contract::__freeze::call_external as freeze;
pub use crate::contract::__initialize::call_external as initialize;
pub use crate::contract::__is_frozen::call_external as is_frozen;
pub use crate::contract::__mint::call_external as mint;
pub use crate::contract::__name::call_external as name;
pub use crate::contract::__nonce::call_external as nonce;
pub use crate::contract::__set_admin::call_external as set_admin;
pub use crate::contract::__symbol::call_external as symbol;
pub use crate::contract::__unfreeze::call_external as unfreeze;
pub use crate::contract::__xfer::call_external as xfer;
pub use crate::contract::__xfer_from::call_external as xfer_from;

pub fn to_ed25519(e: &Env, kp: &Keypair) -> Identifier {
    Identifier::Ed25519(kp.public.to_bytes().try_into_val(e).unwrap())
}

pub struct Token {
    env: Env,
    contract_id: Binary,
}

impl Token {
    pub fn new(env: &Env, contract_id: &[u8; 32]) -> Self {
        Self {
            env: env.clone(),
            contract_id: Binary::from_slice(env, contract_id),
        }
    }

    pub fn initialize(&mut self, admin: &Identifier, decimals: u32, name: &str, symbol: &str) {
        let name: Binary = Binary::from_slice(&self.env, name.as_bytes());
        let symbol: Binary = Binary::from_slice(&self.env, symbol.as_bytes());
        initialize(
            &mut self.env,
            &self.contract_id,
            admin,
            &decimals,
            &name,
            &symbol,
        )
    }

    pub fn nonce(&mut self, id: &Identifier) -> BigInt {
        nonce(&mut self.env, &self.contract_id, id)
    }

    pub fn allowance(&mut self, from: &Identifier, spender: &Identifier) -> BigInt {
        allowance(&mut self.env, &self.contract_id, from, spender)
    }

    pub fn approve(&mut self, from: &Keypair, spender: &Identifier, amount: &BigInt) {
        let mut args: Vec<EnvVal> = Vec::new(&self.env);
        args.push(spender.clone().into_env_val(&self.env));
        args.push(amount.clone().into_env_val(&self.env));
        let msg = Message::V0(MessageV0 {
            nonce: self.nonce(&to_ed25519(&self.env, from)),
            domain: crate::cryptography::Domain::Approve as u32,
            parameters: args,
        });
        let auth = KeyedAuthorization::Ed25519(KeyedEd25519Authorization {
            public_key: FixedBinary::from_array(&self.env, from.public.to_bytes()),
            signature: from.sign(msg).unwrap().try_into_val(&self.env).unwrap(),
        });
        approve(&mut self.env, &self.contract_id, &auth, spender, amount)
    }

    pub fn balance(&mut self, id: &Identifier) -> BigInt {
        balance(&mut self.env, &self.contract_id, id)
    }

    pub fn is_frozen(&mut self, id: &Identifier) -> bool {
        is_frozen(&mut self.env, &self.contract_id, id)
    }

    pub fn xfer(&mut self, from: &Keypair, to: &Identifier, amount: &BigInt) {
        let mut args: Vec<EnvVal> = Vec::new(&self.env);
        args.push(to.clone().into_env_val(&self.env));
        args.push(amount.clone().into_env_val(&self.env));
        let msg = Message::V0(MessageV0 {
            nonce: self.nonce(&to_ed25519(&self.env, from)),
            domain: crate::cryptography::Domain::Transfer as u32,
            parameters: args,
        });
        let auth = KeyedAuthorization::Ed25519(KeyedEd25519Authorization {
            public_key: FixedBinary::from_array(&self.env, from.public.to_bytes()),
            signature: from.sign(msg).unwrap().try_into_val(&self.env).unwrap(),
        });
        xfer(&mut self.env, &self.contract_id, &auth, to, amount)
    }

    pub fn xfer_from(
        &mut self,
        spender: &Keypair,
        from: &Identifier,
        to: &Identifier,
        amount: &BigInt,
    ) {
        let mut args: Vec<EnvVal> = Vec::new(&self.env);
        args.push(from.clone().into_env_val(&self.env));
        args.push(to.clone().into_env_val(&self.env));
        args.push(amount.clone().into_env_val(&self.env));
        let msg = Message::V0(MessageV0 {
            nonce: self.nonce(&to_ed25519(&self.env, spender)),
            domain: crate::cryptography::Domain::TransferFrom as u32,
            parameters: args,
        });
        let auth = KeyedAuthorization::Ed25519(KeyedEd25519Authorization {
            public_key: FixedBinary::from_array(&self.env, spender.public.to_bytes()),
            signature: spender.sign(msg).unwrap().try_into_val(&self.env).unwrap(),
        });
        xfer_from(&mut self.env, &self.contract_id, &auth, from, to, amount)
    }

    pub fn burn(&mut self, admin: &Keypair, from: &Identifier, amount: &BigInt) {
        let mut args: Vec<EnvVal> = Vec::new(&self.env);
        args.push(from.clone().into_env_val(&self.env));
        args.push(amount.clone().into_env_val(&self.env));
        let msg = Message::V0(MessageV0 {
            nonce: self.nonce(&to_ed25519(&self.env, admin)),
            domain: crate::cryptography::Domain::Burn as u32,
            parameters: args,
        });
        let auth =
            Authorization::Ed25519(admin.sign(msg).unwrap().try_into_val(&self.env).unwrap());
        burn(&mut self.env, &self.contract_id, &auth, from, amount)
    }

    pub fn freeze(&mut self, admin: &Keypair, id: &Identifier) {
        let mut args: Vec<EnvVal> = Vec::new(&self.env);
        args.push(id.clone().into_env_val(&self.env));
        let msg = Message::V0(MessageV0 {
            nonce: self.nonce(&to_ed25519(&self.env, admin)),
            domain: crate::cryptography::Domain::Freeze as u32,
            parameters: args,
        });
        let auth =
            Authorization::Ed25519(admin.sign(msg).unwrap().try_into_val(&self.env).unwrap());
        freeze(&mut self.env, &self.contract_id, &auth, id)
    }

    pub fn mint(&mut self, admin: &Keypair, to: &Identifier, amount: &BigInt) {
        let mut args: Vec<EnvVal> = Vec::new(&self.env);
        args.push(to.clone().into_env_val(&self.env));
        args.push(amount.clone().into_env_val(&self.env));
        let msg = Message::V0(MessageV0 {
            nonce: self.nonce(&to_ed25519(&self.env, admin)),
            domain: crate::cryptography::Domain::Mint as u32,
            parameters: args,
        });
        let auth =
            Authorization::Ed25519(admin.sign(msg).unwrap().try_into_val(&self.env).unwrap());
        mint(&mut self.env, &self.contract_id, &auth, to, amount)
    }

    pub fn set_admin(&mut self, admin: &Keypair, new_admin: &Identifier) {
        let mut args: Vec<EnvVal> = Vec::new(&self.env);
        args.push(new_admin.clone().into_env_val(&self.env));
        let msg = Message::V0(MessageV0 {
            nonce: self.nonce(&to_ed25519(&self.env, admin)),
            domain: crate::cryptography::Domain::SetAdministrator as u32,
            parameters: args,
        });
        let auth =
            Authorization::Ed25519(admin.sign(msg).unwrap().try_into_val(&self.env).unwrap());
        set_admin(&mut self.env, &self.contract_id, &auth, new_admin)
    }

    pub fn unfreeze(&mut self, admin: &Keypair, id: &Identifier) {
        let mut args: Vec<EnvVal> = Vec::new(&self.env);
        args.push(id.clone().into_env_val(&self.env));
        let msg = Message::V0(MessageV0 {
            nonce: self.nonce(&to_ed25519(&self.env, admin)),
            domain: crate::cryptography::Domain::Unfreeze as u32,
            parameters: args,
        });
        let auth =
            Authorization::Ed25519(admin.sign(msg).unwrap().try_into_val(&self.env).unwrap());
        unfreeze(&mut self.env, &self.contract_id, &auth, id)
    }

    pub fn decimals(&mut self) -> u32 {
        decimals(&mut self.env, &self.contract_id)
    }

    pub fn name(&mut self) -> Binary {
        name(&mut self.env, &self.contract_id)
    }

    pub fn symbol(&mut self) -> Binary {
        symbol(&mut self.env, &self.contract_id)
    }
}
