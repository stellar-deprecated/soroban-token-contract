#![cfg(feature = "testutils")]

use crate::contract::TokenClient;
use ed25519_dalek::Keypair;
use soroban_sdk::testutils::ed25519::Sign;
use soroban_sdk::{symbol, BigInt, Bytes, BytesN, Env, IntoVal, RawVal, Vec};
use soroban_sdk_auth::public_types::{
    Ed25519Signature, Identifier, Signature, SignaturePayload, SignaturePayloadV0,
};

pub fn register_test_contract(e: &Env, contract_id: &[u8; 32]) {
    let contract_id = BytesN::from_array(e, contract_id);
    e.register_contract(&contract_id, crate::contract::Token {});
}

pub fn to_ed25519(e: &Env, kp: &Keypair) -> Identifier {
    Identifier::Ed25519(kp.public.to_bytes().into_val(e))
}

pub struct Token {
    env: Env,
    contract_id: BytesN<32>,
}

impl Token {
    pub fn new(env: &Env, contract_id: &[u8; 32]) -> Self {
        Self {
            env: env.clone(),
            contract_id: BytesN::from_array(env, contract_id),
        }
    }

    pub fn initialize(&self, admin: &Identifier, decimals: u32, name: &str, symbol: &str) {
        let name: Bytes = name.into_val(&self.env);
        let symbol: Bytes = symbol.into_val(&self.env);
        TokenClient::new(&self.env, &self.contract_id)
            .initialize(&admin, &decimals, &name, &symbol);
    }

    pub fn nonce(&self, id: &Identifier) -> BigInt {
        TokenClient::new(&self.env, &self.contract_id).nonce(&id)
    }

    pub fn allowance(&self, from: &Identifier, spender: &Identifier) -> BigInt {
        TokenClient::new(&self.env, &self.contract_id).allowance(&from, &spender)
    }

    pub fn approve(&self, from: &Keypair, spender: &Identifier, amount: &BigInt) {
        let from_id = to_ed25519(&self.env, from);
        let nonce = self.nonce(&from_id);

        let mut args: Vec<RawVal> = Vec::new(&self.env);
        args.push_back(from_id.clone().into_val(&self.env));
        args.push_back(nonce.clone().into_val(&self.env));
        args.push_back(spender.clone().into_val(&self.env));
        args.push_back(amount.clone().into_val(&self.env));

        let msg = SignaturePayload::V0(SignaturePayloadV0 {
            function: symbol!("approve"),
            contract: self.contract_id.clone(),
            network: self.env.ledger().network_passphrase(),
            args,
        });

        let auth = Signature::Ed25519(Ed25519Signature {
            public_key: from.public.to_bytes().into_val(&self.env),
            signature: from.sign(msg).unwrap().into_val(&self.env),
        });
        TokenClient::new(&self.env, &self.contract_id).approve(&auth, &nonce, &spender, &amount)
    }

    pub fn balance(&self, id: &Identifier) -> BigInt {
        TokenClient::new(&self.env, &self.contract_id).balance(&id)
    }

    pub fn is_frozen(&self, id: &Identifier) -> bool {
        TokenClient::new(&self.env, &self.contract_id).is_frozen(&id)
    }

    pub fn xfer(&self, from: &Keypair, to: &Identifier, amount: &BigInt) {
        let from_id = to_ed25519(&self.env, from);
        let nonce = self.nonce(&from_id);

        let mut args: Vec<RawVal> = Vec::new(&self.env);
        args.push_back(from_id.clone().into_val(&self.env));
        args.push_back(nonce.clone().into_val(&self.env));
        args.push_back(to.clone().into_val(&self.env));
        args.push_back(amount.clone().into_val(&self.env));
        let msg = SignaturePayload::V0(SignaturePayloadV0 {
            function: symbol!("xfer"),
            contract: self.contract_id.clone(),
            network: self.env.ledger().network_passphrase(),
            args,
        });

        let auth = Signature::Ed25519(Ed25519Signature {
            public_key: BytesN::from_array(&self.env, &from.public.to_bytes()),
            signature: from.sign(msg).unwrap().into_val(&self.env),
        });

        TokenClient::new(&self.env, &self.contract_id).xfer(&auth, &nonce, &to, &amount)
    }

    pub fn xfer_from(
        &self,
        spender: &Keypair,
        from: &Identifier,
        to: &Identifier,
        amount: &BigInt,
    ) {
        let spender_id = to_ed25519(&self.env, spender);
        let nonce = self.nonce(&spender_id);

        let mut args: Vec<RawVal> = Vec::new(&self.env);
        args.push_back(spender_id.clone().into_val(&self.env));
        args.push_back(nonce.clone().into_val(&self.env));
        args.push_back(from.clone().into_val(&self.env));
        args.push_back(to.clone().into_val(&self.env));
        args.push_back(amount.clone().into_val(&self.env));

        let msg = SignaturePayload::V0(SignaturePayloadV0 {
            function: symbol!("xfer_from"),
            contract: self.contract_id.clone(),
            network: self.env.ledger().network_passphrase(),
            args,
        });

        let auth = Signature::Ed25519(Ed25519Signature {
            public_key: spender.public.to_bytes().into_val(&self.env),
            signature: spender.sign(msg).unwrap().into_val(&self.env),
        });

        TokenClient::new(&self.env, &self.contract_id).xfer_from(&auth, &nonce, &from, &to, &amount)
    }

    pub fn burn(&self, admin: &Keypair, from: &Identifier, amount: &BigInt) {
        let admin_id = to_ed25519(&self.env, admin);
        let nonce = self.nonce(&admin_id);

        let mut args: Vec<RawVal> = Vec::new(&self.env);
        args.push_back(admin_id.clone().into_val(&self.env));
        args.push_back(nonce.clone().into_val(&self.env));
        args.push_back(from.clone().into_val(&self.env));
        args.push_back(amount.clone().into_val(&self.env));
        let msg = SignaturePayload::V0(SignaturePayloadV0 {
            function: symbol!("burn"),
            contract: self.contract_id.clone(),
            network: self.env.ledger().network_passphrase(),
            args,
        });
        let auth = Signature::Ed25519(Ed25519Signature {
            public_key: admin.public.to_bytes().into_val(&self.env),
            signature: admin.sign(msg).unwrap().into_val(&self.env),
        });
        TokenClient::new(&self.env, &self.contract_id).burn(&auth, &nonce, &from, &amount)
    }

    pub fn freeze(&self, admin: &Keypair, id: &Identifier) {
        let admin_id = to_ed25519(&self.env, admin);
        let nonce = self.nonce(&admin_id);

        let mut args: Vec<RawVal> = Vec::new(&self.env);
        args.push_back(admin_id.clone().into_val(&self.env));
        args.push_back(nonce.clone().into_val(&self.env));
        args.push_back(id.clone().into_val(&self.env));
        let msg = SignaturePayload::V0(SignaturePayloadV0 {
            function: symbol!("freeze"),
            contract: self.contract_id.clone(),
            network: self.env.ledger().network_passphrase(),
            args,
        });
        let auth = Signature::Ed25519(Ed25519Signature {
            public_key: admin.public.to_bytes().into_val(&self.env),
            signature: admin.sign(msg).unwrap().into_val(&self.env),
        });
        TokenClient::new(&self.env, &self.contract_id).freeze(&auth, &nonce, &id)
    }

    pub fn mint(&self, admin: &Keypair, to: &Identifier, amount: &BigInt) {
        let admin_id = to_ed25519(&self.env, admin);
        let nonce = self.nonce(&admin_id);

        let mut args: Vec<RawVal> = Vec::new(&self.env);
        args.push_back(admin_id.clone().into_val(&self.env));
        args.push_back(nonce.clone().into_val(&self.env));
        args.push_back(to.clone().into_val(&self.env));
        args.push_back(amount.clone().into_val(&self.env));
        let msg = SignaturePayload::V0(SignaturePayloadV0 {
            function: symbol!("mint"),
            contract: self.contract_id.clone(),
            network: self.env.ledger().network_passphrase(),
            args,
        });
        let auth = Signature::Ed25519(Ed25519Signature {
            public_key: admin.public.to_bytes().into_val(&self.env),
            signature: admin.sign(msg).unwrap().into_val(&self.env),
        });
        TokenClient::new(&self.env, &self.contract_id).mint(&auth, &nonce, &to, &amount)
    }

    pub fn set_admin(&self, admin: &Keypair, new_admin: &Identifier) {
        let admin_id = to_ed25519(&self.env, admin);
        let nonce = self.nonce(&admin_id);

        let mut args: Vec<RawVal> = Vec::new(&self.env);
        args.push_back(admin_id.clone().into_val(&self.env));
        args.push_back(nonce.clone().into_val(&self.env));
        args.push_back(new_admin.clone().into_val(&self.env));
        let msg = SignaturePayload::V0(SignaturePayloadV0 {
            function: symbol!("set_admin"),
            contract: self.contract_id.clone(),
            network: self.env.ledger().network_passphrase(),
            args,
        });
        let auth = Signature::Ed25519(Ed25519Signature {
            public_key: admin.public.to_bytes().into_val(&self.env),
            signature: admin.sign(msg).unwrap().into_val(&self.env),
        });
        TokenClient::new(&self.env, &self.contract_id).set_admin(&auth, &nonce, &new_admin)
    }

    pub fn unfreeze(&self, admin: &Keypair, id: &Identifier) {
        let admin_id = to_ed25519(&self.env, admin);
        let nonce = self.nonce(&admin_id);

        let mut args: Vec<RawVal> = Vec::new(&self.env);
        args.push_back(admin_id.clone().into_val(&self.env));
        args.push_back(nonce.clone().into_val(&self.env));
        args.push_back(id.clone().into_val(&self.env));
        let msg = SignaturePayload::V0(SignaturePayloadV0 {
            function: symbol!("unfreeze"),
            contract: self.contract_id.clone(),
            network: self.env.ledger().network_passphrase(),
            args,
        });
        let auth = Signature::Ed25519(Ed25519Signature {
            public_key: admin.public.to_bytes().into_val(&self.env),
            signature: admin.sign(msg).unwrap().into_val(&self.env),
        });
        TokenClient::new(&self.env, &self.contract_id).unfreeze(&auth, &nonce, &id)
    }

    pub fn decimals(&self) -> u32 {
        TokenClient::new(&self.env, &self.contract_id).decimals()
    }

    pub fn name(&self) -> Bytes {
        TokenClient::new(&self.env, &self.contract_id).name()
    }

    pub fn symbol(&self) -> Bytes {
        TokenClient::new(&self.env, &self.contract_id).symbol()
    }
}
