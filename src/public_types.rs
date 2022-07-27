use stellar_contract_sdk::{contracttype, BigInt, Env, EnvVal, FixedBinary, Vec};

pub type U256 = FixedBinary<32>;
pub type U512 = FixedBinary<64>;

#[derive(Clone)]
#[contracttype]
pub struct KeyedEd25519Signature {
    pub public_key: U256,
    pub signature: U512,
}

#[derive(Clone)]
#[contracttype]
pub struct KeyedEd25519Authorization {
    pub public_key: U256,
    pub signature: U512,
}

#[derive(Clone)]
#[contracttype]
pub struct AccountAuthorization {
    pub signatures: Vec<KeyedEd25519Signature>,
}

#[derive(Clone)]
#[contracttype]
pub struct KeyedAccountAuthorization {
    pub public_key: U256,
    pub auth: AccountAuthorization,
}

#[derive(Clone)]
#[contracttype]
pub enum Authorization {
    Contract,
    Ed25519(U512),
    Account(AccountAuthorization),
}

#[derive(Clone)]
#[contracttype]
pub enum KeyedAuthorization {
    Contract,
    Ed25519(KeyedEd25519Authorization),
    Account(KeyedAccountAuthorization),
}

impl KeyedAuthorization {
    pub fn get_identifier(&self, env: &Env) -> Identifier {
        match self {
            KeyedAuthorization::Contract => Identifier::Contract(env.get_invoking_contract()),
            KeyedAuthorization::Ed25519(kea) => Identifier::Ed25519(kea.public_key.clone()),
            KeyedAuthorization::Account(kaa) => Identifier::Account(kaa.public_key.clone()),
        }
    }
}

#[derive(Clone)]
#[contracttype]
pub enum Identifier {
    Contract(U256),
    Ed25519(U256),
    Account(U256),
}

// TODO: This is missing fields
#[derive(Clone)]
#[contracttype]
pub struct MessageV0 {
    pub nonce: BigInt,
    pub domain: u32,
    pub parameters: Vec<EnvVal>,
}

#[derive(Clone)]
#[contracttype]
pub enum Message {
    V0(MessageV0),
}
