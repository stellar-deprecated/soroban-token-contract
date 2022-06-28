use crate::Identifier;
use stellar_contract_sdk::{contracttype, Env, EnvVal, IntoEnvVal, RawVal};

#[derive(Clone)]
#[contracttype]
pub struct AllowanceDataKey {
    pub from: Identifier,
    pub spender: Identifier,
}

#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    Allowance(AllowanceDataKey),
    Balance(Identifier),
    Nonce(Identifier),
    State(Identifier),
    Administrator,
}
