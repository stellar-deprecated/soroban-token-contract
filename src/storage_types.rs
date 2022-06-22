use crate::Identifier;
use stellar_contract_sdk::{Env, EnvVal, IntoEnvVal, RawVal};

#[derive(Clone)]
pub struct AllowanceDataKey {
    pub from: Identifier,
    pub spender: Identifier,
}

impl IntoEnvVal<Env, RawVal> for AllowanceDataKey {
    #[inline(always)]
    fn into_env_val(self, env: &Env) -> EnvVal {
        (self.from, self.spender).into_env_val(env)
    }
}

#[derive(Clone)]
pub enum DataKey {
    Allowance(AllowanceDataKey),
    Balance(Identifier),
    Nonce(Identifier),
    State(Identifier),
    Administrator,
}

impl IntoEnvVal<Env, RawVal> for DataKey {
    #[inline(always)]
    fn into_env_val(self, env: &Env) -> EnvVal {
        match self {
            DataKey::Allowance(adk) => (0u32, adk).into_env_val(env),
            DataKey::Balance(id) => (1u32, id).into_env_val(env),
            DataKey::Nonce(id) => (2u32, id).into_env_val(env),
            DataKey::State(id) => (3u32, id).into_env_val(env),
            DataKey::Administrator => (4u32, ()).into_env_val(env),
        }
    }
}
