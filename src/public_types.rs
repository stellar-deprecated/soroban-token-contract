use stellar_contract_sdk::{ArrayBinary, Env, EnvVal, IntoEnvVal, RawVal, Vec};

pub type U256 = ArrayBinary<32>;
pub type U512 = ArrayBinary<64>;

#[derive(Clone)]
pub struct KeyedEd25519Signature {
    pub public_key: U256,
    pub signature: U512,
}

impl TryFrom<EnvVal> for KeyedEd25519Signature {
    type Error = ();

    #[inline(always)]
    fn try_from(ev: EnvVal) -> Result<Self, Self::Error> {
        let (public_key, signature): (U256, U512) = ev.try_into()?;
        Ok(KeyedEd25519Signature {
            public_key,
            signature,
        })
    }
}

impl IntoEnvVal<Env, RawVal> for KeyedEd25519Signature {
    #[inline(always)]
    fn into_env_val(self, env: &Env) -> EnvVal {
        (self.public_key, self.signature).into_env_val(env)
    }
}

#[derive(Clone)]
pub struct Ed25519Authorization {
    pub nonce: U256,
    pub signature: U512,
}

impl TryFrom<EnvVal> for Ed25519Authorization {
    type Error = ();

    #[inline(always)]
    fn try_from(ev: EnvVal) -> Result<Self, Self::Error> {
        let (nonce, signature): (U256, U512) = ev.try_into()?;
        Ok(Ed25519Authorization { nonce, signature })
    }
}

impl IntoEnvVal<Env, RawVal> for Ed25519Authorization {
    #[inline(always)]
    fn into_env_val(self, env: &Env) -> EnvVal {
        (self.nonce, self.signature).into_env_val(env)
    }
}

#[derive(Clone)]
pub struct KeyedEd25519Authorization {
    pub public_key: U256,
    pub authorization: Ed25519Authorization,
}

impl TryFrom<EnvVal> for KeyedEd25519Authorization {
    type Error = ();

    #[inline(always)]
    fn try_from(ev: EnvVal) -> Result<Self, Self::Error> {
        let (public_key, authorization): (U256, Ed25519Authorization) = ev.try_into()?;
        Ok(KeyedEd25519Authorization {
            public_key,
            authorization,
        })
    }
}

impl IntoEnvVal<Env, RawVal> for KeyedEd25519Authorization {
    #[inline(always)]
    fn into_env_val(self, env: &Env) -> EnvVal {
        (self.public_key, self.authorization).into_env_val(env)
    }
}

#[derive(Clone)]
pub struct AccountAuthorization {
    pub nonce: U256,
    pub signatures: Vec<KeyedEd25519Signature>,
}

impl TryFrom<EnvVal> for AccountAuthorization {
    type Error = ();

    #[inline(always)]
    fn try_from(ev: EnvVal) -> Result<Self, Self::Error> {
        let (nonce, signatures): (U256, Vec<KeyedEd25519Signature>) = ev.try_into()?;
        Ok(AccountAuthorization { nonce, signatures })
    }
}

impl IntoEnvVal<Env, RawVal> for AccountAuthorization {
    #[inline(always)]
    fn into_env_val(self, env: &Env) -> EnvVal {
        (self.nonce, self.signatures).into_env_val(env)
    }
}

#[derive(Clone)]
pub struct KeyedAccountAuthorization {
    pub public_key: U256,
    pub authorization: AccountAuthorization,
}

impl TryFrom<EnvVal> for KeyedAccountAuthorization {
    type Error = ();

    #[inline(always)]
    fn try_from(ev: EnvVal) -> Result<Self, Self::Error> {
        let (public_key, authorization): (U256, AccountAuthorization) = ev.try_into()?;
        Ok(KeyedAccountAuthorization {
            public_key,
            authorization,
        })
    }
}

impl IntoEnvVal<Env, RawVal> for KeyedAccountAuthorization {
    #[inline(always)]
    fn into_env_val(self, env: &Env) -> EnvVal {
        (self.public_key, self.authorization).into_env_val(env)
    }
}

#[derive(Clone)]
pub enum Authorization {
    Contract,
    Ed25519(Ed25519Authorization),
    Account(AccountAuthorization),
}

impl TryFrom<EnvVal> for Authorization {
    type Error = ();

    #[inline(always)]
    fn try_from(ev: EnvVal) -> Result<Self, Self::Error> {
        let (discriminant, tail): (u32, EnvVal) = ev.try_into()?;
        match discriminant {
            0 => Ok(Authorization::Contract),
            1 => Ok(Authorization::Ed25519(tail.try_into()?)),
            2 => Ok(Authorization::Account(tail.try_into()?)),
            _ => Err(()),
        }
    }
}

impl IntoEnvVal<Env, RawVal> for Authorization {
    #[inline(always)]
    fn into_env_val(self, env: &Env) -> EnvVal {
        match self {
            Authorization::Contract => (0u32, ()).into_env_val(env),
            Authorization::Ed25519(ea) => (1u32, ea).into_env_val(env),
            Authorization::Account(aa) => (2u32, aa).into_env_val(env),
        }
    }
}

#[derive(Clone)]
pub enum KeyedAuthorization {
    Contract,
    Ed25519(KeyedEd25519Authorization),
    Account(KeyedAccountAuthorization),
}

impl TryFrom<EnvVal> for KeyedAuthorization {
    type Error = ();

    #[inline(always)]
    fn try_from(ev: EnvVal) -> Result<Self, Self::Error> {
        let (discriminant, tail): (u32, EnvVal) = ev.try_into()?;
        match discriminant {
            0 => Ok(KeyedAuthorization::Contract),
            1 => Ok(KeyedAuthorization::Ed25519(tail.try_into()?)),
            2 => Ok(KeyedAuthorization::Account(tail.try_into()?)),
            _ => Err(()),
        }
    }
}

impl IntoEnvVal<Env, RawVal> for KeyedAuthorization {
    #[inline(always)]
    fn into_env_val(self, env: &Env) -> EnvVal {
        match self {
            KeyedAuthorization::Contract => (0u32, ()).into_env_val(env),
            KeyedAuthorization::Ed25519(kea) => (1u32, kea).into_env_val(env),
            KeyedAuthorization::Account(kaa) => (2u32, kaa).into_env_val(env),
        }
    }
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
pub enum Identifier {
    Contract(U256),
    Ed25519(U256),
    Account(U256),
}

impl TryFrom<EnvVal> for Identifier {
    type Error = ();

    #[inline(always)]
    fn try_from(ev: EnvVal) -> Result<Self, Self::Error> {
        let (discriminant, tail): (u32, EnvVal) = ev.try_into()?;
        match discriminant {
            0 => Ok(Identifier::Contract(tail.try_into()?)),
            1 => Ok(Identifier::Ed25519(tail.try_into()?)),
            2 => Ok(Identifier::Account(tail.try_into()?)),
            _ => Err(()),
        }
    }
}

impl IntoEnvVal<Env, RawVal> for Identifier {
    #[inline(always)]
    fn into_env_val(self, env: &Env) -> EnvVal {
        match self {
            Identifier::Contract(addr) => (0u32, addr).into_env_val(env),
            Identifier::Ed25519(public_key) => (1u32, public_key).into_env_val(env),
            Identifier::Account(public_key) => (2u32, public_key).into_env_val(env),
        }
    }
}

// TODO: This is missing fields
#[derive(Clone)]
pub struct MessageV0 {
    pub nonce: u64,
    pub domain: u32,
    pub parameters: Vec<EnvVal>,
}

impl TryFrom<EnvVal> for MessageV0 {
    type Error = ();

    #[inline(always)]
    fn try_from(ev: EnvVal) -> Result<Self, Self::Error> {
        let (nonce, domain, parameters): (u64, u32, Vec<EnvVal>) = ev.try_into()?;
        Ok(MessageV0 {
            nonce,
            domain,
            parameters,
        })
    }
}

impl IntoEnvVal<Env, RawVal> for MessageV0 {
    #[inline(always)]
    fn into_env_val(self, env: &Env) -> EnvVal {
        (self.nonce, self.domain, self.parameters).into_env_val(env)
    }
}

#[derive(Clone)]
pub enum Message {
    V0(MessageV0),
}

impl TryFrom<EnvVal> for Message {
    type Error = ();

    #[inline(always)]
    fn try_from(ev: EnvVal) -> Result<Self, Self::Error> {
        let (discriminant, tail): (u32, EnvVal) = ev.try_into()?;
        match discriminant {
            0 => Ok(Message::V0(tail.try_into()?)),
            _ => Err(()),
        }
    }
}

impl IntoEnvVal<Env, RawVal> for Message {
    #[inline(always)]
    fn into_env_val(self, env: &Env) -> EnvVal {
        match self {
            Message::V0(v0) => (0u32, v0).into_env_val(env),
        }
    }
}
