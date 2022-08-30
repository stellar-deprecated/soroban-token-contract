use soroban_sdk::contracttype;
use soroban_sdk_auth::Identifier;

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
    Admin,
    Decimals,
    Name,
    Symbol,
}
