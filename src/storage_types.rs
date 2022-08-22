use soroban_authorization_contract::public_types::Identifier;
use soroban_sdk::contracttype;

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
