#![no_std]

mod admin;
mod allowance;
mod balance;
mod cryptography;
mod nonce;
mod public_types;
mod storage_types;
mod test;

use admin::{to_administrator_authorization, write_administrator};
use allowance::{read_allowance, spend_allowance, write_allowance};
use balance::{read_balance, receive_balance, spend_balance};
use balance::{read_state, write_state};
use cryptography::{check_auth, Domain};
use public_types::{Authorization, Identifier, KeyedAuthorization};
use stellar_contract_sdk::{contractfn, Env, IntoEnvVal};

#[contractfn]
pub fn allowance(e: Env, from: Identifier, spender: Identifier) -> u64 {
    read_allowance(&e, from, spender)
}

#[contractfn]
pub fn approve(e: Env, from: KeyedAuthorization, spender: Identifier, amount: u64) {
    let from_id = from.get_identifier(&e);
    check_auth(
        &e,
        from,
        Domain::Approve,
        (spender.clone(), amount.clone()).into_env_val(&e),
    );
    write_allowance(&e, from_id, spender, amount);
}

#[contractfn]
pub fn balance(e: Env, id: Identifier) -> u64 {
    read_balance(&e, id)
}

#[contractfn]
pub fn is_frozen(e: Env, id: Identifier) -> bool {
    read_state(&e, id)
}

#[contractfn]
pub fn xfer(e: Env, from: KeyedAuthorization, to: Identifier, amount: u64) {
    let from_id = from.get_identifier(&e);
    check_auth(
        &e,
        from,
        Domain::Transfer,
        (to.clone(), amount.clone()).into_env_val(&e),
    );
    spend_balance(&e, from_id, amount);
    receive_balance(&e, to, amount);
}

#[contractfn]
pub fn xfer_from(
    e: Env,
    spender: KeyedAuthorization,
    from: Identifier,
    to: Identifier,
    amount: u64,
) {
    let spender_id = spender.get_identifier(&e);
    check_auth(
        &e,
        spender,
        Domain::TransferFrom,
        (from.clone(), to.clone(), amount.clone()).into_env_val(&e),
    );
    spend_allowance(&e, from.clone(), spender_id, amount);
    spend_balance(&e, from, amount);
    receive_balance(&e, to, amount);
}

#[contractfn]
pub fn burn(e: Env, admin: Authorization, from: Identifier, amount: u64) {
    let auth = to_administrator_authorization(&e, admin);
    check_auth(
        &e,
        auth,
        Domain::Burn,
        (from.clone(), amount.clone()).into_env_val(&e),
    );
    spend_balance(&e, from, amount);
}

#[contractfn]
pub fn freeze(e: Env, admin: Authorization, id: Identifier) {
    let auth = to_administrator_authorization(&e, admin);
    check_auth(
        &e,
        auth,
        Domain::Freeze,
        (id.clone(), ()).clone().into_env_val(&e),
    );
    write_state(&e, id, true);
}

#[contractfn]
pub fn mint(e: Env, admin: Authorization, to: Identifier, amount: u64) {
    let auth = to_administrator_authorization(&e, admin);
    check_auth(
        &e,
        auth,
        Domain::Mint,
        (to.clone(), amount.clone()).into_env_val(&e),
    );
    receive_balance(&e, to, amount);
}

#[contractfn]
pub fn set_admin(e: Env, admin: Authorization, new_admin: Identifier) {
    let auth = to_administrator_authorization(&e, admin);
    check_auth(
        &e,
        auth,
        Domain::SetAdministrator,
        (new_admin.clone(), ()).into_env_val(&e),
    );
    write_administrator(&e, new_admin);
}

#[contractfn]
pub fn unfreeze(e: Env, admin: Authorization, id: Identifier) {
    let auth = to_administrator_authorization(&e, admin);
    check_auth(&e, auth, Domain::Unfreeze, id.clone().into_env_val(&e));
    write_state(&e, id, false);
}
