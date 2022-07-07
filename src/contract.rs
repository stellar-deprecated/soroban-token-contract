use crate::admin::{has_administrator, to_administrator_authorization, write_administrator};
use crate::allowance::{read_allowance, spend_allowance, write_allowance};
use crate::balance::{read_balance, receive_balance, spend_balance};
use crate::balance::{read_state, write_state};
use crate::cryptography::{check_auth, Domain};
use crate::nonce::read_nonce;
use crate::public_types::{Authorization, Identifier, KeyedAuthorization};
use stellar_contract_sdk::{contractfn, BigInt, Env, IntoEnvVal};

#[contractfn]
pub fn initialize(e: Env, admin: Identifier) {
    if has_administrator(&e) {
        panic!()
    }
    write_administrator(&e, admin);
}

#[contractfn]
pub fn nonce(e: Env, id: Identifier) -> BigInt {
    read_nonce(&e, id)
}

#[contractfn]
pub fn allowance(e: Env, from: Identifier, spender: Identifier) -> BigInt {
    read_allowance(&e, from, spender)
}

#[contractfn]
pub fn approve(e: Env, from: KeyedAuthorization, spender: Identifier, amount: BigInt) {
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
pub fn balance(e: Env, id: Identifier) -> BigInt {
    read_balance(&e, id)
}

#[contractfn]
pub fn is_frozen(e: Env, id: Identifier) -> bool {
    read_state(&e, id)
}

#[contractfn]
pub fn xfer(e: Env, from: KeyedAuthorization, to: Identifier, amount: BigInt) {
    let from_id = from.get_identifier(&e);
    check_auth(
        &e,
        from,
        Domain::Transfer,
        (to.clone(), amount.clone()).into_env_val(&e),
    );
    spend_balance(&e, from_id, amount.clone());
    receive_balance(&e, to, amount);
}

#[contractfn]
pub fn xfer_from(
    e: Env,
    spender: KeyedAuthorization,
    from: Identifier,
    to: Identifier,
    amount: BigInt,
) {
    let spender_id = spender.get_identifier(&e);
    check_auth(
        &e,
        spender,
        Domain::TransferFrom,
        (from.clone(), to.clone(), amount.clone()).into_env_val(&e),
    );
    spend_allowance(&e, from.clone(), spender_id, amount.clone());
    spend_balance(&e, from, amount.clone());
    receive_balance(&e, to, amount);
}

#[contractfn]
pub fn burn(e: Env, admin: Authorization, from: Identifier, amount: BigInt) {
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
pub fn mint(e: Env, admin: Authorization, to: Identifier, amount: BigInt) {
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
    check_auth(
        &e,
        auth,
        Domain::Unfreeze,
        (id.clone(), ()).into_env_val(&e),
    );
    write_state(&e, id, false);
}
