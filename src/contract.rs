use crate::admin::{has_administrator, to_administrator_authorization, write_administrator};
use crate::allowance::{read_allowance, spend_allowance, write_allowance};
use crate::balance::{read_balance, receive_balance, spend_balance};
use crate::balance::{read_state, write_state};
use crate::cryptography::{check_auth, Domain};
use crate::metadata::{
    read_decimal, read_name, read_symbol, write_decimal, write_name, write_symbol,
};
use crate::nonce::read_nonce;
use crate::public_types::{Authorization, Identifier, KeyedAuthorization};
use soroban_sdk::{contractimpl, BigInt, Binary, Env, IntoVal};

pub trait TokenTrait {
    fn initialize(e: Env, admin: Identifier, decimal: u32, name: Binary, symbol: Binary);

    fn nonce(e: Env, id: Identifier) -> BigInt;

    fn allowance(e: Env, from: Identifier, spender: Identifier) -> BigInt;

    fn approve(e: Env, from: KeyedAuthorization, spender: Identifier, amount: BigInt);

    fn balance(e: Env, id: Identifier) -> BigInt;

    fn is_frozen(e: Env, id: Identifier) -> bool;

    fn xfer(e: Env, from: KeyedAuthorization, to: Identifier, amount: BigInt);

    fn xfer_from(
        e: Env,
        spender: KeyedAuthorization,
        from: Identifier,
        to: Identifier,
        amount: BigInt,
    );

    fn burn(e: Env, admin: Authorization, from: Identifier, amount: BigInt);

    fn freeze(e: Env, admin: Authorization, id: Identifier);

    fn mint(e: Env, admin: Authorization, to: Identifier, amount: BigInt);

    fn set_admin(e: Env, admin: Authorization, new_admin: Identifier);

    fn unfreeze(e: Env, admin: Authorization, id: Identifier);

    fn decimals(e: Env) -> u32;

    fn name(e: Env) -> Binary;

    fn symbol(e: Env) -> Binary;
}

pub struct Token;

#[contractimpl(export_if = "export")]
impl TokenTrait for Token {
    fn initialize(e: Env, admin: Identifier, decimal: u32, name: Binary, symbol: Binary) {
        if has_administrator(&e) {
            panic!("already initialized")
        }
        write_administrator(&e, admin);

        write_decimal(&e, u8::try_from(decimal).expect("Decimal must fit in a u8"));
        write_name(&e, name);
        write_symbol(&e, symbol);
    }

    fn nonce(e: Env, id: Identifier) -> BigInt {
        read_nonce(&e, id)
    }

    fn allowance(e: Env, from: Identifier, spender: Identifier) -> BigInt {
        read_allowance(&e, from, spender)
    }

    fn approve(e: Env, from: KeyedAuthorization, spender: Identifier, amount: BigInt) {
        let from_id = from.get_identifier(&e);
        check_auth(
            &e,
            from,
            Domain::Approve,
            (spender.clone(), amount.clone()).into_val(&e),
        );
        write_allowance(&e, from_id, spender, amount);
    }

    fn balance(e: Env, id: Identifier) -> BigInt {
        read_balance(&e, id)
    }

    fn is_frozen(e: Env, id: Identifier) -> bool {
        read_state(&e, id)
    }

    fn xfer(e: Env, from: KeyedAuthorization, to: Identifier, amount: BigInt) {
        let from_id = from.get_identifier(&e);
        check_auth(
            &e,
            from,
            Domain::Transfer,
            (to.clone(), amount.clone()).into_val(&e),
        );
        spend_balance(&e, from_id, amount.clone());
        receive_balance(&e, to, amount);
    }

    fn xfer_from(
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
            (from.clone(), to.clone(), amount.clone()).into_val(&e),
        );
        spend_allowance(&e, from.clone(), spender_id, amount.clone());
        spend_balance(&e, from, amount.clone());
        receive_balance(&e, to, amount);
    }

    fn burn(e: Env, admin: Authorization, from: Identifier, amount: BigInt) {
        let auth = to_administrator_authorization(&e, admin);
        check_auth(
            &e,
            auth,
            Domain::Burn,
            (from.clone(), amount.clone()).into_val(&e),
        );
        spend_balance(&e, from, amount);
    }

    fn freeze(e: Env, admin: Authorization, id: Identifier) {
        let auth = to_administrator_authorization(&e, admin);
        check_auth(&e, auth, Domain::Freeze, (id.clone(),).into_val(&e));
        write_state(&e, id, true);
    }

    fn mint(e: Env, admin: Authorization, to: Identifier, amount: BigInt) {
        let auth = to_administrator_authorization(&e, admin);
        check_auth(
            &e,
            auth,
            Domain::Mint,
            (to.clone(), amount.clone()).into_val(&e),
        );
        receive_balance(&e, to, amount);
    }

    fn set_admin(e: Env, admin: Authorization, new_admin: Identifier) {
        let auth = to_administrator_authorization(&e, admin);
        check_auth(
            &e,
            auth,
            Domain::SetAdministrator,
            (new_admin.clone(),).into_val(&e),
        );
        write_administrator(&e, new_admin);
    }

    fn unfreeze(e: Env, admin: Authorization, id: Identifier) {
        let auth = to_administrator_authorization(&e, admin);
        check_auth(&e, auth, Domain::Unfreeze, (id.clone(),).into_val(&e));
        write_state(&e, id, false);
    }

    fn decimals(e: Env) -> u32 {
        read_decimal(&e)
    }

    fn name(e: Env) -> Binary {
        read_name(&e)
    }

    fn symbol(e: Env) -> Binary {
        read_symbol(&e)
    }
}
