use ed25519_dalek::Keypair;
use external::MessageWithoutNonce as ContractFn;
use num_bigint::BigInt;
use rand::{thread_rng, RngCore};
use stellar_contract_sdk::Env;
use stellar_token_contract::{external, external::Identifier};

fn generate_contract_id() -> [u8; 32] {
    let mut id: [u8; 32] = Default::default();
    thread_rng().fill_bytes(&mut id);
    id
}

fn generate_keypair() -> Keypair {
    Keypair::generate(&mut thread_rng())
}

fn make_auth(kp: &Keypair, msg: &external::Message) -> external::Authorization {
    let signature = msg.sign(kp).unwrap();
    external::Authorization::Ed25519(signature)
}

fn make_keyed_auth(kp: &Keypair, msg: &external::Message) -> external::KeyedAuthorization {
    use external::{KeyedAuthorization, KeyedEd25519Authorization};
    let signature = msg.sign(kp).unwrap();
    KeyedAuthorization::Ed25519(KeyedEd25519Authorization {
        public_key: kp.public.to_bytes(),
        signature,
    })
}

struct Token(Env, [u8; 32]);

impl Token {
    fn initialize(&mut self, admin: &Identifier, decimal: u32, name: &str, symbol: &str) {
        let n = stellar_contract_sdk::Vec::from_slice(&mut self.0, name.as_bytes());
        let s = stellar_contract_sdk::Vec::from_slice(&mut self.0, symbol.as_bytes());
        external::initialize(&mut self.0, &self.1, admin, &decimal, &n, &s);
    }

    fn nonce(&mut self, id: &Identifier) -> BigInt {
        external::nonce(&mut self.0, &self.1, id)
    }

    fn allowance(&mut self, from: &Identifier, spender: &Identifier) -> BigInt {
        external::allowance(&mut self.0, &self.1, from, spender)
    }

    fn approve(&mut self, from: &Keypair, spender: &Identifier, amount: BigInt) {
        let from_id = Identifier::Ed25519(from.public.to_bytes());
        let msg = external::Message(
            self.nonce(&from_id),
            ContractFn::Approve(spender.clone(), amount.clone()),
        );
        external::approve(
            &mut self.0,
            &self.1,
            &make_keyed_auth(from, &msg),
            spender,
            &amount,
        );
    }

    fn balance(&mut self, id: &Identifier) -> BigInt {
        external::balance(&mut self.0, &self.1, id)
    }

    fn is_frozen(&mut self, id: &Identifier) -> bool {
        external::is_frozen(&mut self.0, &self.1, id)
    }

    fn xfer(&mut self, from: &Keypair, to: &Identifier, amount: BigInt) {
        let from_id = Identifier::Ed25519(from.public.to_bytes());
        let msg = external::Message(
            self.nonce(&from_id),
            ContractFn::Transfer(to.clone(), amount.clone()),
        );
        external::xfer(
            &mut self.0,
            &self.1,
            &make_keyed_auth(from, &msg),
            to,
            &amount,
        );
    }

    fn xfer_from(&mut self, spender: &Keypair, from: &Identifier, to: &Identifier, amount: BigInt) {
        let spender_id = Identifier::Ed25519(spender.public.to_bytes());
        let msg = external::Message(
            self.nonce(&spender_id),
            ContractFn::TransferFrom(from.clone(), to.clone(), amount.clone()),
        );
        external::xfer_from(
            &mut self.0,
            &self.1,
            &make_keyed_auth(spender, &msg),
            from,
            to,
            &amount,
        );
    }

    fn burn(&mut self, admin: &Keypair, from: &Identifier, amount: BigInt) {
        let admin_id = Identifier::Ed25519(admin.public.to_bytes());
        let msg = external::Message(
            self.nonce(&admin_id),
            ContractFn::Burn(from.clone(), amount.clone()),
        );
        external::burn(&mut self.0, &self.1, &make_auth(admin, &msg), from, &amount);
    }

    fn freeze(&mut self, admin: &Keypair, id: &Identifier) {
        let admin_id = Identifier::Ed25519(admin.public.to_bytes());
        let msg = external::Message(self.nonce(&admin_id), ContractFn::Freeze(id.clone()));
        external::freeze(&mut self.0, &self.1, &make_auth(admin, &msg), id);
    }

    fn mint(&mut self, admin: &Keypair, to: &Identifier, amount: BigInt) {
        let admin_id = Identifier::Ed25519(admin.public.to_bytes());
        let msg = external::Message(
            self.nonce(&admin_id),
            ContractFn::Mint(to.clone(), amount.clone()),
        );
        external::mint(&mut self.0, &self.1, &make_auth(admin, &msg), to, &amount);
    }

    fn set_admin(&mut self, admin: &Keypair, new_admin: &Identifier) {
        let admin_id = Identifier::Ed25519(admin.public.to_bytes());
        let msg = external::Message(
            self.nonce(&admin_id),
            ContractFn::SetAdministrator(new_admin.clone()),
        );
        external::set_admin(&mut self.0, &self.1, &make_auth(admin, &msg), new_admin);
    }

    fn unfreeze(&mut self, admin: &Keypair, id: &Identifier) {
        let admin_id = Identifier::Ed25519(admin.public.to_bytes());
        let msg = external::Message(self.nonce(&admin_id), ContractFn::Unfreeze(id.clone()));
        external::unfreeze(&mut self.0, &self.1, &make_auth(admin, &msg), id);
    }

    fn decimals(&mut self) -> u32 {
        external::decimals(&mut self.0, &self.1)
    }

    fn name(&mut self) -> stellar_contract_sdk::Vec<u8> {
        external::name(&mut self.0, &self.1)
    }

    fn symbol(&mut self) -> stellar_contract_sdk::Vec<u8> {
        external::symbol(&mut self.0, &self.1)
    }
}

#[test]
fn test() {
    let e = Env::with_empty_recording_storage();
    let contract_id = generate_contract_id();
    external::register_test_contract(&e, &contract_id);

    let name = "name";
    let symbol = "symbol";
    let name_vec = stellar_contract_sdk::Vec::from_slice(&e, name.as_bytes());
    let symbol_vec = stellar_contract_sdk::Vec::from_slice(&e, symbol.as_bytes());

    let mut token = Token(e, contract_id.clone());

    let admin1 = generate_keypair();
    let admin2 = generate_keypair();
    let user1 = generate_keypair();
    let user2 = generate_keypair();
    let user3 = generate_keypair();
    let admin1_id = Identifier::Ed25519(admin1.public.to_bytes());
    let admin2_id = Identifier::Ed25519(admin2.public.to_bytes());
    let user1_id = Identifier::Ed25519(user1.public.to_bytes());
    let user2_id = Identifier::Ed25519(user2.public.to_bytes());
    let user3_id = Identifier::Ed25519(user3.public.to_bytes());

    token.initialize(&admin1_id, 10, name, symbol);

    assert_eq!(token.decimals(), 10);
    assert_eq!(token.name(), name_vec);
    assert_eq!(token.symbol(), symbol_vec);

    token.mint(&admin1, &user1_id, 1000u64.into());
    assert_eq!(token.balance(&user1_id), 1000u64.into());
    assert_eq!(token.nonce(&admin1_id), 1u64.into());

    token.approve(&user2, &user3_id, 500u64.into());
    assert_eq!(token.allowance(&user2_id, &user3_id), 500u64.into());
    assert_eq!(token.nonce(&user2_id), 1u64.into());

    token.xfer(&user1, &user2_id, 600u64.into());
    assert_eq!(token.balance(&user1_id), 400u64.into());
    assert_eq!(token.balance(&user2_id), 600u64.into());
    assert_eq!(token.nonce(&user1_id), 1u64.into());

    token.xfer_from(&user3, &user2_id, &user1_id, 400u64.into());
    assert_eq!(token.balance(&user1_id), 800u64.into());
    assert_eq!(token.balance(&user2_id), 200u64.into());
    assert_eq!(token.nonce(&user3_id), 1u64.into());

    token.xfer(&user1, &user3_id, 300u64.into());
    assert_eq!(token.balance(&user1_id), 500u64.into());
    assert_eq!(token.balance(&user3_id), 300u64.into());
    assert_eq!(token.nonce(&user1_id), 2u64.into());

    token.set_admin(&admin1, &admin2_id);
    assert_eq!(token.nonce(&admin1_id), 2u64.into());

    token.freeze(&admin2, &user2_id);
    assert_eq!(token.is_frozen(&user2_id), true);
    assert_eq!(token.nonce(&admin2_id), 1u64.into());

    token.unfreeze(&admin2, &user3_id);
    assert_eq!(token.is_frozen(&user3_id), false);
    assert_eq!(token.nonce(&admin2_id), 2u64.into());

    token.burn(&admin2, &user3_id, 100u64.into());
    assert_eq!(token.balance(&user3_id), 200u64.into());
    assert_eq!(token.nonce(&admin2_id), 3u64.into());
}

#[test]
#[should_panic(expected = "insufficient balance")]
fn xfer_insufficient_balance() {
    let e = Env::with_empty_recording_storage();
    let contract_id = generate_contract_id();
    external::register_test_contract(&e, &contract_id);
    let mut token = Token(e, contract_id.clone());

    let admin1 = generate_keypair();
    let user1 = generate_keypair();
    let user2 = generate_keypair();
    let admin1_id = Identifier::Ed25519(admin1.public.to_bytes());
    let user1_id = Identifier::Ed25519(user1.public.to_bytes());
    let user2_id = Identifier::Ed25519(user2.public.to_bytes());

    token.initialize(&admin1_id, 10, "name", "symbol");

    token.mint(&admin1, &user1_id, 1000u64.into());
    assert_eq!(token.balance(&user1_id), 1000u64.into());
    assert_eq!(token.nonce(&admin1_id), 1u64.into());

    token.xfer(&user1, &user2_id, 1001u64.into());
}

#[test]
#[should_panic(expected = "can't receive when frozen")]
fn xfer_receive_frozen() {
    let e = Env::with_empty_recording_storage();
    let contract_id = generate_contract_id();
    external::register_test_contract(&e, &contract_id);
    let mut token = Token(e, contract_id.clone());

    let admin1 = generate_keypair();
    let user1 = generate_keypair();
    let user2 = generate_keypair();
    let admin1_id = Identifier::Ed25519(admin1.public.to_bytes());
    let user1_id = Identifier::Ed25519(user1.public.to_bytes());
    let user2_id = Identifier::Ed25519(user2.public.to_bytes());

    token.initialize(&admin1_id, 10, "name", "symbol");

    token.mint(&admin1, &user1_id, 1000u64.into());
    assert_eq!(token.balance(&user1_id), 1000u64.into());
    assert_eq!(token.nonce(&admin1_id), 1u64.into());

    token.freeze(&admin1, &user2_id);
    token.xfer(&user1, &user2_id, 1u64.into());
}

#[test]
#[should_panic(expected = "can't spend when frozen")]
fn xfer_spend_frozen() {
    let e = Env::with_empty_recording_storage();
    let contract_id = generate_contract_id();
    external::register_test_contract(&e, &contract_id);
    let mut token = Token(e, contract_id.clone());

    let admin1 = generate_keypair();
    let user1 = generate_keypair();
    let user2 = generate_keypair();
    let admin1_id = Identifier::Ed25519(admin1.public.to_bytes());
    let user1_id = Identifier::Ed25519(user1.public.to_bytes());
    let user2_id = Identifier::Ed25519(user2.public.to_bytes());

    token.initialize(&admin1_id, 10, "name", "symbol");

    token.mint(&admin1, &user1_id, 1000u64.into());
    assert_eq!(token.balance(&user1_id), 1000u64.into());
    assert_eq!(token.nonce(&admin1_id), 1u64.into());

    token.freeze(&admin1, &user1_id);
    token.xfer(&user1, &user2_id, 1u64.into());
}

#[test]
#[should_panic(expected = "insufficient allowance")]
fn xfer_from_insufficient_allowance() {
    let e = Env::with_empty_recording_storage();
    let contract_id = generate_contract_id();
    external::register_test_contract(&e, &contract_id);
    let mut token = Token(e, contract_id.clone());

    let admin1 = generate_keypair();
    let user1 = generate_keypair();
    let user2 = generate_keypair();
    let user3 = generate_keypair();
    let admin1_id = Identifier::Ed25519(admin1.public.to_bytes());
    let user1_id = Identifier::Ed25519(user1.public.to_bytes());
    let user2_id = Identifier::Ed25519(user2.public.to_bytes());
    let user3_id = Identifier::Ed25519(user3.public.to_bytes());

    token.initialize(&admin1_id, 10, "name", "symbol");

    token.mint(&admin1, &user1_id, 1000u64.into());
    assert_eq!(token.balance(&user1_id), 1000u64.into());
    assert_eq!(token.nonce(&admin1_id), 1u64.into());

    token.approve(&user1, &user3_id, 100u64.into());
    assert_eq!(token.allowance(&user1_id, &user3_id), 100u64.into());
    assert_eq!(token.nonce(&user1_id), 1u64.into());

    token.xfer_from(&user3, &user1_id, &user2_id, 101u64.into());
}

#[test]
#[should_panic(expected = "already initialized")]
fn initialize_already_initialized() {
    let e = Env::with_empty_recording_storage();
    let contract_id = generate_contract_id();
    external::register_test_contract(&e, &contract_id);
    let mut token = Token(e, contract_id.clone());

    let admin1 = generate_keypair();
    let admin1_id = Identifier::Ed25519(admin1.public.to_bytes());

    token.initialize(&admin1_id, 10, "name", "symbol");
    token.initialize(&admin1_id, 10, "name", "symbol");
}

#[test]
#[should_panic] // TODO: Add expected
fn set_admin_bad_signature() {
    let e = Env::with_empty_recording_storage();
    let contract_id = generate_contract_id();
    external::register_test_contract(&e, &contract_id);
    let mut token = Token(e, contract_id.clone());

    let admin1 = generate_keypair();
    let admin2 = generate_keypair();
    let admin1_id = Identifier::Ed25519(admin1.public.to_bytes());
    let admin2_id = Identifier::Ed25519(admin2.public.to_bytes());

    token.initialize(&admin1_id, 10, "name", "symbol");

    let mut signature: [u8; 64] = vec![0; 64].as_slice().try_into().unwrap();
    thread_rng().fill_bytes(&mut signature);
    let auth = external::Authorization::Ed25519(signature);
    external::set_admin(&mut token.0, &token.1, &auth, &admin2_id);
}

#[test]
#[should_panic(expected = "Decimal must fit in a u8")]
fn decimal_is_over_max() {
    let e = Env::with_empty_recording_storage();
    let contract_id = generate_contract_id();
    external::register_test_contract(&e, &contract_id);
    let mut token = Token(e, contract_id.clone());

    let admin1 = generate_keypair();
    let admin1_id = Identifier::Ed25519(admin1.public.to_bytes());

    token.initialize(&admin1_id, u32::from(u8::MAX) + 1, "name", "symbol");
}
