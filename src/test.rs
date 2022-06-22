#![cfg(test)]

use crate::public_types::{Authorization, Ed25519Authorization, Identifier};
use stellar_contract_sdk::{ArrayBinary, Binary, Env, FixedLengthBinary, VariableLengthBinary};

fn make_binary<const N: u32>(e: &Env, x: u8) -> ArrayBinary<N> {
    let mut bin = Binary::new(e);
    bin.push(x);
    for _ in 0..(N - 1) {
        bin.push(0);
    }
    assert_eq!(bin.len(), N);
    bin.try_into().unwrap()
}

#[test]
fn mint_and_burn() {
    let e = Env::with_empty_recording_storage();
    let _fg = e.push_test_frame(make_binary::<32>(&e, 0));

    let admin = Authorization::Ed25519(Ed25519Authorization {
        nonce: make_binary(&e, 0),
        signature: make_binary(&e, 0),
    });
    let id = Identifier::Ed25519(make_binary(&e, 1));

    super::mint(e.clone(), admin.clone(), id.clone(), 1000);
    assert_eq!(super::balance(e.clone(), id.clone()), 1000);

    super::burn(e.clone(), admin.clone(), id.clone(), 200);
    assert_eq!(super::balance(e.clone(), id.clone()), 800);
}
