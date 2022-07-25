#![cfg(feature = "testutils")]

use stellar_contract_sdk::{Binary, Env};

pub fn register_test_contract(e: &Env, contract_id: &[u8; 32]) {
    let contract_id = Binary::from_array(e, *contract_id);
    e.register_contract(contract_id, crate::contract::Token {});
}

pub use crate::contract::__initialize::call_external as initialize;
pub use crate::contract::__nonce::call_external as nonce;
pub use crate::contract::__allowance::call_external as allowance;
pub use crate::contract::__approve as approve;
pub use crate::contract::__balance as balance;
pub use crate::contract::__is_frozen as is_frozen;
pub use crate::contract::__xfer as xfer;
pub use crate::contract::__xfer_from as xfer_from;
pub use crate::contract::__burn::call_external as burn;
pub use crate::contract::__freeze as freeze;
pub use crate::contract::__mint::call_external as mint;
pub use crate::contract::__set_admin as set_admin;
pub use crate::contract::__unfreeze as unfreeze;
pub use crate::contract::__decimals as decimals;
pub use crate::contract::__name as name;
pub use crate::contract::__symbol as symbol;
