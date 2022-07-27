#![no_std]

#[cfg(any(test, feature = "testutils"))]
#[macro_use]
extern crate std;

mod admin;
mod allowance;
mod balance;
mod contract;
mod cryptography;
mod metadata;
mod nonce;
pub mod public_types;
mod storage_types;
pub mod testutils;

pub use cryptography::Domain;

pub use crate::contract::__allowance::call_internal as allowance;
pub use crate::contract::__approve::call_internal as approve;
pub use crate::contract::__balance::call_internal as balance;
pub use crate::contract::__burn::call_internal as burn;
pub use crate::contract::__decimals::call_internal as decimals;
pub use crate::contract::__freeze::call_internal as freeze;
pub use crate::contract::__initialize::call_internal as initialize;
pub use crate::contract::__is_frozen::call_internal as is_frozen;
pub use crate::contract::__mint::call_internal as mint;
pub use crate::contract::__name::call_internal as name;
pub use crate::contract::__nonce::call_internal as nonce;
pub use crate::contract::__set_admin::call_internal as set_admin;
pub use crate::contract::__symbol::call_internal as symbol;
pub use crate::contract::__unfreeze::call_internal as unfreeze;
pub use crate::contract::__xfer::call_internal as xfer;
pub use crate::contract::__xfer_from::call_internal as xfer_from;
