// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

#![cfg(feature = "uvsecret")]
//! Provides functionality to manage the UV secret store.
//!
//! Provides functionality to build `Add Secret` requests.
//! Also provides interfaces, to dispatch `Add Secret`, `Lock Secret Store`,
//! and `List Secrets` requests,
#[cfg(feature = "request")]
pub mod asrcb;
#[cfg(feature = "request")]
pub mod ext_secret;
#[cfg(feature = "request")]
pub mod guest_secret;
pub mod secret_list;
pub mod uvc;

use crate::request::MagicValue;
use crate::requires_feat;

#[allow(unused_imports)] //used for more convenient docstring
use asrcb::AddSecretRequest;
/// Types of (non architectured) user data for [`AddSecretRequest`]
///
#[doc = requires_feat!(uvsecret)]
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, zerocopy::AsBytes)]
pub enum UserDataType {
    /// Marker that the request does not contain any user data
    Null = 0x0000,
}

/// The magic value used to identify an [`AddSecretRequest`]
///
/// The magic value is ASCII:
/// ```rust
/// # use pv::request::uvsecret::AddSecretMagic;
/// # use pv::request::MagicValue;
/// # fn main() {
/// # let magic =
/// # b"asrcbM"
/// # ;
/// # assert!(AddSecretMagic::starts_with_magic(magic));
/// # }
///```
///
#[doc = requires_feat!(uvsecret)]
#[repr(C)]
#[derive(Debug, Clone, Copy, zerocopy::AsBytes)]
pub struct AddSecretMagic {
    magic: [u8; 6], // [0x61, 0x73, 0x72, 0x63, 0x62, 0x4D]
    tp: UserDataType,
}

impl MagicValue<6> for AddSecretMagic {
    // "asrcbM"
    const MAGIC: [u8; 6] = [0x61, 0x73, 0x72, 0x63, 0x62, 0x4D];
}

impl From<UserDataType> for AddSecretMagic {
    fn from(tp: UserDataType) -> Self {
        Self {
            magic: Self::MAGIC,
            tp,
        }
    }
}

const SECRET_ID_SIZE: usize = 32;
fn ser_gsid<S>(id: &[u8; SECRET_ID_SIZE], ser: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut s = String::with_capacity(32 * 2 + 2);
    s.push_str("0x");
    let s = id.iter().fold(s, |acc, e| acc + &format!("{e:02x}"));
    ser.serialize_str(&s)
}
