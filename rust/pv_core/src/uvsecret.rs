// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

use crate::{
    misc::to_u16,
    request::MagicValue,
    uv::{ListCmd, UvCmd},
    Error, Result,
};
use std::{
    fmt::Display,
    io::{Cursor, Read, Seek, Write},
};
use zerocopy::{AsBytes, FromBytes, U16, U32};

/// The magic value used to identify an add-secret request`]
///
/// The magic value is ASCII:
/// ```rust
/// # use pv_core::request::uvsecret::AddSecretMagic;
/// # use pv_core::request::MagicValue;
/// # fn main() {
/// # let magic =
/// b"asrcbM"
/// # ;
/// # assert!(AddSecretMagic::starts_with_magic(magic));
/// # }
///```
///
#[repr(C)]
#[derive(Debug, Clone, Copy, AsBytes)]
pub struct AddSecretMagic {
    magic: [u8; 6], // [0x61, 0x73, 0x72, 0x63, 0x62, 0x4D]
    tp: UserDataType,
}

impl MagicValue<6> for AddSecretMagic {
    // "asrcbM"
    const MAGIC: [u8; 6] = [0x61, 0x73, 0x72, 0x63, 0x62, 0x4D];
}

/// Types of (non architectured) user data for an add-secret request
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, zerocopy::AsBytes)]
pub enum UserDataType {
    /// Marker that the request does not contain any user data
    Null = 0x0000,
}

impl From<UserDataType> for AddSecretMagic {
    fn from(tp: UserDataType) -> Self {
        Self {
            magic: Self::MAGIC,
            tp,
        }
    }
}
