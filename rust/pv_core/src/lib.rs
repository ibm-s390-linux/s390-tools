// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023
#![deny(missing_docs)]
#![allow(unused)]
//! pv_core - basic library for pv-tools
//!
//! This library is intened to be used by tools and libraries that
//! are used for creating and managing IBM Secure Execution guests.
//! `pv_core` provides abstraction layers for secure memory management,
//! logging, and accessing the uvdevice.
//!
//! It does not provide any cryptographic operations through OpenSSL.
//! For this use `pv` which reexports all symbos from this crate.
mod error;
mod log;
mod macros;
mod utils;
mod uvdevice;
mod uvsecret;

pub use crate::log::PvLogger;
pub use error::{Error, FileAccessErrorType, FileIoErrorType, Result};

/// Miscellaneous functions and definitions
pub mod misc {
    pub use crate::utils::pv_guest_bit_set;
    pub use crate::utils::{create_file, open_file, read_exact_file, read_file, write_file};
    pub use crate::utils::{memeq, parse_hex, to_u16, to_u32, try_parse_u128, try_parse_u64};
    pub use crate::utils::{read, write};
    pub use crate::utils::{Flags, Lsb0Flags64, Msb0Flags64};
}

/// Definitions and functions for interacting with the Ultravisor
pub mod uv {
    pub use crate::uvdevice::secret::{AddCmd, ListCmd, LockCmd};
    pub use crate::uvdevice::secret::{ListableSecretType, SecretEntry, SecretList};
    pub use crate::uvdevice::{
        uv_ioctl, ConfigUid, UvCmd, UvDevice, UvDeviceInfo, UvFlags, UvcSuccess,
    };
}

/// Functionalities to verify UV requests
pub mod request {
    /// Functionalities for reading add-secret requests
    pub mod uvsecret {
        pub use crate::uvsecret::AddSecretMagic;
        pub use crate::uvsecret::UserDataType;
    }

    /// Version number of the request in system-endian
    pub type RequestVersion = u32;
    /// Request magic value
    ///
    /// The first 8 byte of a request providing an identifier of the request type
    /// for programs
    pub type RequestMagic = [u8; 8];
    /// A `MagicValue` is a bytepattern, that indicates if a byte slice contains the specified
    /// (binary) data.
    pub trait MagicValue<const N: usize> {
        /// Magic value as byte array
        const MAGIC: [u8; N];
        /// Test whether the given slice starts with the magic value.
        fn starts_with_magic(v: &[u8]) -> bool {
            if v.len() < Self::MAGIC.len() {
                return false;
            }
            crate::misc::memeq(&v[..Self::MAGIC.len()], &Self::MAGIC)
        }
    }
}

/// Provides cargo version Info about this crate.
///
/// Produces `pv_core-crate <version>`
pub const fn crate_info() -> &'static str {
    concat!(env!("CARGO_PKG_NAME"), "-crate ", env!("CARGO_PKG_VERSION"))
}

// Internal definitions/ imports
const PAGESIZE: usize = 0x1000;
use ::utils::assert_size;
use ::utils::static_assert;

#[doc(hidden)]
/// stuff pv_core and pv share. Not intended for other users
pub mod for_pv {
    pub use crate::uvdevice::secret::ser_gsid;
    pub use crate::uvdevice::secret::SECRET_ID_SIZE;
}
