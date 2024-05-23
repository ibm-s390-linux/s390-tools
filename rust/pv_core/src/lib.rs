// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023, 2024
#![deny(
    missing_docs,
    missing_debug_implementations,
    trivial_numeric_casts,
    unstable_features,
    unused_import_braces,
    unused_qualifications
)]
#![doc = include_str!("../README.md")]
mod error;
mod macros;
mod utils;
mod uvattest;
mod uvdevice;
mod uvsecret;

pub use error::{Error, FileAccessErrorType, FileIoErrorType, Result};

/// Functionalities for reading attestation requests
pub mod attest {
    pub use crate::uvattest::{AttestationMagic, AttestationMeasAlg};
}

/// Miscellaneous functions and definitions
pub mod misc {
    pub use crate::utils::pv_guest_bit_set;
    pub use crate::utils::{create_file, open_file, read_exact_file, read_file, write_file};
    pub use crate::utils::{parse_hex, to_u16, to_u32, try_parse_u128, try_parse_u64};
    pub use crate::utils::{read, write};
    pub use crate::utils::{Flags, Lsb0Flags64, Msb0Flags64};
}

/// Definitions and functions for interacting with the Ultravisor
///
/// For detailed Information on how to send Ultravisor Commands see [`crate::uv::UvDevice`] and
/// [`crate::uv::UvCmd`]
pub mod uv {
    pub use crate::uvdevice::attest::AttestationCmd;
    pub use crate::uvdevice::secret::{AddCmd, ListCmd, LockCmd};
    pub use crate::uvdevice::secret_list::{ListableSecretType, SecretEntry, SecretId, SecretList};
    pub use crate::uvdevice::{ConfigUid, UvCmd, UvDevice, UvDeviceInfo, UvFlags, UvcSuccess};
}

/// Functionalities to verify UV requests
pub mod request {
    /// Version number of the request in system endianness
    pub type RequestVersion = u32;
    /// Request magic value
    ///
    /// The first 8 byte of a request providing an identifier of the request type
    /// for programs
    pub type RequestMagic = [u8; 8];
    /// A `MagicValue` is a byte pattern, that indicates if a byte slice contains the specified
    /// (binary) data.
    pub trait MagicValue<const N: usize> {
        /// Magic value as byte array
        const MAGIC: [u8; N];
        /// Test whether the given slice starts with the magic value.
        fn starts_with_magic(v: &[u8]) -> bool {
            if v.len() < Self::MAGIC.len() {
                return false;
            }
            v[..Self::MAGIC.len()] == Self::MAGIC
        }
    }
}

/// Functionalities for reading add-secret requests
pub mod secret {
    pub use crate::uvsecret::AddSecretMagic;
    pub use crate::uvsecret::UserDataType;
}

// Internal definitions/ imports
const PAGESIZE: usize = 0x1000;
