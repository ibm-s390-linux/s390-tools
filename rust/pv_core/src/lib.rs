// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023, 2024
#![doc = include_str!("../README.md")]
mod apdevice;
mod confidential;
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
    pub use crate::utils::{create_file, open_file};
    pub use crate::utils::{decode_hex, encode_hex, parse_hex};
    pub use crate::utils::{read, write};
    pub use crate::utils::{read_exact_file, read_file, read_file_string, write_file};
    pub use crate::utils::{to_u16, to_u32, try_parse_u128, try_parse_u64};
    pub use crate::utils::{Flags, Lsb0Flags64, Msb0Flags64};
}

/// Definitions and functions for interacting with the Ultravisor
///
/// For detailed Information on how to send Ultravisor Commands see [`crate::uv::UvDevice`] and
/// [`crate::uv::UvCmd`]
pub mod uv {
    pub use crate::uvdevice::attest::AttestationCmd;
    pub use crate::uvdevice::retr_secret::RetrievableSecret;
    pub use crate::uvdevice::retr_secret::{AesSizes, AesXtsSizes, EcCurves, HmacShaSizes};
    pub use crate::uvdevice::secret::{AddCmd, ListCmd, LockCmd, RetrieveCmd};
    pub use crate::uvdevice::secret_list::{ListableSecretType, SecretEntry, SecretId, SecretList};
    pub use crate::uvdevice::{ConfigUid, UvCmd, UvDevice, UvDeviceInfo, UvFlags, UvcSuccess};
}

/// Functionalities to verify UV requests
pub mod request {
    pub use crate::confidential::{Confidential, Zeroize};
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

/// Functionalities for the AP bus
pub mod ap {
    pub use crate::apdevice::Apqn;
    pub use crate::apdevice::RE_QUEUE_DIR;
    pub use crate::apdevice::{get_apqn_bind_state, set_apqn_bind_state};
    /// AP modes
    pub mod apqn_mode {
        pub use crate::apdevice::ApqnMode::{self, *};
    }
    /// AP info for each state
    pub mod apqn_info {
        pub use crate::apdevice::ApqnInfo::{self, *};
        pub use crate::apdevice::{ApqnInfoAccel, ApqnInfoCca, ApqnInfoEp11};
    }
    /// AP bind states
    pub mod bind_state {
        pub use crate::apdevice::BindState::{self, *};
    }
    /// AP association states
    pub mod assoc_state {
        pub use crate::apdevice::AssocState::{self, *};
    }
}

// Internal definitions/ imports
const PAGESIZE: usize = 0x1000;
