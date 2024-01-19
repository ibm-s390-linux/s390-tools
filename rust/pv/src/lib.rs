// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

#![allow(macro_expanded_macro_exports_accessed_by_absolute_paths)]
#![deny(missing_docs)]
//! pv - library for pv-tools
//!
//! This library is intened to be used by tools and libraries that
//! are used for creating and managing IBM Secure Execution guests.
//! `pv` provides abstraction layers for encryption, secure memory management,
//! logging, and accessing the uvdevice.
//!
//! ## Feature Flags
//! The following feature flags are available:
//! - `request`
//!     - optional
//!     - Enables generation of UV requests
//! - `uvsecret`
//!     - optional
//!     - Enables support for the UV Secret API.
mod error;
mod log;
mod utils;
mod uvdevice;

/// Internal macro to conveninetly document required features on items
// #[macro_export]
#[doc(hidden)]
macro_rules! requires_feat {
    (request) => {
        " Requires the feature `request`"
    };
    (uvsecret) => {
        " Requires the feature `uvsecret`"
    };
    (reqsecret) => {
        "Requires the features `request` & `uvsecret`"
    };
}
#[allow(unused_imports)]
use requires_feat;

//only some features need this
#[allow(dead_code)]
const PAGESIZE: usize = 0x1000;

cfg_if::cfg_if! {
    if #[cfg(feature = "request")] {
        mod brcb;
        mod cli;
        mod crypto;
        mod req;
        mod secret;
        mod uvsecret;
        mod verify;

        /// utility functions for writing TESTS!!!
        #[allow(dead_code)]
        //hide any test helpers on docs!
        #[doc(hidden)]
        pub mod test_utils;

   }
}
/// Definitions and functions for interacting with the Ultravisor
pub mod uv {
    pub use crate::uvdevice::{
        uv_ioctl, ConfigUid, UvCmd, UvDevice, UvDeviceInfo, UvFlags, UvcSuccess,
    };
    #[cfg(feature = "uvsecret")]
    pub use crate::uvsecret::{
        secret_list::{ListableSecretType, SecretEntry, SecretList},
        uvc::{AddCmd, ListCmd, LockCmd},
    };
}

/// Miscellaneous functions and definitions
pub mod misc {

    #[cfg(feature = "request")]
    pub use crate::cli::{
        get_reader_from_cli_file_arg, get_writer_from_cli_file_arg, CertificateOptions, STDIN,
        STDOUT,
    };
    pub use crate::log::PvLogger;
    pub use crate::utils::{
        create_file, memeq, open_file, parse_hex, pv_guest_bit_set, read, read_exact_file,
        read_file, to_u16, to_u32, try_parse_u128, try_parse_u64, write, write_file, Flags,
        Lsb0Flags64, Msb0Flags64,
    };
    #[cfg(feature = "request")]
    pub use crate::utils::{read_certs, read_crls};
}

#[cfg(feature = "request")]
pub use crate::error::HkdVerifyErrorType;
pub use error::{Error, FileAccessErrorType, FileIoErrorType, Result};

/// Functionalities to build UV requests
#[doc = requires_feat!(request)]
pub mod request {

    cfg_if::cfg_if! {
        if #[cfg(feature = "request")] {
            pub use crate::brcb::{BootHdrTags, BootHdrMagic};
            pub use crate::crypto::{
                derive_key, encrypt_aes, encrypt_aes_gcm, gen_ec_key, hash, hkdf_rfc_5869,
                random_array, Aes256Key, SymKey, SymKeyType,
            };
            pub use crate::req::{Aad, Encrypt, Keyslot, ReqEncrCtx, Request};
            pub use crate::secret::{Secret, Zeroize};
            pub use crate::verify::HkdVerifier;

            /// Reexports some useful OpenSSL symbols
            ///
            #[doc = requires_feat!(request)]
            pub mod openssl {
                pub use openssl::error::ErrorStack;
                pub use openssl::hash::MessageDigest;
                pub use openssl::md::Md;
                pub use openssl::pkey;
            }

        }
    }

    cfg_if::cfg_if! {
        if #[cfg(feature = "uvsecret")] {
            /// Functionalities for creating add-secret requests
            pub mod uvsecret {
                #[cfg(feature = "request")]
                pub use crate::uvsecret::{
                        asrcb::{AddSecretFlags, AddSecretRequest,  AddSecretVersion,},
                        ext_secret::ExtSecret,
                        guest_secret::GuestSecret,
                };
                pub use crate::uvsecret::AddSecretMagic;
                pub use crate::uvsecret::UserDataType;
            }
        }
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
/// Produces `pv-crate <version>`
pub const fn crate_info() -> &'static str {
    concat!(env!("CARGO_PKG_NAME"), "-crate ", env!("CARGO_PKG_VERSION"))
}
