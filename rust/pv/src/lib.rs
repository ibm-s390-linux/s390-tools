// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

#![deny(missing_docs)]
//! pv - library for pv-tools
//!
//! This library is intened to be used by tools and libraries that
//! are used for creating and managing IBM Secure Execution guests.
//! `pv` provides abstraction layers for encryption, secure memory management,
//! logging, and accessing the uvdevice.
//!
//! If you do not need any OpenSSL features use `pv_core`.
//! This crate reexports all symbols from `pv_core`
mod brcb;
mod cli;
mod crypto;
mod error;
mod req;
mod secret;
mod utils;
mod uvsecret;
mod verify;

/// utility functions for writing TESTS!!!
//hide any test helpers on docs!
#[doc(hidden)]
#[allow(dead_code)]
pub mod test_utils;

pub use ::utils::assert_size;
pub use ::utils::static_assert;

const PAGESIZE: usize = 0x1000;

/// Definitions and functions for interacting with the Ultravisor
pub mod uv {
    pub use pv_core::uv::{
        uv_ioctl, ConfigUid, UvCmd, UvDevice, UvDeviceInfo, UvFlags, UvcSuccess,
    };
    pub use pv_core::uv::{AddCmd, ListCmd, LockCmd};
    pub use pv_core::uv::{ListableSecretType, SecretEntry, SecretList};
}

/// Miscellaneous functions and definitions
pub mod misc {
    pub use crate::cli::{
        get_reader_from_cli_file_arg, get_writer_from_cli_file_arg, CertificateOptions, STDIN,
        STDOUT,
    };
    pub use crate::utils::{read_certs, read_crls};
    pub use pv_core::misc::*;
    pub use pv_core::PvLogger;
}

pub use crate::error::HkdVerifyErrorType;
pub use error::{Error, Result};

/// Functionalities to build UV requests
pub mod request {
    pub use crate::brcb::{BootHdrMagic, BootHdrTags};
    pub use crate::crypto::derive_key;
    pub use crate::crypto::random_array;
    pub use crate::crypto::{encrypt_aes, encrypt_aes_gcm, gen_ec_key};
    pub use crate::crypto::{hash, hkdf_rfc_5869};
    pub use crate::crypto::{sign_msg, verify_signature};
    pub use crate::crypto::{Aes256Key, SymKey, SymKeyType};
    pub use crate::req::{Aad, Encrypt, Keyslot, ReqEncrCtx, Request};
    pub use crate::secret::{Secret, Zeroize};
    pub use crate::verify::{CertVerifier, HkdVerifier, NoVerifyHkd};

    /// Reexports some useful OpenSSL symbols
    pub mod openssl {
        pub use openssl::error::ErrorStack;
        pub use openssl::hash::MessageDigest;
        pub use openssl::md::Md;
        pub use openssl::pkey;
    }

    /// Functionalities for creating add-secret requests
    pub mod uvsecret {
        pub use crate::uvsecret::{
            asrcb::{AddSecretFlags, AddSecretRequest, AddSecretVersion},
            ext_secret::ExtSecret,
            guest_secret::GuestSecret,
        };
        pub use pv_core::request::uvsecret::AddSecretMagic;
        pub use pv_core::request::uvsecret::UserDataType;
    }
    pub use pv_core::request::RequestMagic;
}

/// Provides cargo version Info about this crate.
///
/// Produces `pv-crate <version>`
pub const fn crate_info() -> &'static str {
    concat!(env!("CARGO_PKG_NAME"), "-crate ", env!("CARGO_PKG_VERSION"))
}
