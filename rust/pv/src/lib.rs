// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023, 2024

#![deny(missing_docs)]
//! pv - library for pv-tools
//!
//! This library is intened to be used by tools and libraries that
//! are used for creating and managing IBM Secure Execution guests.
//! `pv` provides abstraction layers for encryption, secure memory management,
//!  and accessing the uvdevice.
//!
//! If you do not need any OpenSSL features use `pv_core`.
//! This crate reexports all symbols from `pv_core`
mod brcb;
mod confidential;
mod crypto;
mod error;
mod req;
mod utils;
mod uvsecret;
mod verify;

/// utility functions for writing TESTS!!!
// hide any test helpers on docs!
#[doc(hidden)]
#[allow(dead_code)]
pub mod test_utils;

pub use pv_core::assert_size;
pub use pv_core::static_assert;

const PAGESIZE: usize = 0x1000;

/// Definitions and functions for interacting with the Ultravisor
pub mod uv {
    pub use pv_core::uv::*;
}

/// Miscellaneous functions and definitions
pub mod misc {
    pub use crate::utils::read_certs;
    pub use pv_core::misc::*;
}

pub use crate::error::HkdVerifyErrorType;
pub use error::{Error, Result};

/// Functionalities to build UV requests
pub mod request {
    pub use crate::brcb::BootHdrTags;
    pub use crate::confidential::{Confidential, Zeroize};
    pub use crate::crypto::{SymKey, SymKeyType};
    pub use crate::req::{Keyslot, ReqEncrCtx, Request};
    pub use crate::verify::{CertVerifier, HkdVerifier, NoVerifyHkd};

    /// Reexports some useful OpenSSL symbols
    pub mod openssl {
        pub use openssl::error::ErrorStack;
        pub use openssl::pkey;
        pub use openssl::x509;
    }

    pub use pv_core::request::*;
}

/// Functionalities for creating add-secret requests
pub mod secret {
    pub use crate::uvsecret::{
        asrcb::{AddSecretFlags, AddSecretRequest, AddSecretVersion},
        ext_secret::ExtSecret,
        guest_secret::GuestSecret,
        user_data::verify_asrcb_and_get_user_data,
    };
    pub use pv_core::secret::*;
}
