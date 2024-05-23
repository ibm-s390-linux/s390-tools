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
//! # Manage guest secret store
//!
//! This crate provides functionalities for creating add-secret requests. Also provides support for
//! sending those requests, list all stored secrets, and lock the secret store.
//!
//! ## Create
//! [`secret::AddSecretRequest`]
//!
//! ## Add
//! [`uv::UvDevice`] and [`uv::AddCmd`]
//!
//! ## List
//! [`uv::UvDevice`] and [`uv::ListCmd`]
//!
//! ## Lock
//! [`uv::UvDevice`] and [`uv::LockCmd`]
//!
//! # Attestation
//!
//! This crate provides functionalities for creating, performing, and verifying Attestation
//! measurements for _IBM Secure Execution for Linux_. See:
//!
//! ## Create
//! [`attest::AttestationRequest`]
//!
//! ## Perform
//! [`uv::UvDevice`] and [`uv::AttestationCmd`]
//!
//! # Verify
//! [`attest::AttestationItems`], [`attest::AttestationMeasurement`]
mod brcb;
mod confidential;
mod crypto;
mod error;
mod openssl_extensions;
mod req;
mod utils;
mod uvattest;
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

/// Functionalities for creating attestation requests
pub mod attest {
    pub use crate::uvattest::{
        additional::AdditionalData,
        arcb::{AttestationAuthenticated, AttestationRequest},
        arcb::{AttestationFlags, AttestationVersion},
        attest::{AttestationItems, AttestationMeasurement},
    };
    pub use pv_core::attest::*;
}

/// Miscellaneous functions and definitions
pub mod misc {
    pub use crate::utils::read_certs;
    pub use pv_core::misc::*;
}

pub use crate::error::HkdVerifyErrorType;
pub use error::{Error, Result};
pub use pv_core::Error as PvCoreError;
pub use pv_core::{FileAccessErrorType, FileIoErrorType};

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
