// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023, 2024

#![doc = include_str!("../README.md")]
//! # Library for Protected Virtualization (PV) related tools
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

pub use pv_core::{assert_size, static_assert};

const PAGESIZE: usize = 0x1000;

/// Definitions and functions for interacting with the Ultravisor
pub mod uv {
    pub use pv_core::uv::*;
}

/// Functionalities for creating attestation requests
pub mod attest {
    pub use pv_core::attest::*;

    pub use crate::uvattest::{
        additional::AdditionalData,
        arcb::{
            AttestationAuthenticated, AttestationFlags, AttestationRequest, AttestationVersion,
        },
        attest::{AttestationItems, AttestationMeasurement},
    };
}

/// Miscellaneous functions and definitions
pub mod misc {
    pub use pv_core::misc::*;

    pub use crate::utils::read_certs;
}

pub use error::{Error, Result};
pub use pv_core::{Error as PvCoreError, FileAccessErrorType, FileIoErrorType};

pub use crate::error::HkdVerifyErrorType;

/// Functionalities to build UV requests
pub mod request {
    pub use crate::{
        brcb::{seek_se_hdr_start, BootHdrTags, SeImgMetaData},
        crypto::{
            decrypt_aead, derive_aes256_gcm_key, encrypt_aead, gen_ec_key, random_array,
            AeadDecryptionResult, AeadEncryptionResult, Aes256GcmKey, Aes256XtsKey, SymKey,
            SymKeyType, SHA_512_HASH_LEN,
        },
        req::{EcPubKeyCoord, Encrypt, Keyslot, ReqEncrCtx, Request},
        verify::{CertVerifier, HkdVerifier, NoVerifyHkd},
    };

    /// Reexports some useful OpenSSL symbols
    pub mod openssl {
        pub use openssl::{error::ErrorStack, hash::DigestBytes, pkey, x509};
    }

    pub use pv_core::request::*;
}

/// Functionalities for creating add-secret requests
pub mod secret {
    pub use pv_core::secret::*;

    pub use crate::uvsecret::{
        asrcb::{AddSecretFlags, AddSecretRequest, AddSecretVersion},
        ext_secret::ExtSecret,
        guest_secret::GuestSecret,
        user_data::verify_asrcb_and_get_user_data,
    };
}
