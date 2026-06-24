// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp.

//! Host key types for UV requests

use openssl::pkey::{PKey, Public};

/// Versioned host keys container
#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum HostKey {
    /// ECDH public key
    V1(PKey<Public>),
}

impl HostKey {
    /// Return the ECDH public key
    pub fn ec_key(&self) -> &PKey<Public> {
        match self {
            HostKey::V1(ec_key) => ec_key,
        }
    }
}

impl AsRef<HostKey> for HostKey {
    fn as_ref(&self) -> &HostKey {
        self
    }
}
