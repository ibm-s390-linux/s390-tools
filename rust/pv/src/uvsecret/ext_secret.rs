// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

use crate::request::Secret;

/// Extension Secret for [`crate::request::uvsecret::AddSecretRequest`]
#[derive(Debug, Clone)]
pub enum ExtSecret {
    /// A bytepattern that must be equal for each request targeting the same SE-guest instance
    Simple(Secret<[u8; 32]>), // contains the secret
    /// A secret that is derived from the Customer communication key from the SE-header
    Derived(Secret<[u8; 32]>), // contains the cck
}
