// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

use crate::{request::Secret, requires_feat};

/// Extension Secret for [`crate::request::uvsecret::AddSecretRequest`]
///
#[doc = requires_feat!(reqsecret)]
#[derive(Debug, Clone)]
pub enum ExtSecret {
    /// A bytepattern that must be equal for each request targeting the same SE-guest instance
    Simple(Secret<[u8; 32]>), // contains the secret
    /// A secret that is derived from the Customer communication key from the SE-header
    Derived(Secret<[u8; 32]>), // contains the cck
}
