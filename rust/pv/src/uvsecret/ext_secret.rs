// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

use crate::request::Confidential;

/// Extension Secret for [`crate::secret::AddSecretRequest`]
#[derive(Debug, Clone)]
pub enum ExtSecret {
    /// A bytepattern that must be equal for each request targeting the same SE-guest instance
    Simple(Confidential<[u8; 32]>), // contains the secret
    /// A secret that is derived from the Customer communication key from the SE-header
    Derived(Confidential<[u8; 32]>), // contains the cck
}
