// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp.

use openssl::pkey::{PKeyRef, Private};

use super::keyslot::Keyslot;
use crate::Result;

/// Encrypt a _secret_ using self and a given private key.
pub trait Encrypt {
    /// Encrypts `secret` using `self` and `priv_key` the encryption.
    ///
    /// # Returns
    /// the encrypted data.
    ///
    /// # Errors
    ///
    /// This function will return an error if OpenSSL could not encrypt the secret.
    fn encrypt(&self, secret: &[u8], priv_key: &PKeyRef<Private>) -> Result<Vec<u8>> {
        let mut res = Vec::with_capacity(80);
        self.encrypt_to(secret, priv_key, &mut res)?;
        Ok(res)
    }

    /// Encrypts `secret` using `self` and `priv_key` the encryption.
    /// Appends the encrypted data to `to`
    ///
    /// # Returns
    /// The encrypted data.
    ///
    /// # Errors
    ///
    /// This function will return an error if OpenSSL could not encrypt the secret.
    fn encrypt_to(
        &self,
        secret: &[u8],
        priv_key: &PKeyRef<Private>,
        to: &mut Vec<u8>,
    ) -> Result<()>;
}

/// Types of Authenticated Data
#[allow(missing_debug_implementations)]
pub enum Aad<'a> {
    /// Authenticated Keyslot
    Ks(&'a Keyslot),
    /// Unchanged authenticated data
    Plain(&'a [u8]),
    /// Authenticated  data that has to be encrypted in beforehand
    Encr(&'a dyn Encrypt),
}
