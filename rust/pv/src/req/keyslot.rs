// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp.

//! IBM Z Host key-slot implementations.

use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, PKeyRef, Private, Public};

use super::ec_coord::EcPubKeyCoord;
use super::encrypt::Encrypt;
use crate::crypto::{derive_aes256_gcm_key, encrypt_aead, hash};
use crate::request::HostKey;
use crate::Result;

/// IBM Z Host key-slot
///
/// Layout in binary format:
/// ```none
/// _______________________________________________________________
/// |   Public Host Key Hash (32)                                 |
/// |   Wrapped(=Encrypted) Request Protection Key(32)            |
/// |   Key Slot Tag (16)                                         |
/// |_____________________________________________________________|
/// ```
#[derive(Debug, Clone)]
pub struct KeyslotV1(PKey<Public>);

impl KeyslotV1 {
    /// Size of a host-key hash
    pub const PHKH_SIZE: u32 = 0x20;
    /// Size of complete V1 keyslot in bytes
    pub const SIZE: usize = 80;

    /// Creates a new Keyslot from the provided public key
    pub fn new(hostkey: PKey<Public>) -> Self {
        Self(hostkey)
    }
}

impl Encrypt for KeyslotV1 {
    /// Encrypts the given request protection key `prot_key`.
    ///
    /// The AES256 encryption key is derived from `self` as public key, and `priv_key` as private
    /// key.
    ///
    /// # Returns
    /// The encrypted Keyslot.
    ///
    /// # Errors
    ///
    /// This function will return an error if OpenSSL could not encrypt the secret.
    fn encrypt_to(
        &self,
        prot_key: &[u8],
        priv_key: &PKeyRef<Private>,
        to: &mut Vec<u8>,
    ) -> Result<()> {
        let derived_key = derive_aes256_gcm_key(priv_key, &self.0)?;
        let mut wrpk_and_kst =
            encrypt_aead(&derived_key.into(), &[0; 12], &[], prot_key)?.into_buf();
        assert_eq!(wrpk_and_kst.len(), 48);
        let phk: EcPubKeyCoord = self.0.as_ref().try_into()?;

        to.reserve(80);
        let hash = hash(MessageDigest::sha256(), phk.as_ref())?;
        assert_eq!(hash.len(), 32);
        to.extend_from_slice(&hash);
        to.append(&mut wrpk_and_kst);
        Ok(())
    }
}

/// Versioned keyslot container
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum Keyslot {
    /// V1 key-slots with ECDH keys
    V1(KeyslotV1),
}

impl Keyslot {
    /// Return a keyslot with the same key-type as the given host-key
    pub fn new(hostkey: HostKey) -> Self {
        match hostkey {
            HostKey::V1(key) => Keyslot::V1(KeyslotV1::new(key)),
        }
    }

    /// Return the public host key hash size for the given version of the key-slot in bytes
    pub fn phkh_size(&self) -> u32 {
        match self {
            Keyslot::V1(_) => KeyslotV1::PHKH_SIZE,
        }
    }

    /// Return the size of the key-slot in bytes
    pub fn size(&self) -> usize {
        match self {
            Keyslot::V1(_) => KeyslotV1::SIZE,
        }
    }

    /// Return whether the key-slot uses hybrid keys
    pub fn is_hybrid(&self) -> bool {
        match self {
            Keyslot::V1(_) => false,
        }
    }
}

impl Encrypt for Keyslot {
    fn encrypt_to(
        &self,
        secret: &[u8],
        priv_key: &PKeyRef<Private>,
        to: &mut Vec<u8>,
    ) -> Result<()> {
        match self {
            Keyslot::V1(ks) => ks.encrypt_to(secret, priv_key, to),
        }
    }
}

impl From<PKey<Public>> for Keyslot {
    fn from(key: PKey<Public>) -> Self {
        Keyslot::V1(KeyslotV1::new(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::get_test_asset;
    use crate::test_utils::*;

    #[test]
    fn keyslot() {
        let (cust_key, host_key) = get_test_keys();
        let exp_keyslot = get_test_asset!("exp/keyslot.bin").to_vec();

        let keyslot = KeyslotV1(host_key);
        let encr_ks = keyslot.encrypt(&[0x17u8; 32], &cust_key).unwrap();

        assert_eq!(exp_keyslot, encr_ks);

        let encr_ks = keyslot.encrypt(&[0x16u8; 32], &cust_key).unwrap();
        assert_ne!(exp_keyslot, encr_ks);
    }
}
