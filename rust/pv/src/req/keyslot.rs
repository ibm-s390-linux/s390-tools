// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp.

use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, PKeyRef, Private, Public};

use super::ec_coord::EcPubKeyCoord;
use super::encrypt::Encrypt;
use crate::crypto::{derive_aes256_gcm_key, encrypt_aead, hash};
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
pub struct Keyslot(PKey<Public>);

impl Keyslot {
    /// Size of a host-key hash
    pub const PHKH_SIZE: u32 = 0x20;

    /// Creates a new Keyslot from the provided public key
    pub fn new(hostkey: PKey<Public>) -> Self {
        Self(hostkey)
    }
}

impl Encrypt for Keyslot {
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
        let phk: EcPubKeyCoord = self.0.as_ref().try_into()?;

        to.reserve(80);
        to.extend_from_slice(&hash(MessageDigest::sha256(), phk.as_ref())?);
        to.append(&mut wrpk_and_kst);
        Ok(())
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

        let keyslot = Keyslot::new(host_key);
        let encr_ks = keyslot.encrypt(&[0x17u8; 32], &cust_key).unwrap();

        assert_eq!(exp_keyslot, encr_ks);

        let encr_ks = keyslot.encrypt(&[0x16u8; 32], &cust_key).unwrap();
        assert_ne!(exp_keyslot, encr_ks);
    }
}
