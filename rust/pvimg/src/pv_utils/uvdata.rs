// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use enum_dispatch::enum_dispatch;
use pv::request::{
    decrypt_aead, derive_aes256_gcm_key, encrypt_aead,
    openssl::pkey::{PKey, PKeyRef, Private, Public},
    Confidential, SymKey, SymKeyType,
};

use super::se_hdr::{SeHdrBinV1, SeHdrData, SeHdrVersioned};
use crate::pv_utils::{
    error::{Error, Result},
    serializing::deserialize_from_bytes,
};

/// Trait to be used for Authenticated Encryption with Associated Data (AEAD)
/// data structures.
#[enum_dispatch]
pub trait AeadCipherTrait {
    /// Returns the AEAD key type used by the data structure.
    fn aead_key_type(&self) -> SymKeyType;

    /// Returns the AEAD tag size used by the data structure.
    fn aead_tag_size(&self) -> usize;

    /// Returns the initialization vector (IV) used for AEAD
    /// encryption/decryption.
    fn iv(&self) -> &[u8];
}

/// Trait to be used for AEAD cipher data
#[enum_dispatch]
pub trait AeadDataTrait {
    /// Returns the authenticated associated data.
    fn aad(&self) -> Vec<u8>;

    /// Returns the encrypted data.
    fn data(&self) -> Vec<u8>;

    /// Returns the tag data.
    fn tag(&self) -> Vec<u8>;
}

/// Trait to be used for AEAD plaintext data
#[enum_dispatch]
pub trait AeadPlainDataTrait {
    /// Returns the authenticated associated data.
    fn aad(&self) -> Vec<u8>;

    /// Returns the unencrypted data.
    fn data(&self) -> Confidential<Vec<u8>>;

    /// Returns the tag data.
    fn tag(&self) -> Vec<u8>;
}

/// Key exchange related methods
#[enum_dispatch]
pub trait KeyExchangeTrait {
    /// Checks if a public key was used.
    ///
    /// # Errors
    ///
    /// This function will return an error if the public key cannot be converted
    /// into a hash.
    fn contains<K: AsRef<PKeyRef<Public>>>(&self, key: K) -> Result<bool>;

    /// Checks if the hash of a public key was used.
    fn contains_hash<H: AsRef<[u8]>>(&self, hash: H) -> bool;

    /// Returns the public key from the party (e.g. guest owner) that is stored
    /// in the data structed.
    ///
    /// # Errors
    ///
    /// This function will return an error if the public key cannot be
    /// reconstructed.
    fn cust_pub_key(&mut self) -> Result<PKey<Public>>;

    /// Returns the key type of the exchanged key.
    fn key_type(&self) -> SymKeyType;

    /// Derive the key.
    ///
    /// # Errors
    ///
    /// This function will return an error if there is no customer public key is
    /// available or the key derivations fails.
    fn derive_key<K: AsRef<PKeyRef<Private>>>(&mut self, other_priv_key: K) -> Result<SymKey> {
        match self.key_type() {
            SymKeyType::Aes256Gcm => Ok(derive_aes256_gcm_key(
                other_priv_key.as_ref(),
                self.cust_pub_key()?.as_ref(),
            )?
            .into()),
            _ => unreachable!("BUG"),
        }
    }
}

/// Trait to be used for plain UV data.
#[enum_dispatch]
pub trait UvDataPlainTrait:
    AeadPlainDataTrait + AeadCipherTrait + KeyExchangeTrait + Clone
{
    /// Returned type by [`Self::encrypt`].
    type C: UvDataTrait;

    /// Encrypt the plain data.
    ///
    /// # Errors
    ///
    /// This function will return an error if the passed `key` has the wrong
    /// key type or the encryption fails.
    fn encrypt(&self, key: &SymKey) -> Result<Self::C>
    where
        <Self as UvDataPlainTrait>::C: for<'a> deku::DekuContainerRead<'a>,
    {
        if key.key_type() != self.aead_key_type() {
            return Err(Error::UnexpectedKeyType {
                given: self.key_type().to_string(),
                expected: self.aead_key_type().to_string(),
            });
        }
        let aad = self.aad();
        let unecrypted_data = self.data();
        let iv = self.iv();
        let result = encrypt_aead(key, iv, &aad, unecrypted_data.value())?;
        Self::C::try_from_data(&result.into_buf())
    }

    /// Parses and converts the data into an instance of [`Self`] if possible.
    ///
    /// # Errors
    ///
    /// This function will return an error if the data could not parsed or
    /// converted.
    fn try_from_data<'a>(data: &'a [u8]) -> Result<Self>
    where
        Self: deku::DekuContainerRead<'a> + Sized,
    {
        deserialize_from_bytes(data)
    }
}

/// Trait to be used for (cipher) UV data.
#[enum_dispatch]
pub trait UvDataTrait: AeadDataTrait + AeadCipherTrait + KeyExchangeTrait + Clone {
    /// Returned type by [`Self::decrypt`].
    type P: UvDataPlainTrait;

    /// Decrypt the UV data.
    ///
    /// # Errors
    ///
    /// This function will return an error if the passed `key` has the wrong key
    /// type or the decryption fails.
    fn decrypt(&self, key: &SymKey) -> Result<Self::P>
    where
        <Self as UvDataTrait>::P: for<'a> deku::DekuContainerRead<'a>,
    {
        if key.key_type() != self.aead_key_type() {
            return Err(Error::UnexpectedKeyType {
                given: key.key_type().to_string(),
                expected: self.aead_key_type().to_string(),
            });
        }

        let tag_size = self.aead_tag_size();
        let aad = self.aad();
        let unecrypted_data = self.data();
        let iv = self.iv();
        let tag = self.tag();
        assert_eq!(tag.len(), tag_size);
        let result = decrypt_aead(key, iv, &aad, &unecrypted_data, &tag)?;
        Self::P::try_from_data(result.into_buf().value())
    }

    /// Parses and converts the data into an instance of [`Self`] if possible.
    ///
    /// # Errors
    ///
    /// This function will return an error if the data could not parsed or
    /// converted.
    fn try_from_data<'a>(data: &'a [u8]) -> Result<Self>
    where
        Self: deku::DekuContainerRead<'a> + Sized,
    {
        deserialize_from_bytes(data)
    }
}
