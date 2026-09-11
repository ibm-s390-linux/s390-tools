// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp.

//! IBM Z Host key-slot implementations.

use openssl::hash::{DigestBytes, MessageDigest};
use openssl::pkey::{PKey, PKeyRef, Private, Public};

use crate::crypto::{derive_aes256_gcm_key, derive_aes256_gcm_key_hybrid, encrypt_aead, hash};
use crate::req::{EcPubKeyCoord, Encrypt, HostKey, HybridPKey};
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

/// IBM Z hybrid (V2) Host key-slot
///
/// Layout in binary format:
/// ```none
/// _______________________________________________________________
/// |   Public Host Key Hash (64)                                 |
/// |   Wrapped(=Encrypted) Request Protection Key(32)            |
/// |   Key Slot Tag (16)                                         |
/// |   ML-KEM Ciphertext (1568)                                  |
/// |_____________________________________________________________|
/// ```
#[derive(Debug, Clone)]
pub struct KeyslotV2 {
    ec_hostkey: PKey<Public>,
    mlkem_hostkey: PKey<Public>,
}

impl KeyslotV2 {
    /// Size of a hybrid host-key hash
    pub const PHKH_SIZE: u32 = 0x40;
    /// Size of a complete V2 keyslot in bytes
    pub const SIZE: usize = 1680;

    /// Creates a new HybridKeyslot from the provided hybrid public key
    pub fn new(hostkey: HybridPKey) -> Self {
        let HybridPKey { ec_key, mlkem_key } = hostkey;
        Self {
            ec_hostkey: ec_key,
            mlkem_hostkey: mlkem_key,
        }
    }

    /// calculates the sha512 of this hybrid key
    pub fn sha512(&self) -> Result<DigestBytes> {
        let mut phk_buf = Vec::<u8>::with_capacity(160 + 1568);
        let ec_phk: EcPubKeyCoord = self.ec_hostkey.as_ref().try_into()?;
        phk_buf.extend_from_slice(ec_phk.as_ref());
        phk_buf.extend_from_slice(&self.mlkem_hostkey.raw_public_key()?);
        assert_eq!(phk_buf.len(), 160 + 1568);

        let hash = hash(MessageDigest::sha512(), &phk_buf)?;
        assert_eq!(hash.len(), 64);
        Ok(hash)
    }

    /// Encrypts `secret` using `self` and `priv_key` the encryption.
    ///
    /// # Returns
    /// the encrypted data.
    ///
    /// # Errors
    ///
    /// This function will return an error if OpenSSL could not encrypt the secret.
    pub fn encrypt(&self, secret: &[u8], priv_key: &PKeyRef<Private>) -> Result<Vec<u8>> {
        let mut res = Vec::with_capacity(1680);
        self.encrypt_to(secret, priv_key, &mut res)?;
        Ok(res)
    }

    /// Encrypts the given request protection key `prot_key`.
    ///
    /// The AES256 encryption key is derived from `self` as public key, and `priv_key` as private
    /// key.
    ///
    /// # Returns
    /// The encrypted HybridKeyslot.
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
        let (derived_key, ciphertext) =
            derive_aes256_gcm_key_hybrid(priv_key, &self.ec_hostkey, &self.mlkem_hostkey)?;
        let mut wrpk_and_kst =
            encrypt_aead(&derived_key.into(), &[0; 12], &[], prot_key)?.into_buf();
        assert_eq!(wrpk_and_kst.len(), 48);

        to.reserve(1680);
        let hash = self.sha512()?;
        assert_eq!(hash.len(), 64);
        to.extend_from_slice(&hash);
        to.append(&mut wrpk_and_kst);
        assert_eq!(ciphertext.len(), 1568);
        to.extend_from_slice(&ciphertext);
        Ok(())
    }
}

/// Versioned keyslot container
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum Keyslot {
    /// V1 key-slots with ECDH keys
    V1(KeyslotV1),
    /// V2 key-slots with hybrid ECDH/ML-KEM keys
    V2(KeyslotV2),
}

impl Keyslot {
    /// Return a keyslot with the same key-type as the given host-key
    pub fn new(hostkey: HostKey) -> Self {
        match hostkey {
            HostKey::V1(key) => Keyslot::V1(KeyslotV1::new(key)),
            HostKey::V2(key) => Keyslot::V2(KeyslotV2::new(key)),
        }
    }

    /// Return the public host key hash size for the given version of the key-slot in bytes
    #[must_use]
    pub fn phkh_size(&self) -> u32 {
        match self {
            Keyslot::V1(_) => KeyslotV1::PHKH_SIZE,
            Keyslot::V2(_) => KeyslotV2::PHKH_SIZE,
        }
    }

    /// Return the size of the key-slot in bytes
    #[must_use]
    pub fn size(&self) -> usize {
        match self {
            Keyslot::V1(_) => KeyslotV1::SIZE,
            Keyslot::V2(_) => KeyslotV2::SIZE,
        }
    }

    /// Return whether the key-slot uses hybrid keys
    #[must_use]
    pub fn is_hybrid(&self) -> bool {
        match self {
            Keyslot::V1(_) => false,
            Keyslot::V2(_) => true,
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
            Keyslot::V2(ks) => ks.encrypt_to(secret, priv_key, to),
        }
    }
}

impl From<PKey<Public>> for Keyslot {
    fn from(key: PKey<Public>) -> Self {
        Keyslot::V1(KeyslotV1::new(key))
    }
}

impl From<HybridPKey> for Keyslot {
    fn from(key: HybridPKey) -> Self {
        Keyslot::V2(KeyslotV2::new(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::get_test_asset;
    use crate::test_utils::{DeterministicTestRandGuard, *};

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

    #[test]
    fn keyslot_v2() {
        // Install deterministic RNG for reproducible encryption.
        // 4096 bytes is enough to cover both the pairwise consistency checks in
        // get_test_keys_hybrid() (ossl_ec_key_pairwise_check consumes random bytes for
        // ladder-blinding) and the subsequent ML-KEM encapsulation in encrypt().
        let _guard = DeterministicTestRandGuard::install(&[0x42; 4096], &[0x17; 16]).unwrap();

        let (cust_key, host_key1, host_key2) = get_test_keys_hybrid();
        let host_key = HostKey::V2(HybridPKey::new(host_key1, host_key2).unwrap());
        let exp_keyslot = vec![
            255, 94, 191, 53, 220, 196, 47, 37, 93, 227, 234, 101, 1, 174, 171, 68, 42, 136, 92,
            238, 72, 6, 17, 77, 231, 225, 174, 22, 222, 188, 212, 15, 248, 145, 72, 126, 139, 17,
            233, 225, 156, 46, 233, 151, 54, 2, 175, 88, 215, 254, 243, 222, 37, 81, 50, 110, 18,
            76, 252, 12, 210, 146, 66, 23, 123, 246, 141, 14, 70, 157, 73, 124, 205, 112, 192, 82,
            160, 243, 2, 154, 134, 145, 176, 147, 30, 217, 221, 93, 170, 239, 165, 37, 30, 192, 47,
            94, 129, 165, 12, 137, 239, 12, 180, 199, 240, 160, 180, 205, 117, 84, 16, 148, 51, 48,
            243, 216, 50, 132, 187, 115, 137, 3, 109, 145, 172, 159, 224, 25, 63, 96, 241, 105, 89,
            35, 42, 180, 248, 35, 166, 81, 116, 175, 179, 252, 81, 188, 189, 42, 17, 60, 231, 132,
            32, 111, 90, 138, 201, 16, 3, 97, 246, 130, 173, 85, 218, 187, 232, 92, 52, 120, 56,
            142, 137, 101, 31, 21, 194, 186, 198, 38, 240, 58, 150, 93, 86, 18, 186, 5, 12, 41, 37,
            94, 162, 119, 16, 237, 82, 252, 178, 159, 57, 58, 162, 20, 173, 140, 10, 172, 203, 241,
            94, 110, 117, 32, 36, 217, 7, 168, 50, 105, 43, 33, 174, 140, 55, 88, 26, 233, 81, 253,
            98, 121, 190, 70, 146, 84, 186, 6, 51, 181, 2, 59, 216, 45, 78, 4, 82, 90, 21, 180, 99,
            239, 195, 254, 33, 171, 124, 97, 36, 110, 119, 142, 98, 125, 70, 236, 51, 192, 32, 8,
            214, 224, 101, 169, 45, 173, 137, 194, 78, 114, 224, 76, 174, 188, 133, 227, 167, 169,
            47, 241, 190, 15, 145, 217, 87, 254, 15, 150, 52, 138, 192, 230, 52, 129, 36, 8, 40,
            37, 126, 103, 85, 86, 25, 78, 53, 243, 107, 193, 18, 102, 3, 83, 212, 5, 252, 224, 241,
            7, 205, 220, 168, 183, 15, 37, 52, 190, 12, 9, 152, 124, 210, 65, 152, 210, 199, 81,
            95, 240, 141, 196, 236, 8, 249, 221, 116, 130, 42, 52, 208, 218, 180, 27, 249, 59, 245,
            21, 165, 142, 234, 140, 75, 89, 136, 250, 155, 157, 12, 154, 152, 188, 178, 227, 237,
            124, 111, 176, 131, 227, 238, 164, 22, 88, 80, 217, 42, 217, 80, 148, 118, 12, 136, 95,
            53, 69, 209, 131, 74, 91, 193, 253, 229, 146, 11, 58, 125, 19, 8, 229, 60, 177, 244,
            74, 41, 92, 91, 62, 64, 221, 20, 213, 227, 4, 40, 22, 177, 155, 236, 147, 165, 27, 4,
            99, 4, 151, 155, 82, 72, 151, 22, 102, 183, 192, 242, 18, 104, 146, 205, 107, 21, 254,
            88, 23, 69, 246, 57, 217, 249, 124, 246, 54, 163, 244, 38, 74, 215, 144, 50, 45, 142,
            36, 216, 88, 39, 70, 67, 88, 130, 1, 8, 205, 240, 159, 210, 205, 233, 237, 60, 81, 176,
            112, 172, 187, 121, 239, 198, 43, 17, 49, 55, 170, 228, 243, 255, 76, 72, 121, 125,
            157, 250, 93, 251, 55, 25, 4, 129, 67, 195, 30, 37, 6, 76, 10, 240, 178, 255, 151, 138,
            36, 255, 32, 237, 133, 162, 130, 91, 9, 238, 67, 134, 4, 86, 225, 179, 166, 219, 4,
            144, 7, 125, 248, 75, 132, 54, 56, 51, 237, 206, 252, 96, 9, 208, 140, 127, 143, 180,
            32, 179, 254, 18, 233, 187, 122, 159, 172, 77, 204, 9, 179, 242, 153, 18, 138, 82, 13,
            210, 140, 207, 9, 217, 216, 241, 106, 205, 109, 195, 223, 82, 172, 181, 48, 91, 124,
            235, 85, 17, 18, 166, 216, 86, 120, 185, 54, 147, 156, 84, 106, 30, 235, 234, 114, 27,
            23, 121, 210, 251, 136, 117, 53, 177, 28, 153, 144, 17, 70, 190, 206, 27, 135, 42, 227,
            39, 243, 86, 170, 11, 63, 191, 102, 89, 92, 137, 103, 59, 142, 236, 203, 156, 231, 255,
            30, 5, 86, 53, 59, 76, 181, 218, 184, 244, 21, 50, 100, 72, 81, 98, 193, 34, 58, 67,
            150, 15, 17, 162, 216, 119, 213, 203, 50, 27, 158, 61, 105, 134, 151, 200, 68, 103, 74,
            207, 12, 5, 163, 30, 198, 28, 41, 41, 97, 93, 251, 213, 133, 41, 225, 178, 67, 160, 85,
            132, 146, 1, 201, 99, 49, 185, 27, 150, 213, 165, 134, 45, 248, 204, 67, 145, 49, 81,
            35, 246, 25, 215, 209, 159, 106, 212, 14, 149, 193, 163, 90, 24, 83, 230, 178, 216,
            194, 130, 118, 169, 81, 49, 49, 145, 96, 206, 216, 15, 134, 43, 130, 25, 110, 84, 39,
            175, 223, 183, 209, 123, 5, 166, 244, 19, 89, 2, 47, 226, 3, 93, 156, 163, 67, 156,
            237, 17, 59, 69, 99, 94, 32, 180, 64, 64, 115, 75, 44, 241, 150, 43, 169, 17, 36, 125,
            216, 132, 92, 3, 244, 16, 83, 179, 192, 65, 133, 208, 19, 156, 17, 60, 54, 29, 253,
            237, 18, 158, 145, 142, 232, 147, 2, 91, 21, 145, 125, 204, 243, 161, 245, 110, 140,
            219, 206, 70, 235, 211, 167, 138, 104, 132, 248, 157, 65, 153, 216, 47, 125, 205, 237,
            137, 220, 25, 228, 146, 194, 10, 169, 201, 224, 88, 119, 38, 140, 120, 125, 140, 46,
            184, 221, 30, 10, 47, 34, 140, 173, 64, 38, 48, 77, 236, 206, 163, 111, 80, 46, 40,
            232, 63, 247, 222, 25, 20, 246, 143, 9, 107, 172, 180, 84, 188, 234, 102, 87, 181, 173,
            83, 14, 163, 170, 91, 29, 209, 93, 52, 158, 213, 6, 91, 71, 54, 244, 189, 198, 60, 21,
            131, 210, 35, 18, 36, 164, 188, 87, 54, 73, 208, 115, 11, 248, 57, 107, 93, 23, 49,
            129, 221, 61, 12, 172, 31, 199, 129, 196, 5, 184, 78, 226, 210, 83, 232, 153, 64, 17,
            119, 243, 45, 73, 50, 129, 35, 94, 243, 146, 86, 136, 202, 86, 87, 97, 193, 59, 160,
            181, 95, 150, 148, 117, 96, 31, 151, 97, 159, 53, 72, 171, 239, 210, 67, 207, 201, 109,
            160, 230, 235, 176, 35, 235, 98, 128, 166, 195, 144, 200, 156, 7, 72, 242, 15, 95, 99,
            69, 41, 219, 254, 244, 80, 158, 177, 64, 83, 11, 235, 98, 201, 130, 176, 119, 22, 214,
            135, 215, 37, 65, 108, 91, 34, 94, 0, 153, 161, 87, 144, 177, 12, 122, 205, 11, 72,
            233, 213, 63, 37, 12, 255, 235, 188, 194, 189, 65, 169, 185, 207, 131, 182, 243, 233,
            30, 245, 39, 42, 188, 157, 28, 121, 231, 194, 121, 250, 121, 11, 28, 252, 98, 151, 238,
            124, 56, 138, 106, 116, 187, 203, 21, 75, 239, 132, 19, 62, 43, 42, 12, 214, 87, 225,
            217, 169, 134, 183, 193, 241, 175, 140, 36, 147, 248, 86, 6, 58, 212, 72, 112, 0, 56,
            168, 128, 68, 253, 173, 225, 152, 167, 138, 254, 97, 123, 227, 163, 135, 198, 49, 49,
            138, 249, 234, 245, 78, 150, 140, 170, 199, 41, 206, 246, 19, 117, 241, 27, 112, 102,
            4, 94, 237, 30, 0, 68, 252, 163, 205, 10, 63, 146, 147, 37, 153, 197, 52, 162, 50, 250,
            219, 130, 197, 3, 60, 246, 133, 83, 140, 103, 227, 50, 212, 121, 165, 114, 139, 225,
            195, 145, 107, 249, 127, 194, 23, 112, 141, 242, 14, 218, 42, 131, 19, 245, 143, 73,
            79, 194, 135, 224, 171, 249, 169, 129, 160, 153, 75, 66, 26, 12, 254, 180, 212, 229,
            172, 134, 159, 122, 212, 219, 21, 29, 33, 11, 176, 149, 73, 169, 26, 150, 96, 133, 90,
            217, 18, 37, 244, 48, 249, 4, 180, 129, 9, 45, 219, 106, 215, 28, 81, 118, 48, 98, 109,
            167, 72, 107, 187, 78, 127, 251, 184, 170, 74, 57, 188, 91, 196, 229, 251, 70, 163, 68,
            227, 238, 71, 115, 155, 246, 146, 97, 208, 21, 245, 62, 127, 47, 79, 131, 217, 41, 153,
            52, 237, 159, 60, 98, 18, 169, 149, 6, 84, 135, 2, 45, 170, 165, 213, 201, 127, 23,
            209, 2, 158, 235, 240, 195, 255, 76, 54, 189, 113, 50, 105, 230, 191, 217, 29, 46, 181,
            80, 197, 60, 177, 243, 61, 52, 24, 140, 134, 147, 176, 198, 22, 92, 156, 217, 189, 134,
            17, 122, 53, 49, 14, 87, 128, 99, 207, 123, 113, 169, 195, 206, 127, 211, 21, 216, 166,
            18, 137, 110, 148, 70, 26, 54, 52, 113, 189, 45, 89, 254, 218, 247, 193, 71, 19, 153,
            35, 179, 49, 237, 199, 176, 251, 143, 95, 115, 195, 3, 122, 161, 243, 220, 39, 102,
            147, 134, 25, 172, 164, 167, 110, 123, 221, 177, 28, 236, 100, 165, 186, 179, 45, 189,
            183, 76, 171, 127, 209, 108, 220, 83, 207, 136, 98, 54, 76, 37, 188, 57, 157, 204, 109,
            150, 181, 110, 57, 5, 26, 168, 34, 11, 117, 3, 184, 147, 155, 122, 244, 251, 215, 1,
            211, 226, 185, 214, 120, 206, 212, 75, 203, 174, 140, 20, 93, 93, 207, 28, 15, 122, 9,
            83, 98, 107, 51, 202, 151, 220, 42, 95, 17, 141, 141, 201, 149, 253, 55, 169, 170, 237,
            166, 92, 92, 20, 89, 124, 167, 102, 161, 87, 97, 88, 20, 245, 175, 32, 111, 0, 2, 192,
            25, 63, 182, 10, 226, 165, 162, 223, 35, 243, 198, 189, 167, 137, 134, 207, 84, 240, 8,
            95, 137, 31, 159, 58, 211, 161, 94, 150, 54, 188, 145, 253, 206, 156, 130, 121, 192,
            221, 73, 249, 92, 91, 184, 211, 131, 206, 205, 183, 159, 195, 170, 47, 13, 131, 6, 132,
            103, 121, 40, 252, 250, 251, 85, 253, 68, 66, 211, 24, 104, 48, 150, 176, 62, 201, 161,
            93, 204, 120, 196, 159, 208, 199, 96, 228, 239, 29, 239, 128, 156, 14, 131, 25, 27,
            157, 249, 253, 250, 193, 148, 133, 59, 138, 202, 239,
        ];

        let keyslot = Keyslot::new(host_key);
        let encr_keyslot = keyslot.encrypt(&[0x17u8; 32], &cust_key).unwrap();

        assert_eq!(encr_keyslot, exp_keyslot);
    }

    #[test]
    fn test_keyslot_v2_constants() {
        // Test V2 keyslot constants
        assert_eq!(
            KeyslotV2::SIZE,
            1680,
            "V2 keyslot size should be 1680 bytes"
        );
        assert_eq!(
            KeyslotV2::PHKH_SIZE,
            0x40,
            "V2 PHKH size should be 64 bytes (SHA-512)"
        );
    }

    #[test]
    fn test_keyslot_v2_creation() {
        let (_, ec_key, mlkem_key) = get_test_key_and_cert_hybrid();
        let hybrid = HybridPKey::new(
            ec_key.public_key().unwrap(),
            mlkem_key.public_key().unwrap(),
        )
        .unwrap();

        let keyslot = KeyslotV2::new(hybrid);

        // Verify keyslot was created successfully
        assert!(keyslot.ec_hostkey.public_key_to_der().is_ok());
        assert!(keyslot.mlkem_hostkey.public_key_to_der().is_ok());
    }

    #[test]
    fn test_keyslot_enum_v1_variant() {
        let (_, host_key) = get_test_keys();
        let keyslot = Keyslot::V1(KeyslotV1(host_key));

        assert_eq!(keyslot.phkh_size(), KeyslotV1::PHKH_SIZE);
        assert_eq!(keyslot.size(), KeyslotV1::SIZE);
        assert!(matches!(keyslot, Keyslot::V1(_)));
    }

    #[test]
    fn test_keyslot_enum_v2_variant() {
        let (_, ec_key, mlkem_key) = get_test_key_and_cert_hybrid();
        let hybrid = HybridPKey::new(
            ec_key.public_key().unwrap(),
            mlkem_key.public_key().unwrap(),
        )
        .unwrap();
        let keyslot = Keyslot::V2(KeyslotV2::new(hybrid));

        assert_eq!(keyslot.phkh_size(), KeyslotV2::PHKH_SIZE);
        assert_eq!(keyslot.size(), KeyslotV2::SIZE);
        assert!(matches!(keyslot, Keyslot::V2(_)));
    }

    #[test]
    fn test_keyslot_from_hostkey_v1() {
        let (_, ec_key) = get_test_keys();
        let hostkey = HostKey::V1(ec_key);
        let keyslot = Keyslot::new(hostkey);

        assert!(matches!(keyslot, Keyslot::V1(_)));
        assert_eq!(keyslot.size(), KeyslotV1::SIZE);
    }

    #[test]
    fn test_keyslot_from_hostkey_v2() {
        let (_, ec_key, mlkem_key) = get_test_key_and_cert_hybrid();
        let hybrid = HybridPKey::new(
            ec_key.public_key().unwrap(),
            mlkem_key.public_key().unwrap(),
        )
        .unwrap();
        let hostkey = HostKey::V2(hybrid);
        let keyslot = Keyslot::new(hostkey);

        assert!(matches!(keyslot, Keyslot::V2(_)));
        assert_eq!(keyslot.size(), KeyslotV2::SIZE);
    }

    #[test]
    fn test_keyslot_from_hybrid_public_key() {
        let (_, ec_key, mlkem_key) = get_test_key_and_cert_hybrid();
        let hybrid = HybridPKey::new(
            ec_key.public_key().unwrap(),
            mlkem_key.public_key().unwrap(),
        )
        .unwrap();

        let keyslot: Keyslot = hybrid.into();
        assert!(matches!(keyslot, Keyslot::V2(_)));
    }

    #[test]
    fn test_keyslot_sizes() {
        // Document the sizes for V1 and V2
        assert_eq!(KeyslotV1::SIZE, 80, "V1 keyslot size");
        assert_eq!(
            KeyslotV2::SIZE,
            1680,
            "V2 keyslot size (includes ML-KEM ciphertext)"
        );
    }
}
