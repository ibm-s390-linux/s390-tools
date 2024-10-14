// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023, 2024

use std::{convert::TryInto, fmt::Display, ops::Range};

use enum_dispatch::enum_dispatch;
use openssl::{
    derive::Deriver,
    ec::{EcGroup, EcKey},
    hash::{DigestBytes, MessageDigest},
    md::MdRef,
    nid::Nid,
    pkey::{HasPublic, Id, PKey, PKeyRef, Private, Public},
    pkey_ctx::{HkdfMode, PkeyCtx},
    rand::rand_bytes,
    rsa::Padding,
    sign::{Signer, Verifier},
    symm::{decrypt_aead as openssl_decrypt_aead, encrypt_aead as openssl_encrypt_aead, Cipher},
};
use pv_core::request::Confidential;

use crate::{error::Result, Error};

/// An AES256-GCM key that will purge itself out of the memory when going out of scope
pub type Aes256GcmKey = Confidential<[u8; SymKeyType::AES_256_GCM_KEY_LEN]>;
/// An AES256-XTS key that will purge itself out of the memory when going out of scope
pub type Aes256XtsKey = Confidential<[u8; SymKeyType::AES_256_XTS_KEY_LEN]>;

/// SHA-512 digest length (in bytes)
#[allow(unused)]
pub const SHA_512_HASH_LEN: usize = 64;

#[allow(dead_code)]
pub(crate) const SHA_256_HASH_LEN: u32 = 32;
#[allow(dead_code)]
pub(crate) type Sha256Hash = [u8; SHA_256_HASH_LEN as usize];

/// Types of symmetric keys, to specify during construction.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymKeyType {
    /// AES 256 GCM key (32 bytes)
    Aes256Gcm,
    /// AES 256 XTS key (64 bytes)
    Aes256Xts,
}

impl SymKeyType {
    #[deprecated]
    #[allow(non_upper_case_globals)]
    /// AES 256 GCM key (32 bytes)
    pub const Aes256: Self = Self::Aes256Gcm;
    /// AES256-GCM key length (in bytes)
    pub const AES_256_GCM_KEY_LEN: usize = 32;
    /// AES256-GCM IV length (in bytes)
    pub const AES_256_GCM_IV_LEN: usize = 12;
    /// AES256-GCM tag size (in bytes)
    pub const AES_256_GCM_TAG_LEN: usize = 16;
    /// AES256-XTS key length (in bytes)
    pub const AES_256_XTS_KEY_LEN: usize = 64;
    /// AES256-XTS tweak length (in bytes)
    pub const AES_256_XTS_TWEAK_LEN: usize = 16;

    /// Returns the tag length of the [`SymKeyType`] if it is an AEAD key
    pub const fn tag_len(&self) -> Option<usize> {
        match self {
            SymKeyType::Aes256Gcm => Some(Self::AES_256_GCM_TAG_LEN),
            SymKeyType::Aes256Xts => None,
        }
    }

    /// Returns true if the [`SymKeyType`] is an AEAD key
    pub const fn is_aead(&self) -> bool {
        self.tag_len().is_some()
    }
}

impl Display for SymKeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Aes256Gcm => "AES-256-GCM",
            Self::Aes256Xts => "AES-256-XTS",
        };
        write!(f, "{s}")
    }
}

impl From<SymKeyType> for Nid {
    fn from(value: SymKeyType) -> Self {
        match value {
            SymKeyType::Aes256Gcm => Self::AES_256_GCM,
            SymKeyType::Aes256Xts => Self::AES_256_XTS,
        }
    }
}

/// The `enum_dispatch` macros needs at least one local trait to be implemented.
#[allow(unused)]
#[enum_dispatch(SymKey)]
trait SymKeyTrait {}

/// Types of symmetric keys
#[non_exhaustive]
#[enum_dispatch()]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymKey {
    /// AES 256 GCM key (32 bytes)
    Aes256(Aes256GcmKey),
    /// AES 256 XTS key (64 bytes)
    Aes256Xts(Aes256XtsKey),
}

impl SymKey {
    /// Generates a random symmetric key.
    ///
    /// * `key_tp` - type of the symmetric key
    ///
    /// # Errors
    ///
    /// This function will return an error if the Key cannot be generated.
    pub fn random(key_tp: SymKeyType) -> Result<Self> {
        match key_tp {
            SymKeyType::Aes256Gcm => Ok(Self::Aes256(random_array().map(|v| v.into())?)),
            SymKeyType::Aes256Xts => Ok(Self::Aes256Xts(random_array().map(|v| v.into())?)),
        }
    }

    /// Returns a reference to the value of this [`SymKey`].
    pub fn value(&self) -> &[u8] {
        match self {
            Self::Aes256(key) => key.value(),
            Self::Aes256Xts(key) => key.value(),
        }
    }

    /// Return the key type of this [`SymKey`].
    pub fn key_type(&self) -> SymKeyType {
        match self {
            Self::Aes256(_) => SymKeyType::Aes256Gcm,
            Self::Aes256Xts(_) => SymKeyType::Aes256Xts,
        }
    }
}

/// Performs an hkdf according to RFC 5869.
/// See [`OpenSSL HKDF`]()
///
/// # Errors
///
/// This function will return an OpenSSL error if the key could not be generated.
pub(crate) fn hkdf_rfc_5869<const COUNT: usize>(
    md: &MdRef,
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
) -> Result<[u8; COUNT]> {
    let mut ctx = PkeyCtx::new_id(Id::HKDF)?;
    ctx.derive_init()?;
    ctx.set_hkdf_mode(HkdfMode::EXTRACT_THEN_EXPAND)?;
    ctx.set_hkdf_md(md)?;
    ctx.set_hkdf_salt(salt)?;
    ctx.set_hkdf_key(ikm)?;
    ctx.add_hkdf_info(info)?;

    let mut res = [0; COUNT];
    ctx.derive(Some(&mut res))?;
    Ok(res)
}

/// Derive a symmetric AES 256 GCM key from a private and a public key.
///
/// # Errors
///
/// This function will return an error if something went bad in OpenSSL.
pub fn derive_aes256_gcm_key(k1: &PKeyRef<Private>, k2: &PKeyRef<Public>) -> Result<Aes256GcmKey> {
    let mut der = Deriver::new(k1)?;
    der.set_peer(k2)?;
    let mut key = der.derive_to_vec()?;
    key.extend([0, 0, 0, 1]);
    let secr = Confidential::new(key);

    // Panic: does not panic as SHA256 digest is 32 bytes long
    Ok(Aes256GcmKey::new(
        hash(MessageDigest::sha256(), secr.value())?
            .as_ref()
            .try_into()
            .unwrap(),
    ))
}

/// Generate a random array.
///
/// # Errors
///
/// This function will return an error if the entropy source fails or is not available.
pub fn random_array<const COUNT: usize>() -> Result<[u8; COUNT]> {
    let mut rand = [0; COUNT];
    rand_bytes(&mut rand)?;
    Ok(rand)
}

/// Generate a new random EC key.
///
/// # Errors
///
/// This function will return an error if the key could not be generated by OpenSSL.
pub fn gen_ec_key(nid: Nid) -> Result<PKey<Private>> {
    let group = EcGroup::from_curve_name(nid)?;
    let key: EcKey<Private> = EcKey::generate(&group)?;
    PKey::from_ec_key(key).map_err(Error::Crypto)
}

/// Result type for an AES encryption in GCM mode..
#[derive(PartialEq, Eq, Debug)]
pub struct AeadEncryptionResult {
    /// The result.
    ///
    /// [`Vec<u8>`] with the following content:
    /// 1. `aad`
    /// 2. `encr(conf)`
    /// 3. `aes gcm tag`
    pub(crate) buf: Vec<u8>,
    /// The position of the authenticated data in [`Self::buf`]
    pub(crate) aad_range: Range<usize>,
    /// The position of the encrypted data in [`Self::buf`]
    pub(crate) encr_range: Range<usize>,
    /// The position of the tag in [`Self::buf`]
    pub(crate) tag_range: Range<usize>,
}

/// Result type for an AES decryption in GCM mode..
#[derive(PartialEq, Eq, Debug)]
pub struct AeadDecryptionResult {
    /// The result.
    ///
    /// [`Vec<u8>`] with the following content:
    /// 1. `aad`
    /// 2. `decr(conf)`
    /// 3. `aes gcm tag`
    buf: Confidential<Vec<u8>>,
    /// The position of the authenticated data in [`Self::buf`]
    aad_range: Range<usize>,
    /// The position of the authenticated data in [`Self::buf`]
    data_range: Range<usize>,
    /// The position of the tag in [`Self::buf`]
    tag_range: Range<usize>,
}

impl AeadEncryptionResult {
    /// Deconstruct the result to just the resulting data w/o ranges.
    pub fn into_buf(self) -> Vec<u8> {
        let Self { buf, .. } = self;
        buf
    }

    /// Deconstruct the result into all parts: additional authenticated data,
    /// cipher data, and tag.
    #[allow(unused)]
    // here for completeness
    pub(crate) fn into_parts(self) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let Self {
            buf,
            aad_range,
            encr_range,
            tag_range,
        } = self;

        (
            buf[aad_range].to_vec(),
            buf[encr_range].to_vec(),
            buf[tag_range].to_vec(),
        )
    }

    /// Deconstruct the result to the resulting ciphered data w/o ranges.
    #[allow(unused)]
    // here for completeness
    pub(crate) fn into_cipher(self) -> Vec<u8> {
        let Self {
            buf,
            aad_range: _,
            encr_range,
            ..
        } = self;

        buf[encr_range].to_vec()
    }
}

impl AeadDecryptionResult {
    /// Deconstruct the result to just the resulting data w/o ranges.
    pub fn into_buf(self) -> Confidential<Vec<u8>> {
        let Self { buf, .. } = self;
        buf
    }

    /// Deconstruct the result into all parts: additional data, plain data, and tag.
    #[allow(unused)]
    // here for completeness
    pub(crate) fn into_parts(self) -> (Vec<u8>, Confidential<Vec<u8>>, Vec<u8>) {
        let Self {
            buf,
            aad_range,
            data_range,
            tag_range,
        } = self;

        (
            buf.value()[aad_range].to_vec(),
            Confidential::new(buf.value()[data_range].to_vec()),
            buf.value()[tag_range].to_vec(),
        )
    }

    /// Deconstruct the result to the resulting data w/o ranges.
    #[allow(unused)]
    // here for completeness
    pub(crate) fn into_plain(self) -> Confidential<Vec<u8>> {
        let Self {
            buf,
            aad_range: _,
            data_range,
            ..
        } = self;

        Confidential::new(buf.value()[data_range].to_vec())
    }
}

/// Encrypt confidential Data with a symmetric key and provida a gcm tag.
///
/// * `key` - symmetric key used for encryption
/// * `iv` - initialisation vector
/// * `aad` - additional authentic data
/// * `conf` - data to be encrypted
/// * `tag_len` - length of the authentication tag to generate (in bytes)
///
/// # Errors
///
/// This function will return an error if the data could not be encrypted by OpenSSL.
pub fn encrypt_aead(
    key: &SymKey,
    iv: &[u8],
    aad: &[u8],
    conf: &[u8],
) -> Result<AeadEncryptionResult> {
    let tag_len = key.key_type().tag_len().ok_or_else(|| Error::NoAeadKey)?;

    let nid = key.key_type().into();
    let cipher = Cipher::from_nid(nid).ok_or(Error::UnsupportedCipher(nid))?;
    let mut tag = vec![0x0u8; tag_len];
    let encr = openssl_encrypt_aead(cipher, key.value(), Some(iv), aad, conf, &mut tag)?;

    let mut buf = vec![0; aad.len() + encr.len() + tag.len()];
    let aad_range = Range {
        start: 0,
        end: aad.len(),
    };
    let encr_range = Range {
        start: aad.len(),
        end: aad.len() + encr.len(),
    };
    let tag_range = Range {
        start: aad.len() + encr.len(),
        end: aad.len() + encr.len() + tag.len(),
    };

    buf[aad_range.clone()].copy_from_slice(aad);
    buf[encr_range.clone()].copy_from_slice(&encr);
    buf[tag_range.clone()].copy_from_slice(&tag);
    Ok(AeadEncryptionResult {
        buf,
        aad_range,
        encr_range,
        tag_range,
    })
}

/// Decrypt encrypted data with a symmetric key compare the GCM-tag.
///
/// * `key` - symmetric key used for encryption
/// * `iv` - initialisation vector
/// * `aad` - additional authenticated data
/// * `encr` - encrypted data
/// * `tag` - GCM-tag to compare with
///
/// # Returns
/// [`Vec<u8>`] with the decrypted data
///
/// # Errors
///
/// This function will return an error if the data could not be encrypted by OpenSSL.
pub fn decrypt_aead(
    key: &SymKey,
    iv: &[u8],
    aad: &[u8],
    encr: &[u8],
    tag: &[u8],
) -> Result<AeadDecryptionResult> {
    match key {
        SymKey::Aes256(_) => {}
        SymKey::Aes256Xts(_) => return Err(Error::NoAeadKey),
    };
    let nid = key.key_type().into();
    let cipher = Cipher::from_nid(nid).ok_or(Error::UnsupportedCipher(nid))?;
    let decr =
        openssl_decrypt_aead(cipher, key.value(), Some(iv), aad, encr, tag).map_err(|ssl_err| {
            // Empty error-stack -> no internal ssl error but decryption failed.
            // Very likely due to a tag mismatch.
            if ssl_err.errors().is_empty() {
                Error::GcmTagMismatch
            } else {
                Error::Crypto(ssl_err)
            }
        })?;
    let mut conf = Confidential::new(vec![0; aad.len() + decr.len() + tag.len()]);
    let aad_range = Range {
        start: 0,
        end: aad.len(),
    };
    let data_range = Range {
        start: aad.len(),
        end: aad.len() + decr.len(),
    };
    let tag_range = Range {
        start: aad.len() + decr.len(),
        end: aad.len() + decr.len() + tag.len(),
    };

    let buf = conf.value_mut();
    buf[aad_range.clone()].copy_from_slice(aad);
    buf[data_range.clone()].copy_from_slice(&decr);
    buf[tag_range.clone()].copy_from_slice(tag);
    Ok(AeadDecryptionResult {
        buf: conf,
        aad_range,
        data_range,
        tag_range,
    })
}

/// Calculate the hash of a slice.
///
/// # Errors
///
/// This function will return an error if OpenSSL could not compute the hash.
pub(crate) fn hash(t: MessageDigest, data: &[u8]) -> Result<DigestBytes> {
    openssl::hash::hash(t, data).map_err(Error::Crypto)
}

/// Calculate the HMAC of the given message.
pub(crate) fn calculate_hmac(
    hmac_key: &PKeyRef<Private>,
    dgst: MessageDigest,
    msg: &[u8],
) -> Result<Vec<u8>> {
    match hmac_key.id() {
        Id::HMAC => Signer::new(dgst, hmac_key)?
            .sign_oneshot_to_vec(msg)
            .map_err(Error::Crypto),
        _ => Err(Error::UnsupportedSigningKey),
    }
}
/// Calculate a digital signature scheme.
///
/// Calculates the digital signature of the provided message using the signing key. [`Id::EC`],
/// and [`Id::RSA`] keys are supported. For [`Id::RSA`] [`Padding::PKCS1_PSS`] is used.
///
/// # Errors
///
/// This function will return an error if OpenSSL could not compute the signature.
pub(crate) fn sign_msg(
    skey: &PKeyRef<Private>,
    dgst: MessageDigest,
    msg: &[u8],
) -> Result<Vec<u8>> {
    match skey.id() {
        Id::EC => {
            let mut sgn = Signer::new(dgst, skey)?;
            sgn.sign_oneshot_to_vec(msg).map_err(Error::Crypto)
        }
        Id::RSA => {
            let mut sgn = Signer::new(dgst, skey)?;
            sgn.set_rsa_padding(Padding::PKCS1_PSS)?;
            sgn.sign_oneshot_to_vec(msg).map_err(Error::Crypto)
        }
        _ => Err(Error::UnsupportedSigningKey),
    }
}

/// Verify the digital signature of a message.
///
/// Verifies the digital signature of the provided message using the signing key.
/// [`Id::EC`] and [`Id::RSA`] keys are supported. For [`Id::RSA`] [`Padding::PKCS1_PSS`] is used.
///
/// # Returns
/// true if signature could be verified, false otherwise
///
/// # Errors
///
/// This function will return an error if OpenSSL could not compute the signature.
pub(crate) fn verify_signature<T: HasPublic>(
    skey: &PKeyRef<T>,
    dgst: MessageDigest,
    msg: &[u8],
    sign: &[u8],
) -> Result<bool> {
    match skey.id() {
        Id::EC => {
            let mut ctx = Verifier::new(dgst, skey)?;
            ctx.update(msg)?;
            ctx.verify(sign).map_err(Error::Crypto)
        }
        Id::RSA => {
            let mut ctx = Verifier::new(dgst, skey)?;
            ctx.set_rsa_padding(Padding::PKCS1_PSS)?;
            ctx.verify_oneshot(sign, msg).map_err(Error::Crypto)
        }
        _ => Err(Error::UnsupportedVerificationKey),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{get_test_asset, test_utils::*};

    #[test]
    fn sign_ec() {
        let (ec_key, _) = get_test_keys();

        let data = "sample".as_bytes();
        let sign = sign_msg(&ec_key, MessageDigest::sha512(), data).unwrap();
        assert!(sign.len() <= 139, "value is: {}", sign.len());

        assert!(verify_signature(&ec_key, MessageDigest::sha512(), data, &sign).unwrap());
    }

    #[test]
    fn sign_rsa_2048() {
        let keypair = get_test_asset!("keys/rsa2048key.pem");
        let keypair = PKey::private_key_from_pem(keypair).unwrap();

        let data = "sample".as_bytes();
        let sign = sign_msg(&keypair, MessageDigest::sha512(), data).unwrap();
        assert_eq!(256, sign.len());

        assert!(verify_signature(&keypair, MessageDigest::sha512(), data, &sign).unwrap());
    }

    #[test]
    fn sign_rsa_3072() {
        let keypair = get_test_asset!("keys/rsa3072key.pem");
        let keypair = PKey::private_key_from_pem(keypair).unwrap();

        let data = "sample".as_bytes();
        let sign = sign_msg(&keypair, MessageDigest::sha512(), data).unwrap();
        assert_eq!(384, sign.len());

        assert!(verify_signature(&keypair, MessageDigest::sha512(), data, &sign).unwrap());
    }

    #[test]
    fn derive_aes256_gcm_key() {
        let (cust_key, host_key) = get_test_keys();

        let exp_key: Aes256GcmKey = [
            0x75, 0x32, 0x77, 0x55, 0x8f, 0x3b, 0x60, 0x3, 0x41, 0x9e, 0xf2, 0x49, 0xae, 0x3c,
            0x4b, 0x55, 0xaa, 0xd7, 0x7d, 0x9, 0xd9, 0x7f, 0xdd, 0x1f, 0xc8, 0x8f, 0xd8, 0xf0,
            0xcf, 0x22, 0xf1, 0x49,
        ]
        .into();

        let calc_key = super::derive_aes256_gcm_key(&cust_key, &host_key).unwrap();

        assert_eq!(&calc_key, &exp_key);
    }

    #[test]
    fn hkdf_rfc_5869() {
        use openssl::md::Md;
        // RFC 6869 test vector 1
        let ikm = [0x0bu8; 22];
        let salt: [u8; 13] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let exp: [u8; 42] = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];
        let res: [u8; 42] = super::hkdf_rfc_5869(Md::sha256(), &ikm, &salt, &info).unwrap();

        assert_eq!(exp, res);
    }

    #[test]
    fn encrypt_decrypt_aes_256_gcm() {
        let aes_gcm_key = [
            0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66, 0x5f, 0x8a,
            0xe6, 0xd1, 0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69, 0xa3, 0x52, 0x02, 0x93,
            0xa5, 0x72, 0x07, 0x8f,
        ];
        let aes_gcm_iv = [
            0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84,
        ];
        let aes_gcm_plain = Confidential::new(vec![
            0xf5, 0x6e, 0x87, 0x05, 0x5b, 0xc3, 0x2d, 0x0e, 0xeb, 0x31, 0xb2, 0xea, 0xcc, 0x2b,
            0xf2, 0xa5,
        ]);
        let aes_gcm_aad = [
            0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b, 0xdb, 0x37, 0x0c, 0x43, 0x7f, 0xec,
            0x78, 0xde,
        ];
        let aes_gcm_ciphertext = [
            0xf7, 0x26, 0x44, 0x13, 0xa8, 0x4c, 0x0e, 0x7c, 0xd5, 0x36, 0x86, 0x7e, 0xb9, 0xf2,
            0x17, 0x36,
        ];
        let aes_gcm_tag = [
            0x67, 0xba, 0x05, 0x10, 0x26, 0x2a, 0xe4, 0x87, 0xd7, 0x37, 0xee, 0x62, 0x98, 0xf7,
            0x7e, 0x0c,
        ];
        let aes_gcm_res = [aes_gcm_aad, aes_gcm_ciphertext, aes_gcm_tag].concat();
        let key = SymKey::Aes256(aes_gcm_key.into());

        let AeadEncryptionResult {
            buf,
            aad_range,
            encr_range,
            tag_range,
        } = encrypt_aead(&key, &aes_gcm_iv, &aes_gcm_aad, aes_gcm_plain.value()).unwrap();
        assert_eq!(buf, aes_gcm_res);

        let conf = decrypt_aead(
            &key,
            &aes_gcm_iv,
            &buf[aad_range],
            &buf[encr_range],
            &buf[tag_range],
        )
        .unwrap();
        assert_eq!(&conf.buf.value()[conf.aad_range], &aes_gcm_aad);
        assert_eq!(&conf.buf.value()[conf.data_range], aes_gcm_plain.value());
        assert_eq!(&conf.buf.value()[conf.tag_range], &aes_gcm_tag);

        let (aad, ciphertext, tag) =
            encrypt_aead(&key, &aes_gcm_iv, &aes_gcm_aad, aes_gcm_plain.value())
                .unwrap()
                .into_parts();
        assert_eq!(aes_gcm_aad, aad.as_slice());
        assert_eq!(aes_gcm_ciphertext, ciphertext.as_slice());
        assert_eq!(aes_gcm_tag, tag.as_slice());

        let (aad2, plaintext, tag2) = decrypt_aead(&key, &aes_gcm_iv, &aad, &ciphertext, &tag)
            .unwrap()
            .into_parts();
        assert_eq!(aes_gcm_aad, aad2.as_slice());
        assert_eq!(aes_gcm_plain, plaintext);
        assert_eq!(aes_gcm_tag, tag2.as_slice());
    }

    #[test]
    fn aes_gcm_fails_wrong_keytype() {
        let aes_gcm_iv = [
            0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84,
        ];
        let aes_gcm_plain = Confidential::new(vec![
            0xf5, 0x6e, 0x87, 0x05, 0x5b, 0xc3, 0x2d, 0x0e, 0xeb, 0x31, 0xb2, 0xea, 0xcc, 0x2b,
            0xf2, 0xa5,
        ]);
        let aes_gcm_aad = [
            0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b, 0xdb, 0x37, 0x0c, 0x43, 0x7f, 0xec,
            0x78, 0xde,
        ];

        let key = SymKey::random(SymKeyType::Aes256Xts).unwrap();
        encrypt_aead(&key, &aes_gcm_iv, &aes_gcm_aad, aes_gcm_plain.value()).expect_err("");
    }

    #[test]
    fn hmac_sha512_rfc_4868() {
        // use a  test vector with key=64bytes of RFC 4868:
        // https://www.rfc-editor.org/rfc/rfc4868.html#section-2.7.2.3
        let key = [0xb; 64];
        let data = [0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65];

        let exp = vec![
            0x63, 0x7e, 0xdc, 0x6e, 0x01, 0xdc, 0xe7, 0xe6, 0x74, 0x2a, 0x99, 0x45, 0x1a, 0xae,
            0x82, 0xdf, 0x23, 0xda, 0x3e, 0x92, 0x43, 0x9e, 0x59, 0x0e, 0x43, 0xe7, 0x61, 0xb3,
            0x3e, 0x91, 0x0f, 0xb8, 0xac, 0x28, 0x78, 0xeb, 0xd5, 0x80, 0x3f, 0x6f, 0x0b, 0x61,
            0xdb, 0xce, 0x5e, 0x25, 0x1f, 0xf8, 0x78, 0x9a, 0x47, 0x22, 0xc1, 0xbe, 0x65, 0xae,
            0xa4, 0x5f, 0xd4, 0x64, 0xe8, 0x9f, 0x8f, 0x5b,
        ];
        let pkey = PKey::hmac(&key).unwrap();

        let hmac = calculate_hmac(&pkey, MessageDigest::sha512(), &data).unwrap();

        assert_eq!(hmac, exp);
    }

    #[test]
    fn from_symkeytype() {
        assert_eq!(
            <SymKeyType as Into<Nid>>::into(SymKeyType::Aes256Gcm),
            Nid::AES_256_GCM
        );
        assert_eq!(
            <SymKeyType as Into<Nid>>::into(SymKeyType::Aes256Xts),
            Nid::AES_256_XTS
        );
    }

    #[test]
    fn key_type() {
        assert_eq!(
            SymKey::random(SymKeyType::Aes256Gcm).unwrap().key_type(),
            SymKeyType::Aes256Gcm
        );
        assert_eq!(
            SymKey::random(SymKeyType::Aes256Xts).unwrap().key_type(),
            SymKeyType::Aes256Xts
        );
    }

    #[test]
    fn try_from_and_into() {
        let data = [0x1u8; 32];
        let key: SymKey = Aes256GcmKey::new(data).into();
        assert_eq!(key.value(), &data);
        let key_aes: Aes256GcmKey = key.try_into().expect("should not fail");
        assert_eq!(key_aes.value(), &data);
    }
}
