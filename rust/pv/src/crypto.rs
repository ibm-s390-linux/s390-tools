// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023, 2024

use std::convert::TryInto;
use std::fmt::Display;
use std::ops::Range;

use enum_dispatch::enum_dispatch;
use openssl::bn::BigNumContext;
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::error::ErrorStack;
use openssl::hash::{DigestBytes, MessageDigest};
use openssl::md::MdRef;
use openssl::nid::Nid;
use openssl::pkey::{HasPublic, Id, KeyType, PKey, PKeyRef, Private, Public};
use openssl::pkey_ctx::{HkdfMode, PkeyCtx};
use openssl::rand::rand_bytes;
use openssl::rsa::Padding;
use openssl::sign::{Signer, Verifier};
use openssl::symm::{
    decrypt_aead as openssl_decrypt_aead, encrypt_aead as openssl_encrypt_aead, Cipher,
};
use pv_core::request::Confidential;

use crate::error::Result;
use crate::openssl_extensions::PkeyEncapsulateContext;
use crate::req::get_pub_ecdh_points;
use crate::request::EcPubKeyCoord;
use crate::Error;

/// Compute ECDH shared secret from public and private keys
///
/// It is expected that the public and private key are with respect to EC-P521.
///
/// Note that the output is the concatenation of the 80-bytes-left-padded x and
/// 80-bytes-left-padded y coordinate.
fn ecdh_shared_secret(
    pub_key: &PKeyRef<Public>,
    priv_key: &PKeyRef<Private>,
) -> Result<[u8; 160], ErrorStack> {
    let pub_key = pub_key.ec_key()?;
    let priv_key = priv_key.ec_key()?;

    // Verify both keys use the EC-P521 curve (SECP521R1)
    assert_eq!(
        pub_key.group().curve_name(),
        Some(Nid::SECP521R1),
        "Public key must use EC-P521 curve"
    );
    assert_eq!(
        priv_key.group().curve_name(),
        Some(Nid::SECP521R1),
        "Private key must use EC-P521 curve"
    );

    pub_key.check_key()?;
    priv_key.check_key()?;
    let group = pub_key.group();
    let mut bn_ctx = BigNumContext::new()?;
    let mut point = EcPoint::new(group)?;
    point.mul2(
        group,
        pub_key.public_key(),
        priv_key.private_key(),
        &mut bn_ctx,
    )?;
    let coord = get_pub_ecdh_points(&point, group)?;
    Ok(coord)
}

/// An AES256-GCM key that will purge itself out of the memory when going out of scope
pub type Aes256GcmKey = Confidential<[u8; SymKeyType::AES_256_GCM_KEY_LEN]>;
/// An AES256-XTS key that will purge itself out of the memory when going out of scope
pub type Aes256XtsKey = Confidential<[u8; SymKeyType::AES_256_XTS_KEY_LEN]>;

/// SHA-512 digest length (in bytes)
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
    /// AES256 GCM Block length
    pub const AES_256_GCM_BLOCK_LEN: usize = 16;

    /// Returns the tag length of the [`SymKeyType`] if it is an AEAD key
    pub const fn tag_len(&self) -> Option<usize> {
        match self {
            SymKeyType::Aes256Gcm => Some(Self::AES_256_GCM_TAG_LEN),
            SymKeyType::Aes256Xts => None,
        }
    }

    /// Returns true if the [`SymKeyType`] is an AEAD key
    #[must_use]
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

    /// Try to create a symmetric key using the provided data.
    ///
    /// * `key_tp` - type of the symmetric key
    /// * `data`   - raw key data
    ///
    /// # Errors
    ///
    /// This function will return an error if the key cannot be created, e.g.
    /// because the provided data is too small or too large.
    pub fn try_from_data(key_tp: SymKeyType, data: Confidential<Vec<u8>>) -> Result<Self> {
        match key_tp {
            SymKeyType::Aes256Gcm => Ok(Self::Aes256(data.try_into()?)),
            SymKeyType::Aes256Xts => Ok(Self::Aes256Xts(data.try_into()?)),
        }
    }
}

impl Display for SymKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SymKey({:?})", self.key_type())
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

/// Determines the KeyType of a given PKey by testing against all known key types.
///
/// This function iterates through all known OpenSSL key types and uses the `is_a()`
/// method to identify which type the provided key matches. This is more reliable than
/// using `Id` to `KeyType` conversion, especially for newer key types like ML-KEM
/// that may not have a direct `Id` mapping.
///
/// # Parameters
///
/// * `key` - A reference to the PKey to identify
///
/// # Returns
///
/// * `Some(KeyType)` - If the key matches one of the known key types
/// * `None` - If the key type is not recognized or doesn't match any known types
fn pkey_to_keytype<T>(key: &PKeyRef<T>) -> Option<KeyType> {
    const KNOWN_KEY_TYPES: &[KeyType] = &[
        KeyType::RSA,
        KeyType::RSA_PSS,
        KeyType::DSA,
        KeyType::DH,
        KeyType::EC,
        KeyType::HMAC,
        KeyType::CMAC,
        KeyType::X25519,
        KeyType::ED25519,
        KeyType::X448,
        KeyType::ED448,
        KeyType::ML_KEM_512,
        KeyType::ML_KEM_768,
        KeyType::ML_KEM_1024,
    ];

    KNOWN_KEY_TYPES
        .iter()
        .find(|&&key_type| key.is_a(key_type))
        .copied()
}

fn key_type_str(t: KeyType) -> &'static str {
    if t == KeyType::RSA {
        "RSA"
    } else if t == KeyType::RSA_PSS {
        "RSA-PSS"
    } else if t == KeyType::DSA {
        "DSA"
    } else if t == KeyType::DH {
        "DH"
    } else if t == KeyType::EC {
        "EC"
    } else if t == KeyType::HMAC {
        "HMAC"
    } else if t == KeyType::CMAC {
        "CMAC"
    } else if t == KeyType::X25519 {
        "X25519"
    } else if t == KeyType::ED25519 {
        "ED25519"
    } else if t == KeyType::X448 {
        "X448"
    } else if t == KeyType::ED448 {
        "ED448"
    } else if t == KeyType::ML_KEM_512 {
        "ML-KEM-512"
    } else if t == KeyType::ML_KEM_768 {
        "ML-KEM-768"
    } else if t == KeyType::ML_KEM_1024 {
        "ML-KEM-1024"
    } else {
        "unknown"
    }
}

/// Validates that a key matches the expected key type.
///
/// # Errors
///
/// Returns an error if the key doesn't match the expected type.
pub(crate) fn validate_key_type<T: HasPublic>(
    key: &PKeyRef<T>,
    key_name: &str,
    expected_type: KeyType,
) -> Result<()> {
    if !key.is_a(expected_type) {
        return Err(Error::RetrInvKey {
            what: "key type",
            kind: key_name.to_string(),
            value: pkey_to_keytype(key)
                .map(key_type_str)
                .unwrap_or("unknown")
                .to_string(),
            exp: key_type_str(expected_type).to_string(),
        });
    }
    Ok(())
}

/// Validates that a key is an EC key with the specified curve.
///
/// # Errors
///
/// Returns an error if the key is not an EC key or doesn't use the expected curve.
pub(crate) fn validate_ec_key<T: HasPublic>(
    key: &PKeyRef<T>,
    key_name: &str,
    expected_curve: Nid,
) -> Result<()> {
    if key.id() != Id::EC {
        return Err(Error::RetrInvKey {
            what: "key type",
            kind: key_name.to_string(),
            value: pkey_to_keytype(key)
                .map(key_type_str)
                .unwrap_or("unknown")
                .to_string(),
            exp: format!("EC ({})", expected_curve.long_name().unwrap_or("unknown")),
        });
    }
    let ec_key = key.ec_key()?;
    if ec_key.group().curve_name() != Some(expected_curve) {
        return Err(Error::RetrInvKey {
            what: "curve",
            kind: key_name.to_string(),
            value: ec_key
                .group()
                .curve_name()
                .and_then(|nid| nid.long_name().ok())
                .unwrap_or("unknown")
                .to_string(),
            exp: expected_curve.long_name().unwrap_or("unknown").to_string(),
        });
    }
    Ok(())
}

/// Derive a symmetric AES 256 GCM key from a private target key, a public
/// customer key, and a public ML-KEM target key.
///
/// # Returns
///
/// The derived key and the ML-KEM ciphertext (KC).
///
/// # Errors
///
/// This function will return an error if something went bad in OpenSSL or the
/// wrong key types were used.
pub fn derive_aes256_gcm_key_hybrid(
    priv_ecdh_cust_key: &PKeyRef<Private>,
    pub_ecdh_target_key: &PKeyRef<Public>,
    pub_mlkem_target_key: &PKeyRef<Public>,
) -> Result<(Aes256GcmKey, Vec<u8>)> {
    let mut buffer: Vec<u8> = vec![0, 0, 0, 1];

    validate_ec_key(priv_ecdh_cust_key, "ECDH customer key", Nid::SECP521R1)?;
    validate_ec_key(pub_ecdh_target_key, "ECDH target key", Nid::SECP521R1)?;
    validate_key_type(
        pub_mlkem_target_key,
        "ML-KEM target key",
        KeyType::ML_KEM_1024,
    )?;

    // Derive the ECDH shared secret
    let ecdh_derived_secret = ecdh_shared_secret(pub_ecdh_target_key, priv_ecdh_cust_key)?;
    assert_eq!(ecdh_derived_secret.as_ref().len(), 160);
    buffer.extend_from_slice(ecdh_derived_secret.as_ref());

    // Derive the ML-KEM shared secret
    let mut ctx = PkeyCtx::new(pub_mlkem_target_key)?;
    ctx.encapsulate_init()?;
    let (mut ciphertext, mut shared_secret) = (vec![], vec![]);
    ctx.encapsulate_to_vec(&mut ciphertext, &mut shared_secret)?;
    assert_eq!(ciphertext.len(), 1568);
    assert_eq!(shared_secret.len(), 32);
    buffer.extend_from_slice(&shared_secret);

    // Append the private ECDH customer key
    let pub_ecdh_cust_key = EcPubKeyCoord::try_from(priv_ecdh_cust_key)?;
    assert_eq!(pub_ecdh_cust_key.as_ref().len(), 160);
    buffer.extend_from_slice(pub_ecdh_cust_key.as_ref());

    // Append the ciphertext
    buffer.extend_from_slice(&ciphertext);

    // Append the public ECDH target key
    let pub_ecdh_target_key: EcPubKeyCoord = pub_ecdh_target_key.try_into()?;
    assert_eq!(pub_ecdh_target_key.as_ref().len(), 160);
    buffer.extend_from_slice(pub_ecdh_target_key.as_ref());

    // Append the public ML-KEM target key
    assert_eq!(pub_mlkem_target_key.raw_public_key()?.len(), 1568);
    buffer.extend_from_slice(&pub_mlkem_target_key.raw_public_key()?);

    // Append the magic string
    const STRING: &str = "PQC Secure Execution with Format-2 Key Slots KS2";
    assert_eq!(STRING.len(), 48);
    buffer.extend_from_slice(STRING.as_bytes());

    // Sanity check
    assert_eq!(buffer.len(), 4 + 160 + 32 + 160 + 1568 + 160 + 1568 + 48);

    let secr = Confidential::new(buffer);

    // Panic: does not panic as SHA256 digest is 32 bytes long
    Ok((
        Aes256GcmKey::new(
            hash(MessageDigest::sha256(), secr.value())?
                .as_ref()
                .try_into()
                .unwrap(),
        ),
        ciphertext,
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
    let tag_len = key.key_type().tag_len().ok_or(Error::NoAeadKey)?;

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
    let decr = Confidential::new(
        openssl_decrypt_aead(cipher, key.value(), Some(iv), aad, encr, tag).map_err(|ssl_err| {
            // Empty error-stack -> no internal ssl error but decryption failed.
            // Very likely due to a tag mismatch.
            if ssl_err.errors().is_empty() {
                Error::GcmTagMismatch
            } else {
                Error::Crypto(ssl_err)
            }
        })?,
    );
    let mut conf = Confidential::new(vec![0; aad.len() + decr.value().len() + tag.len()]);
    let aad_range = Range {
        start: 0,
        end: aad.len(),
    };
    let data_range = Range {
        start: aad.len(),
        end: aad.len() + decr.value().len(),
    };
    let tag_range = Range {
        start: aad.len() + decr.value().len(),
        end: aad.len() + decr.value().len() + tag.len(),
    };

    let buf = conf.value_mut();
    buf[aad_range.clone()].copy_from_slice(aad);
    buf[data_range.clone()].copy_from_slice(decr.value());
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
    use std::sync::Arc;
    use std::thread;

    use super::*;
    use crate::test_utils::*;
    use crate::{get_test_asset, PvCoreError};

    /// Test that deterministic RNG contexts are thread-local and don't interfere.
    ///
    /// Per OpenSSL documentation (RAND_get0_primary(3)):
    /// "The public and private DRBG are thread-local instances, which are used by
    /// RAND_bytes() and RAND_priv_bytes(), respectively."
    ///
    /// Reference: <https://docs.openssl.org/3.1/man3/RAND_get0_primary/>
    ///
    /// Note: RAND_set0_public() and RAND_set0_private() require OpenSSL >= 3.1.
    #[test]
    fn test_deterministic_rng_thread_isolation() {
        use std::sync::Barrier;

        use openssl::rand::rand_bytes;

        // Barriers to synchronize: thread1 installs → thread2 installs → both generate → both
        // complete
        let barrier_after_t1_install = Arc::new(Barrier::new(2));
        let barrier_after_t2_install = Arc::new(Barrier::new(2));
        let barrier_after_rand_bytes = Arc::new(Barrier::new(2));

        let barrier1_clone = Arc::clone(&barrier_after_t1_install);
        let barrier2_clone = Arc::clone(&barrier_after_t2_install);
        let barrier3_clone = Arc::clone(&barrier_after_rand_bytes);

        // Thread 1: Install deterministic RNG with specific entropy
        let thread1 = thread::spawn(move || {
            let entropy = [0x42u8; 4096];
            let nonce = [0x24u8; 48];

            // Install thread-local deterministic RNG
            let _rng = DeterministicTestRandGuard::install(&entropy, &nonce).unwrap();

            // Signal thread2 that we've installed our RNG
            barrier1_clone.wait();

            // Wait for thread2 to install its RNG
            barrier2_clone.wait();

            // Now generate bytes while thread2 also has its RNG installed
            let mut buf = [0u8; 32];
            rand_bytes(&mut buf).unwrap();

            // Wait for thread2 to also complete rand_bytes
            barrier3_clone.wait();

            buf
        });

        // Thread 2: Install different deterministic RNG after thread1
        let thread2 = thread::spawn(move || {
            // Wait for thread1 to install its RNG first
            barrier_after_t1_install.wait();

            // Now install our own thread-local deterministic RNG with different entropy
            let entropy = [0xAAu8; 4096];
            let nonce = [0x55u8; 48];
            let _rng = DeterministicTestRandGuard::install(&entropy, &nonce).unwrap();

            // Signal thread1 that we've installed our RNG
            barrier_after_t2_install.wait();

            // Generate bytes with our different entropy (concurrently with thread1)
            let mut buf = [0u8; 32];
            rand_bytes(&mut buf).unwrap();

            // Wait for thread1 to also complete rand_bytes
            barrier_after_rand_bytes.wait();

            buf
        });

        let t1_buf = thread1.join().unwrap();
        let t2_buf = thread2.join().unwrap();

        // Expected deterministic values for thread 1 (entropy=0x42, nonce=0x24)
        let expected_t1: [u8; 32] = [
            66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
            66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
        ];

        // Expected deterministic values for thread 2 (entropy=0xAA, nonce=0x55)
        let expected_t2: [u8; 32] = [
            170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
            170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
        ];

        // Verify each thread produced its expected deterministic output
        assert_eq!(
            t1_buf, expected_t1,
            "Thread 1 should produce deterministic output"
        );
        assert_eq!(
            t2_buf, expected_t2,
            "Thread 2 should produce deterministic output"
        );

        // Also verify they are different (proves thread-local isolation)
        assert_ne!(
            t1_buf, t2_buf,
            "Different thread-local entropy should produce different output"
        );
    }

    /// Test that the original RNG is properly restored after DeterministicTestRandGuard is dropped
    #[test]
    fn test_deterministic_rng_restoration() {
        use openssl::rand::rand_bytes;

        // Generate random bytes with system RNG before installing deterministic RNG
        let mut before_buf = [0u8; 32];
        rand_bytes(&mut before_buf).unwrap();

        let deterministic_buf = {
            let entropy = [0x42u8; 4096];
            let nonce = [0x24u8; 48];

            // Install deterministic RNG
            let _rng = DeterministicTestRandGuard::install(&entropy, &nonce).unwrap();

            // Generate deterministic bytes
            let mut buf = [0u8; 32];
            rand_bytes(&mut buf).unwrap();

            // Expected deterministic output
            let expected: [u8; 32] = [
                66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
                66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
            ];
            assert_eq!(buf, expected, "Should produce deterministic output");

            buf
            // _rng is dropped here, should restore original RNG
        };

        // Generate random bytes again with restored system RNG
        let mut after_buf = [0u8; 32];
        rand_bytes(&mut after_buf).unwrap();

        // The system RNG should produce different random values each time
        // (extremely unlikely to match the deterministic output)
        assert_ne!(
            after_buf, deterministic_buf,
            "After restoration, system RNG should produce different random values"
        );

        // Also verify that before and after are different (system RNG produces random values)
        // Note: This could theoretically fail with probability 1/2^256, but that's negligible
        assert_ne!(
            before_buf, after_buf,
            "System RNG should produce different random values on each call"
        );
    }

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
    fn derive_aes256_gcm_key_hybrid() {
        let (cust_key, host_key_1, host_key_2) = get_test_keys_hybrid();
        let entropy = [0x5au8; 4096];
        let nonce = [0xa5u8; 48];

        let _rng = DeterministicTestRandGuard::install(&entropy, &nonce).unwrap();

        let exp_key: Aes256GcmKey = [
            197, 167, 157, 112, 186, 112, 72, 125, 192, 219, 168, 132, 178, 167, 249, 123, 149, 3,
            151, 166, 162, 66, 120, 39, 41, 230, 143, 54, 172, 10, 200, 143,
        ]
        .into();
        let exp_kc = [
            54, 117, 96, 77, 148, 147, 170, 100, 34, 177, 95, 7, 35, 243, 145, 115, 7, 87, 178, 9,
            169, 99, 193, 99, 244, 195, 23, 78, 11, 153, 221, 196, 5, 192, 253, 192, 86, 49, 194,
            236, 43, 69, 183, 125, 166, 87, 158, 188, 13, 152, 19, 6, 253, 29, 194, 0, 101, 236,
            28, 171, 3, 236, 53, 186, 191, 109, 7, 83, 220, 93, 126, 29, 19, 203, 201, 39, 59, 7,
            131, 51, 81, 73, 254, 69, 105, 185, 214, 179, 155, 194, 189, 122, 106, 130, 249, 48, 4,
            33, 245, 170, 163, 4, 223, 208, 138, 224, 203, 119, 105, 59, 187, 153, 235, 90, 79,
            127, 29, 136, 230, 142, 78, 83, 27, 131, 58, 126, 76, 53, 129, 20, 85, 108, 86, 64,
            244, 90, 84, 177, 239, 105, 90, 41, 118, 189, 88, 174, 224, 216, 29, 10, 123, 81, 212,
            203, 197, 120, 20, 190, 3, 45, 37, 194, 208, 249, 232, 221, 67, 10, 62, 121, 143, 169,
            227, 165, 17, 30, 85, 223, 44, 141, 114, 142, 105, 119, 187, 41, 46, 8, 6, 17, 29, 165,
            117, 254, 92, 174, 231, 25, 117, 69, 112, 216, 80, 73, 185, 54, 50, 119, 145, 220, 174,
            26, 105, 81, 114, 210, 144, 148, 109, 218, 64, 78, 231, 196, 229, 88, 46, 128, 106,
            125, 204, 58, 184, 127, 193, 207, 86, 163, 98, 164, 57, 242, 29, 59, 251, 227, 185, 60,
            18, 68, 74, 47, 203, 61, 164, 78, 245, 100, 87, 148, 210, 97, 158, 252, 79, 78, 50,
            143, 35, 231, 215, 211, 75, 133, 214, 227, 140, 27, 21, 46, 221, 84, 89, 165, 161, 227,
            46, 117, 193, 254, 190, 237, 130, 28, 57, 52, 14, 235, 154, 115, 172, 185, 67, 116, 34,
            242, 158, 209, 0, 126, 196, 93, 224, 29, 246, 145, 65, 73, 185, 196, 4, 107, 124, 241,
            157, 230, 168, 244, 238, 84, 188, 173, 17, 238, 26, 161, 24, 176, 229, 226, 33, 244,
            167, 41, 107, 156, 29, 226, 248, 64, 146, 191, 210, 234, 76, 144, 219, 92, 136, 173,
            241, 98, 0, 71, 135, 214, 196, 116, 63, 243, 73, 71, 130, 171, 86, 204, 149, 69, 164,
            20, 177, 122, 95, 226, 95, 126, 106, 160, 59, 97, 137, 8, 73, 113, 189, 172, 24, 114,
            60, 62, 249, 193, 3, 99, 34, 153, 42, 238, 77, 181, 80, 185, 223, 39, 8, 44, 215, 119,
            214, 30, 136, 19, 215, 35, 184, 69, 94, 10, 170, 179, 51, 183, 105, 237, 237, 48, 199,
            122, 159, 87, 183, 71, 230, 87, 102, 77, 81, 116, 28, 126, 195, 72, 50, 157, 223, 243,
            83, 36, 16, 168, 111, 209, 132, 12, 96, 56, 140, 57, 144, 75, 253, 119, 123, 168, 2,
            79, 214, 121, 80, 154, 93, 235, 222, 130, 181, 166, 97, 51, 106, 21, 138, 224, 8, 144,
            223, 162, 152, 183, 6, 80, 64, 144, 21, 155, 56, 255, 108, 248, 125, 196, 46, 99, 119,
            94, 104, 63, 46, 15, 165, 30, 98, 75, 212, 193, 116, 151, 189, 65, 42, 83, 253, 183,
            41, 195, 45, 206, 178, 66, 36, 215, 197, 105, 236, 79, 91, 135, 164, 71, 187, 199, 200,
            150, 226, 182, 254, 6, 234, 109, 3, 17, 116, 249, 44, 211, 184, 61, 189, 44, 181, 249,
            8, 58, 230, 236, 8, 188, 14, 178, 100, 120, 250, 29, 1, 204, 158, 46, 161, 39, 66, 76,
            42, 114, 149, 160, 31, 87, 254, 181, 224, 17, 162, 163, 99, 11, 34, 149, 50, 203, 205,
            224, 38, 18, 233, 161, 49, 7, 151, 63, 81, 68, 71, 174, 49, 22, 143, 93, 50, 0, 154,
            152, 178, 134, 147, 152, 118, 196, 241, 233, 67, 102, 149, 179, 213, 176, 118, 64, 172,
            143, 134, 196, 232, 154, 110, 129, 155, 159, 103, 117, 202, 11, 35, 75, 104, 5, 11,
            160, 147, 174, 49, 248, 45, 247, 16, 7, 64, 209, 255, 170, 243, 242, 40, 158, 94, 239,
            194, 225, 113, 24, 90, 243, 73, 137, 217, 175, 130, 50, 133, 139, 250, 145, 190, 76,
            151, 183, 30, 86, 146, 59, 171, 214, 211, 135, 203, 192, 42, 189, 90, 47, 152, 132,
            168, 252, 175, 71, 234, 118, 207, 161, 176, 254, 189, 54, 174, 160, 178, 158, 133, 122,
            63, 75, 95, 201, 55, 139, 2, 208, 232, 110, 74, 201, 196, 135, 244, 156, 87, 208, 101,
            203, 121, 187, 16, 106, 80, 120, 165, 44, 147, 182, 114, 173, 186, 185, 255, 99, 85,
            88, 26, 27, 43, 203, 176, 207, 88, 20, 253, 169, 210, 168, 109, 75, 234, 239, 8, 243,
            244, 65, 164, 193, 255, 240, 215, 54, 158, 188, 93, 93, 54, 46, 77, 152, 78, 174, 154,
            67, 248, 24, 235, 172, 240, 83, 224, 17, 100, 217, 15, 172, 176, 46, 85, 107, 105, 127,
            147, 158, 202, 255, 145, 237, 84, 223, 100, 214, 38, 133, 169, 112, 227, 138, 220, 125,
            72, 197, 5, 227, 94, 245, 42, 70, 33, 209, 243, 70, 229, 37, 118, 214, 147, 43, 87, 39,
            241, 107, 26, 169, 28, 72, 223, 133, 145, 44, 248, 213, 52, 127, 250, 99, 193, 115,
            113, 147, 89, 112, 237, 199, 208, 36, 155, 106, 144, 73, 249, 8, 116, 198, 107, 120,
            233, 145, 11, 155, 178, 7, 66, 157, 255, 206, 128, 155, 233, 111, 148, 194, 214, 238,
            252, 230, 96, 119, 30, 37, 73, 133, 129, 87, 185, 149, 251, 156, 17, 8, 83, 106, 207,
            98, 203, 100, 39, 199, 127, 253, 59, 37, 121, 161, 216, 146, 6, 178, 183, 243, 191, 91,
            106, 243, 132, 111, 216, 163, 87, 210, 197, 173, 146, 65, 131, 194, 96, 70, 6, 7, 192,
            45, 173, 71, 44, 134, 122, 60, 173, 208, 238, 22, 187, 208, 212, 51, 191, 185, 174, 3,
            125, 28, 134, 216, 209, 4, 224, 199, 16, 15, 56, 70, 188, 216, 92, 24, 96, 57, 125,
            138, 151, 73, 254, 245, 106, 53, 4, 150, 74, 43, 42, 4, 157, 238, 125, 168, 41, 224,
            22, 249, 45, 117, 32, 180, 161, 41, 39, 180, 96, 24, 2, 102, 57, 116, 34, 75, 90, 72,
            134, 176, 2, 196, 59, 143, 182, 201, 117, 178, 153, 81, 108, 167, 122, 139, 71, 197,
            55, 114, 60, 161, 130, 14, 29, 79, 152, 55, 136, 62, 190, 228, 202, 53, 126, 4, 173,
            99, 28, 190, 224, 255, 134, 123, 166, 162, 244, 55, 26, 81, 120, 207, 193, 10, 103,
            153, 215, 220, 12, 71, 67, 217, 154, 212, 44, 200, 232, 0, 178, 39, 44, 22, 7, 14, 215,
            183, 192, 104, 51, 46, 93, 102, 195, 65, 9, 191, 241, 237, 151, 5, 64, 103, 228, 162,
            41, 123, 29, 5, 80, 203, 198, 234, 230, 107, 53, 60, 58, 253, 47, 152, 22, 77, 81, 86,
            215, 132, 152, 135, 6, 218, 46, 92, 192, 218, 198, 234, 76, 178, 25, 203, 48, 61, 76,
            215, 96, 6, 49, 195, 37, 225, 10, 175, 222, 186, 133, 63, 50, 236, 215, 247, 17, 199,
            8, 134, 64, 246, 194, 167, 105, 15, 57, 62, 50, 51, 243, 192, 242, 122, 11, 46, 202,
            47, 10, 71, 153, 212, 226, 38, 12, 90, 150, 154, 152, 233, 7, 172, 111, 185, 160, 246,
            0, 166, 113, 90, 37, 203, 166, 43, 53, 255, 211, 127, 139, 73, 7, 10, 164, 1, 168, 223,
            87, 127, 43, 47, 87, 68, 84, 247, 223, 108, 108, 113, 36, 17, 50, 98, 236, 48, 10, 219,
            182, 107, 240, 198, 207, 20, 178, 9, 142, 14, 93, 163, 166, 147, 38, 176, 172, 156, 73,
            174, 238, 175, 231, 130, 159, 51, 128, 76, 34, 37, 138, 19, 3, 59, 71, 78, 144, 238,
            226, 214, 188, 27, 42, 142, 245, 238, 131, 190, 211, 240, 41, 122, 69, 124, 171, 75,
            115, 45, 144, 133, 176, 19, 81, 125, 230, 149, 235, 159, 6, 155, 195, 119, 62, 140, 50,
            52, 209, 124, 3, 93, 232, 20, 130, 138, 110, 60, 183, 177, 161, 52, 114, 91, 19, 211,
            156, 185, 202, 200, 36, 103, 253, 113, 45, 245, 177, 238, 43, 144, 38, 221, 0, 102, 50,
            255, 20, 154, 56, 156, 155, 92, 157, 57, 209, 77, 84, 88, 24, 116, 116, 54, 213, 222,
            76, 212, 193, 168, 216, 247, 125, 135, 114, 226, 128, 140, 250, 103, 82, 215, 238, 32,
            74, 252, 45, 224, 23, 95, 126, 124, 135, 124, 128, 53, 203, 40, 65, 222, 8, 83, 178,
            211, 64, 141, 64, 98, 188, 134, 100, 65, 166, 52, 249, 1, 206, 58, 55, 195, 23, 218,
            239, 41, 73, 88, 113, 148, 132, 209, 93, 37, 205, 58, 92, 14, 1, 133, 168, 162, 192,
            147, 70, 167, 101, 170, 152, 159, 0, 212, 26, 97, 49, 43, 217, 173, 38, 215, 136, 26,
            208, 244, 19, 83, 207, 38, 224, 254, 92, 169, 219, 236, 172, 49, 55, 98, 55, 15, 187,
            173, 114, 99, 130, 211, 78, 168, 221, 209, 250, 88, 189, 17, 186, 172, 129, 56, 90,
            238, 120, 23, 176, 87, 133, 81, 244, 29, 2, 215, 34, 88, 247, 231, 167, 56,
        ];

        let (exc_key, kc) =
            super::derive_aes256_gcm_key_hybrid(&cust_key, &host_key_1, &host_key_2).unwrap();

        assert_eq!(exc_key, exp_key);
        assert_eq!(kc, exp_kc);
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

    #[test]
    fn try_from_data() {
        let data = [0x3u8; 32];
        let key = SymKey::try_from_data(SymKeyType::Aes256Gcm, Confidential::new(data.into()))
            .expect("should not fail");
        assert_eq!(&data, key.value());
        let key_aes: Aes256GcmKey = key.try_into().expect("should not fail");
        assert_eq!(&data, key_aes.value());

        assert!(matches!(
            SymKey::try_from_data(SymKeyType::Aes256Gcm, Confidential::new([0x4u8; 33].into())),
            Err(Error::PvCore(PvCoreError::LengthMismatch {
                expected: 32,
                actual: 33
            }))
        ));
    }

    #[test]
    fn validate_ec_key_valid() {
        let (cust_key, host_key) = get_test_keys();

        // Both test keys are SECP521R1 EC keys
        assert!(validate_ec_key(&cust_key, "customer key", Nid::SECP521R1).is_ok());
        assert!(validate_ec_key(&host_key, "host key", Nid::SECP521R1).is_ok());
    }

    #[test]
    fn validate_ec_key_wrong_curve() {
        let (cust_key, _) = get_test_keys();

        // Test key is SECP521R1, but we expect SECP384R1
        let result = validate_ec_key(&cust_key, "customer key", Nid::SECP384R1);
        assert!(result.is_err());

        if let Err(Error::RetrInvKey {
            what,
            kind,
            value,
            exp,
        }) = result
        {
            assert_eq!(what, "curve");
            assert_eq!(kind, "customer key");
            assert_eq!(value, "secp521r1");
            assert_eq!(exp, "secp384r1");
        } else {
            panic!("Expected RetrInvKey error");
        }
    }

    #[test]
    fn validate_ec_key_not_ec() {
        let keypair = crate::get_test_asset!("keys/rsa2048key.pem");
        let keypair = PKey::private_key_from_pem(keypair).unwrap();

        // RSA key is not an EC key
        let result = validate_ec_key(&keypair, "EC key", Nid::SECP521R1);
        assert!(result.is_err());

        if let Err(Error::RetrInvKey {
            what,
            kind,
            value,
            exp,
        }) = result
        {
            assert_eq!(what, "key type");
            assert_eq!(kind, "EC key");
            assert_eq!(value, "RSA");
            assert_eq!(exp, "EC (secp521r1)");
        } else {
            panic!("Expected RetrInvKey error");
        }
    }

    #[test]
    fn validate_mlkem_key_valid() {
        let (_, _, mlkem_key) = get_test_keys_hybrid();

        // The third key from get_test_keys_hybrid is ML-KEM-1024
        assert!(validate_key_type(&mlkem_key, "ML-KEM key", KeyType::ML_KEM_1024).is_ok());
    }

    #[test]
    fn validate_mlkem_key_wrong_type() {
        let (ec_key, _) = get_test_keys();

        // EC key is not ML-KEM
        let result = validate_key_type(&ec_key, "EC key", KeyType::ML_KEM_1024);
        assert!(result.is_err());

        if let Err(Error::RetrInvKey {
            what,
            kind,
            value,
            exp,
        }) = result
        {
            assert_eq!(what, "key type");
            assert_eq!(kind, "EC key");
            assert_eq!(value, "EC");
            assert_eq!(exp, "ML-KEM-1024");
        } else {
            panic!("Expected RetrInvKey error");
        }
    }
}
