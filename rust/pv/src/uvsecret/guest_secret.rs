// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

#[allow(unused_imports)] // used for more convenient docstring
use super::asrcb::AddSecretRequest;
use crate::{
    assert_size,
    crypto::{hash, random_array, SymKeyType},
    request::{
        openssl::{NID_ED25519, NID_ED448},
        Confidential,
    },
    uv::{
        AesSizes, AesXtsSizes, EcCurves, HmacShaSizes, ListableSecretType, RetrievableSecret,
        RetrieveCmd, SecretId,
    },
    Error, Result,
};
use openssl::{
    hash::MessageDigest,
    nid::Nid,
    pkey::{Id, PKey, PKeyRef, Private},
};
use pv_core::static_assert;
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use zerocopy::{BigEndian, KnownLayout};
use zerocopy::{FromBytes, Immutable, IntoBytes, U16, U32};

const ASSOC_SECRET_SIZE: usize = 32;
const CCK_SIZE: usize = 32;
/// Maximum size of a plain-text secret payload (8190)
pub(crate) const MAX_SIZE_PLAIN_PAYLOAD: usize = RetrieveCmd::MAX_SIZE - 2;
static_assert!(MAX_SIZE_PLAIN_PAYLOAD == 8190);

/// A Secret to be added in [`AddSecretRequest`]
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum GuestSecret {
    /// No guest secret
    Null,
    /// Association secret used to associate an extension card to a SE guest
    ///
    /// Create Associations using [`GuestSecret::association`]
    Association {
        /// Name of the secret
        name: String,
        /// SHA256 hash of [`GuestSecret::Association::name`]
        id: SecretId,
        /// Confidential actual association secret (32 bytes)
        #[serde(skip)]
        secret: Confidential<[u8; ASSOC_SECRET_SIZE]>,
    },
    /// Retrievable key
    ///
    /// Create Retrievables using [`GuestSecret::retrievable`]
    /// Secret size is always valid for the type/kind
    Retrievable {
        /// Retrievable secret type
        kind: RetrievableSecret,
        /// Name of the secret
        name: String,
        /// SHA256 hash of [`GuestSecret::RetrievableKey::name`]
        id: SecretId,
        /// Confidential actual retrievable secret
        #[serde(skip)]
        secret: Confidential<Vec<u8>>,
    },
    /// CCK update
    ///
    /// Create CCK updates using [`GuestSecret::update_cck`]
    UpdateCck {
        /// Confidential actual CCK (32 bytes)
        #[serde(skip)]
        secret: Confidential<[u8; CCK_SIZE]>,
    },
}

macro_rules! retr_constructor {
    ($(#[$err:meta])* | $(#[$kind:meta])* =>  $type: ty, $func: ident) => {
        /// Create a new
        $(#[$kind])*
        /// [`GuestSecret::Retrievable`] secret.
        ///
        /// * `name` - Name of the secret. Will be hashed into a 32 byte id
        /// * `secret` - the secret value
        ///
        /// # Errors
        ///
        $(#[$err])*
        pub fn $func(name: &str, secret: $type) -> Result<Self> {
            let (kind, secret) = $func(secret)?;
            Ok(Self::Retrievable {
                kind,
                name: name.to_string(),
                id: Self::name_to_id(name)?,
                secret,
            })
        }
    };
}

impl GuestSecret {
    /// Hashes the name with sha256
    pub fn name_to_id(name: &str) -> Result<SecretId> {
        let id: [u8; SecretId::ID_SIZE] = hash(MessageDigest::sha256(), name.as_bytes())?
            .to_vec()
            .try_into()
            .unwrap();
        Ok(id.into())
    }

    /// Create a new [`GuestSecret::Association`].
    ///
    /// * `name` - Name of the secret. Will be hashed into a 32 byte id
    /// * `secret` - Value of the secret. Random if [`Option::None`]
    ///
    /// # Errors
    ///
    /// This function will return an error if OpenSSL cannot create a hash.
    pub fn association<O>(name: &str, secret: O) -> Result<Self>
    where
        O: Into<Option<[u8; ASSOC_SECRET_SIZE]>>,
    {
        let secret = match secret.into() {
            Some(s) => s,
            None => random_array()?,
        };

        Ok(Self::Association {
            name: name.to_string(),
            id: Self::name_to_id(name)?,
            secret: secret.into(),
        })
    }

    retr_constructor!(#[doc = r"This function will return an error if the secret is larger than 8 pages"]
                      | #[doc = r"plaintext"] => Confidential<Vec<u8>>, plaintext);
    retr_constructor!(#[doc = r"This function will return an error if  OpenSSL cannot create a hash or the secret size is invalid"]
                      | #[doc = r"AES Key"] => Confidential<Vec<u8>>, aes);
    retr_constructor!(#[doc = r"This function will return an error if  OpenSSL cannot create a hash or the secret size is invalid"]
                      | #[doc = r"AES-XTS Key"] => Confidential<Vec<u8>>, aes_xts);
    retr_constructor!(#[doc = r"This function will return an error if  OpenSSL cannot create a hash or the secret size is invalid"]
                      | #[doc = r"HMAC-SHA Key"] => Confidential<Vec<u8>>, hmac_sha);
    retr_constructor!(#[doc = r"This function will return an error if  OpenSSL cannot create a hash or the curve is invalid"]
                      | #[doc = r"EC PRIVATE Key"] => PKey<Private>, ec);

    /// Create a new [`GuestSecret::UpdateCck`].
    ///
    /// * `secret` - New CCK.
    pub fn update_cck(secret: [u8; CCK_SIZE]) -> Self {
        Self::UpdateCck {
            secret: secret.into(),
        }
    }

    /// Use the name as ID, do not hash it
    pub fn no_hash_name(&mut self) {
        match self {
            Self::Null | Self::UpdateCck { .. } => (),
            Self::Association {
                name, ref mut id, ..
            }
            | Self::Retrievable {
                name, ref mut id, ..
            } => id.clone_from(&SecretId::from_string(name)),
        }
    }

    /// Reference to the confidential data
    pub fn confidential(&self) -> &[u8] {
        match &self {
            Self::Null => &[],
            Self::Association { secret, .. } => secret.value().as_slice(),
            Self::Retrievable { secret, .. } => secret.value(),
            Self::UpdateCck { secret, .. } => secret.value(),
        }
    }

    /// Creates the non-confidential part of the secret ad-hoc
    pub(crate) fn auth(&self) -> SecretAuth {
        match &self {
            Self::Null => SecretAuth::Null,
            Self::UpdateCck { .. } => SecretAuth::UpdateCck,
            // Panic: other secret types are list-able -> no panic
            listable => {
                SecretAuth::Listable(ListableSecretHdr::from_guest_secret(listable).unwrap())
            }
        }
    }

    /// Returns the UV type ID
    fn kind(&self) -> u16 {
        match self {
            // Null is not listable, but the ListableSecretType provides the type constant (1)
            Self::Null => ListableSecretType::NULL,
            Self::Association { .. } => ListableSecretType::ASSOCIATION,
            Self::Retrievable { kind, .. } => kind.into(),
            Self::UpdateCck { .. } => ListableSecretType::UPDATE_CCK,
        }
    }

    /// Size of the secret value
    fn secret_len(&self) -> u32 {
        match self {
            Self::Null => 0,
            Self::Association { secret, .. } => secret.value().len() as u32,
            Self::Retrievable { secret, .. } => secret.value().len() as u32,
            Self::UpdateCck { secret } => secret.value().len() as u32,
        }
    }

    /// Returns the ID of the secret type (if any)
    fn id(&self) -> Option<SecretId> {
        match self {
            Self::Null | Self::UpdateCck { .. } => None,
            Self::Association { id, .. } | Self::Retrievable { id, .. } => Some(id.to_owned()),
        }
    }
}

type RetrKeyInfo = (RetrievableSecret, Confidential<Vec<u8>>);

fn extend_to_multiple(mut key: Vec<u8>, multiple: usize) -> Confidential<Vec<u8>> {
    match key.len().checked_rem(multiple) {
        Some(0) | None => key,
        Some(m) => {
            key.resize(key.len() + multiple - m, 0);
            key
        }
    }
    .into()
}

/// Get a plain-text key
///
/// ```none
///  size U16<BigEndian> | payload (0-8190) bytes
/// ```
fn plaintext(inp: Confidential<Vec<u8>>) -> Result<RetrKeyInfo> {
    let key_len = inp.value().len();
    if key_len > MAX_SIZE_PLAIN_PAYLOAD {
        return Err(Error::RetrInvKey {
            what: "key size",
            value: key_len.to_string(),
            kind: RetrievableSecret::PlainText.to_string(),
            exp: RetrievableSecret::PlainText.expected(),
        });
    }
    let mut key = Vec::with_capacity(2 + inp.value().len());
    let key_len: U16<BigEndian> = (key_len as u16).into();
    key.extend_from_slice(key_len.as_bytes());
    key.extend_from_slice(inp.value());
    let key = extend_to_multiple(key, SymKeyType::AES_256_GCM_BLOCK_LEN);

    Ok((RetrievableSecret::PlainText, key))
}

/// Get an AES-key
fn aes(key: Confidential<Vec<u8>>) -> Result<RetrKeyInfo> {
    let key_len = key.value().len() as u32;
    let bit_size = bitsize(key_len);
    match AesSizes::from_bits(bit_size) {
        Some(size) => Ok((RetrievableSecret::Aes(size), key)),
        None => {
            // Use some AES type to get exp sizes and name
            let kind = RetrievableSecret::Aes(AesSizes::Bits128);
            Err(Error::RetrInvKey {
                what: "key size",
                value: bit_size.to_string(),
                kind: format!("{kind:#}"),
                exp: kind.expected(),
            })
        }
    }
}

/// Get an AES-XTS-key
fn aes_xts(key: Confidential<Vec<u8>>) -> Result<RetrKeyInfo> {
    let key_len = key.value().len() as u32;
    let bit_size = bitsize(key_len / 2);
    match AesXtsSizes::from_bits(bit_size) {
        Some(size) => Ok((RetrievableSecret::AesXts(size), key)),
        None => {
            // Use some AES-XTS type to get exp sizes and name
            let kind = RetrievableSecret::AesXts(AesXtsSizes::Bits128);
            Err(Error::RetrInvKey {
                what: "key size",
                value: bit_size.to_string(),
                kind: format!("{kind:#}"),
                exp: kind.expected(),
            })
        }
    }
}

/// Get an HMAC-SHA-key
fn hmac_sha(key: Confidential<Vec<u8>>) -> Result<RetrKeyInfo> {
    let key_len = key.value().len() as u32;
    let size = bitsize(key_len / 2);
    match HmacShaSizes::from_sha_size(size) {
        Some(size) => Ok((RetrievableSecret::HmacSha(size), key)),
        None => {
            // Use some HMAC type to get exp sizes and name
            let kind = RetrievableSecret::HmacSha(HmacShaSizes::Sha256);
            Err(Error::RetrInvKey {
                what: "key size",
                value: size.to_string(),
                kind: format!("{kind:#}"),
                exp: kind.expected(),
            })
        }
    }
}

/// Get an EC-private-key
fn ec(key: PKey<Private>) -> Result<RetrKeyInfo> {
    // reads & left-pads Edward EC keys
    fn pad_ed_key(pkey: &PKeyRef<Private>, curve: &EcCurves) -> Result<Vec<u8>> {
        let raw_key = pkey.raw_private_key()?;

        match raw_key.len().cmp(&curve.exp_key_size()) {
            std::cmp::Ordering::Less => {
                let mut key = Vec::with_capacity(curve.exp_key_size());
                key.extend_from_slice(&vec![0u8; curve.exp_key_size() - raw_key.len()]);
                key.extend_from_slice(&raw_key);
                Ok(key)
            }
            std::cmp::Ordering::Equal => Ok(raw_key),
            std::cmp::Ordering::Greater => Err(Error::InvalSslData),
        }
    }

    let nid = match key.id() {
        Id::EC => key.ec_key()?.group().curve_name().unwrap_or(Nid::UNDEF),
        id @ (Id::ED25519 | Id::ED448) => Nid::from_raw(id.as_raw()),
        _ => Nid::UNDEF,
    };

    let kind = match nid {
        Nid::X9_62_PRIME256V1 => EcCurves::Secp256R1,
        Nid::SECP384R1 => EcCurves::Secp384R1,
        Nid::SECP521R1 => EcCurves::Secp521R1,
        NID_ED25519 => EcCurves::Ed25519,
        NID_ED448 => EcCurves::Ed448,
        nid => {
            // Use some EC type to get exp sizes and name
            let ec = RetrievableSecret::Ec(EcCurves::Secp521R1);
            return Err(Error::RetrInvKey {
                what: "curve or format",
                kind: format!("{ec:#}"),
                value: nid.long_name()?.to_string(),
                exp: ec.expected(),
            });
        }
    };

    let key = match key.id() {
        Id::EC => key
            .ec_key()?
            .private_key()
            .to_vec_padded(kind.exp_key_size() as i32)?,
        // ED keys are not handled via the EC struct in OpenSSL.
        Id::ED25519 | Id::ED448 => pad_ed_key(&key, &kind)?,
        _ => unreachable!(),
    };

    Ok((RetrievableSecret::Ec(kind), key.into()))
}

#[inline(always)]
const fn bitsize(bytesize: u32) -> u32 {
    bytesize * 8
}

impl Display for GuestSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Null => write!(f, "Meta"),
            gs => {
                let kind: U16<BigEndian> = gs.kind().into();
                let st: ListableSecretType = kind.get().into();
                write!(f, "{st}")
            }
        }
    }
}

#[derive(Debug)]
pub(crate) enum SecretAuth {
    Null,
    Listable(ListableSecretHdr),
    UpdateCck,
}

impl SecretAuth {
    const NULL_HDR: NullSecretHdr = NullSecretHdr::new();
    const UPDATE_CCK_HDR: UpdateCckHdr = UpdateCckHdr::new();

    pub fn get(&self) -> &[u8] {
        match self {
            Self::Null => Self::NULL_HDR.as_bytes(),
            Self::Listable(h) => h.as_bytes(),
            Self::UpdateCck => Self::UPDATE_CCK_HDR.as_bytes(),
        }
    }
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout)]
struct NullSecretHdr {
    res0: u16,
    kind: U16<BigEndian>,
    secret_len: U32<BigEndian>,
    res8: u64,
}
assert_size!(NullSecretHdr, 0x10);

impl NullSecretHdr {
    const fn new() -> Self {
        Self {
            res0: 0,
            kind: U16::new(ListableSecretType::NULL),
            secret_len: U32::ZERO,
            res8: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout)]
pub(crate) struct ListableSecretHdr {
    res0: u16,
    kind: U16<BigEndian>,
    secret_len: U32<BigEndian>,
    res8: u64,
    pub(crate) id: SecretId,
}
assert_size!(ListableSecretHdr, 0x30);

impl ListableSecretHdr {
    fn from_guest_secret(gs: &GuestSecret) -> Option<Self> {
        Some(Self {
            res0: 0,
            kind: gs.kind().into(),
            secret_len: gs.secret_len().into(),
            res8: 0,
            id: gs.id()?,
        })
    }
}

#[repr(C)]
#[derive(Debug, IntoBytes, Default, Immutable)]
struct UpdateCckHdr {
    res0: u16,
    kind: U16<BigEndian>,
    secret_len: U32<BigEndian>,
    res8: u64,
    res10: [u8; 0x20],
}
assert_size!(UpdateCckHdr, 0x30);

impl UpdateCckHdr {
    const fn new() -> Self {
        Self {
            res0: 0,
            kind: U16::new(ListableSecretType::UPDATE_CCK),
            secret_len: U32::new(CCK_SIZE as u32),
            res8: 0,
            res10: [0; 0x20],
        }
    }
}

#[cfg(test)]
mod test {

    use super::HmacShaSizes as HmacSizes;
    use super::RetrievableSecret::*;
    use super::*;
    use openssl::ec::{EcGroup, EcKey};
    use pv_core::uv::AesSizes;
    use serde_test::{assert_tokens, Token};

    #[test]
    fn association() {
        let secret_value = [0x11; 32];
        let exp_id = [
            0x75, 0xad, 0x01, 0xb4, 0x03, 0xa9, 0xe4, 0x59, 0x5d, 0xf0, 0x7a, 0xce, 0x38, 0x12,
            0x97, 0x99, 0xdd, 0xad, 0x90, 0x8a, 0x8f, 0x82, 0xf9, 0xc3, 0x2c, 0xdd, 0x7d, 0x53,
            0xef, 0xc7, 0x3c, 0x62,
        ];
        let name = "association secret".to_string();
        let secret = GuestSecret::association("association secret", secret_value).unwrap();
        let exp = GuestSecret::Association {
            name,
            id: exp_id.into(),
            secret: secret_value.into(),
        };
        assert_eq!(secret, exp);
    }

    macro_rules! retr_test {
        ($name: ident, $func: ident, $size: expr, $exp_kind: expr) => {
            #[test]
            fn $name() {
                let secret_value = vec![0x11; $size];
                let name = "test retr secret".to_string();
                let secret = GuestSecret::$func(&name, secret_value.clone().into()).unwrap();
                let exp_id = [
                    0x61, 0x2c, 0xd6, 0x3e, 0xa8, 0xf2, 0xc1, 0x15, 0xc1, 0xe, 0x15, 0xb8, 0x8a,
                    0x90, 0x16, 0xc1, 0x55, 0xef, 0x9c, 0x7c, 0x2c, 0x8e, 0x56, 0xd0, 0x78, 0x4c,
                    0x8a, 0x1d, 0xc9, 0x3a, 0x80, 0xba,
                ];
                let exp = GuestSecret::Retrievable {
                    kind: $exp_kind,
                    name,
                    id: exp_id.into(),
                    secret: secret_value.into(),
                };
                assert_eq!(exp, secret);
            }
        };
    }

    retr_test!(retr_aes_128, aes, 16, Aes(AesSizes::Bits128));
    retr_test!(retr_aes_192, aes, 24, Aes(AesSizes::Bits192));
    retr_test!(retr_aes_256, aes, 32, Aes(AesSizes::Bits256));
    retr_test!(retr_aes_xts_128, aes_xts, 32, AesXts(AesXtsSizes::Bits128));
    retr_test!(retr_aes_xts_256, aes_xts, 64, AesXts(AesXtsSizes::Bits256));
    retr_test!(retr_aes_hmac_256, hmac_sha, 64, HmacSha(HmacSizes::Sha256));
    retr_test!(retr_aes_hmac_512, hmac_sha, 128, HmacSha(HmacSizes::Sha512));

    #[test]
    fn update_cck() {
        let new_cck = [11; 32];
        let req = GuestSecret::update_cck(new_cck);
        let exp = GuestSecret::UpdateCck {
            secret: new_cck.into(),
        };
        assert_eq!(req, exp);
    }

    #[test]
    fn plaintext_no_pad() {
        let key = vec![0, 14, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7];
        let name = "PLAINTEXT_PAD".to_string();
        let secret = GuestSecret::plaintext(&name, key[2..].to_vec().into()).unwrap();
        let exp_id = [
            15, 123, 176, 210, 135, 231, 220, 232, 148, 93, 198, 195, 165, 212, 214, 129, 45, 1,
            94, 11, 167, 18, 151, 15, 120, 254, 13, 109, 173, 186, 37, 74,
        ];
        let exp = GuestSecret::Retrievable {
            kind: PlainText,
            name,
            id: exp_id.into(),
            secret: key.into(),
        };

        assert_eq!(secret, exp);
    }

    #[test]
    fn plaintext_pad() {
        let key = vec![0, 10, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 0, 0, 0];
        let name = "PLAINTEXT_PAD".to_string();
        let secret = GuestSecret::plaintext(&name, key[2..12].to_vec().into()).unwrap();
        let exp_id = [
            15, 123, 176, 210, 135, 231, 220, 232, 148, 93, 198, 195, 165, 212, 214, 129, 45, 1,
            94, 11, 167, 18, 151, 15, 120, 254, 13, 109, 173, 186, 37, 74,
        ];
        let exp = GuestSecret::Retrievable {
            kind: PlainText,
            name,
            id: exp_id.into(),
            secret: key.into(),
        };

        assert_eq!(secret, exp);
    }

    #[track_caller]
    fn gen_ec(nid: Nid) -> PKey<Private> {
        let group = EcGroup::from_curve_name(nid).unwrap();
        let key = EcKey::generate(&group).unwrap();
        PKey::from_ec_key(key).unwrap()
    }

    #[track_caller]
    fn test_ec(grp: Nid, exp_kind: EcCurves, exp_len: usize) {
        let key = match grp {
            NID_ED25519 => PKey::generate_ed25519().unwrap(),
            NID_ED448 => PKey::generate_ed448().unwrap(),
            nid => gen_ec(nid),
        };
        let (kind, key) = ec(key).unwrap();

        assert_eq!(kind, Ec(exp_kind));
        assert_eq!(key.value().len(), exp_len);
    }

    #[test]
    fn retr_ec() {
        test_ec(Nid::X9_62_PRIME256V1, EcCurves::Secp256R1, 32);
        test_ec(Nid::SECP384R1, EcCurves::Secp384R1, 48);
        test_ec(Nid::SECP521R1, EcCurves::Secp521R1, 80);
        test_ec(NID_ED25519, EcCurves::Ed25519, 32);
        test_ec(NID_ED448, EcCurves::Ed448, 64);
    }

    #[test]
    fn retr_ec_pad() {
        let pkey = PKey::generate_ed448().unwrap();
        let (_, key) = ec(pkey).unwrap();
        assert_eq!(key.value()[..7], [0; 7]);

        let pkey = gen_ec(Nid::SECP521R1);
        let (_, key) = ec(pkey).unwrap();
        assert_eq!(key.value()[..14], [0; 14]);
    }

    #[test]
    fn asc_parse() {
        let id = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];
        let asc = GuestSecret::Association {
            name: "test123".to_string(),
            id: id.into(),
            secret: [0; 32].into(),
        };

        assert_tokens(
            &asc,
            &[
                Token::StructVariant {
                    name: "GuestSecret",
                    variant: "Association",
                    len: 2,
                },
                Token::String("name"),
                Token::String("test123"),
                Token::String("id"),
                Token::String("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
                Token::StructVariantEnd,
            ],
        );
    }

    #[test]
    fn retrievable_parse() {
        let id = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];
        let asc = GuestSecret::Retrievable {
            kind: PlainText,
            name: "test123".to_string(),
            id: id.into(),
            secret: vec![].into(),
        };

        assert_tokens(
            &asc,
            &[
                Token::StructVariant {
                    name: "GuestSecret",
                    variant: "Retrievable",
                    len: 3,
                },
                Token::String("kind"),
                Token::String("3 (PLAINTEXT)"),
                Token::String("name"),
                Token::String("test123"),
                Token::String("id"),
                Token::String("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
                Token::StructVariantEnd,
            ],
        );
    }

    #[test]
    fn update_cck_parse() {
        let cck = GuestSecret::UpdateCck {
            secret: [0; 32].into(),
        };
        assert_tokens(
            &cck,
            &[
                Token::StructVariant {
                    name: "GuestSecret",
                    variant: "UpdateCck",
                    len: 0,
                },
                Token::StructVariantEnd,
            ],
        )
    }

    #[test]
    fn guest_secret_bin_null() {
        let gs = GuestSecret::Null;
        let gs_bytes = gs.auth();
        let exp = vec![0u8, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        assert_eq!(exp, gs_bytes.get());
        assert_eq!(&Vec::<u8>::new(), gs.confidential())
    }

    #[test]
    fn guest_secret_bin_asoc() {
        let gs = GuestSecret::Association {
            name: "test".to_string(),
            id: [1; 32].into(),
            secret: [2; 32].into(),
        };
        let gs_bytes_auth = gs.auth();
        let mut exp = vec![0u8, 0, 0, 2, 0, 0, 0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0];
        exp.extend([1; 32]);

        assert_eq!(exp, gs_bytes_auth.get());
        assert_eq!(&[2; 32], gs.confidential());
    }

    #[test]
    fn guest_secret_bin_retr() {
        let gs = GuestSecret::Retrievable {
            kind: PlainText,
            name: "test".to_string(),
            id: [1; 32].into(),
            secret: vec![2; 32].into(),
        };
        let auth = gs.auth();
        let gs_bytes_auth = auth.get();
        let mut exp = vec![0u8, 0, 0, 3, 0, 0, 0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0];
        exp.extend([1; 32]);

        assert_eq!(exp, gs_bytes_auth);
        assert_eq!(&[2; 32], gs.confidential());
    }

    #[test]
    fn guest_secret_bin_cck() {
        let gs = GuestSecret::UpdateCck {
            secret: [2; 32].into(),
        };
        let gs_bytes_auth = gs.auth();
        let mut exp = vec![0u8, 0, 0, 0x16, 0, 0, 0, 0x20];
        exp.extend([0; 40]);

        assert_eq!(exp, gs_bytes_auth.get());
        assert_eq!(&[2; 32], gs.confidential());
    }
}
