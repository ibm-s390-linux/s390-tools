// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

#[allow(unused_imports)] // used for more convenient docstring
use super::asrcb::AddSecretRequest;
use crate::assert_size;
use crate::{
    crypto::{hash, random_array},
    request::Confidential,
    Result,
};
use byteorder::BigEndian;
use openssl::hash::MessageDigest;
use pv_core::uv::{ListableSecretType, SecretId};
use serde::{Deserialize, Serialize};
use std::{convert::TryInto, fmt::Display};
use zerocopy::{AsBytes, U16, U32};

const ASSOC_SECRET_SIZE: usize = 32;

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
}

impl GuestSecret {
    /// Create a new [`GuestSecret::Association`].
    ///
    /// * `name` - Name of the secret. Will be hashed into a 32 byte id
    /// * `secret` - Value of the secret. Ranom if [`Option::None`]
    ///
    /// # Errors
    ///
    /// This function will return an error if OpenSSL cannot create a hash.
    pub fn association<O>(name: &str, secret: O) -> Result<GuestSecret>
    where
        O: Into<Option<[u8; ASSOC_SECRET_SIZE]>>,
    {
        let id: [u8; SecretId::ID_SIZE] = hash(MessageDigest::sha256(), name.as_bytes())?
            .to_vec()
            .try_into()
            .unwrap();
        let secret = match secret.into() {
            Some(s) => s,
            None => random_array()?,
        };

        Ok(GuestSecret::Association {
            name: name.to_string(),
            id: id.into(),
            secret: secret.into(),
        })
    }

    /// Reference to the confidential data
    pub(crate) fn confidential(&self) -> &[u8] {
        match &self {
            GuestSecret::Null => &[],
            GuestSecret::Association { secret, .. } => secret.value().as_slice(),
        }
    }

    /// Creates the non-confidential part of the secret ad-hoc
    pub(crate) fn auth(&self) -> SecretAuth {
        match &self {
            GuestSecret::Null => SecretAuth::Null,
            // Panic:  every non null secret type is listable -> no panic
            listable => {
                SecretAuth::Listable(ListableSecretHdr::from_guest_secret(listable).unwrap())
            }
        }
    }

    /// Returns the UV type ID
    fn kind(&self) -> u16 {
        match self {
            // Null is not listable, but the ListableSecretType provides the type constant (1)
            GuestSecret::Null => ListableSecretType::NULL,
            GuestSecret::Association { .. } => ListableSecretType::ASSOCIATION,
        }
    }

    /// Size of the secret value
    fn secret_len(&self) -> u32 {
        match self {
            GuestSecret::Null => 0,
            GuestSecret::Association { secret, .. } => secret.value().len() as u32,
        }
    }

    /// Returns the ID of the secret type (if any)
    fn id(&self) -> Option<SecretId> {
        match self {
            GuestSecret::Null => None,
            GuestSecret::Association { id, .. } => Some(id.to_owned()),
        }
    }
}

impl Display for GuestSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuestSecret::Null => write!(f, "Meta"),
            gs => {
                let kind: U16<BigEndian> = gs.kind().into();
                let st: ListableSecretType = kind.into();
                write!(f, "{st}")
            }
        }
    }
}

#[derive(Debug)]
pub(crate) enum SecretAuth {
    Null,
    Listable(ListableSecretHdr),
}

impl SecretAuth {
    pub fn get(&self) -> &[u8] {
        match self {
            SecretAuth::Null => &[0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            SecretAuth::Listable(h) => h.as_bytes(),
        }
    }
}

#[repr(C)]
#[derive(Debug, AsBytes)]
pub(crate) struct ListableSecretHdr {
    res0: u16,
    kind: U16<BigEndian>,
    secret_len: U32<BigEndian>,
    res8: u64,
    id: SecretId,
}
assert_size!(ListableSecretHdr, 0x30);

impl ListableSecretHdr {
    fn from_guest_secret(gs: &GuestSecret) -> Option<Self> {
        let id = gs.id()?;
        Some(Self {
            res0: 0,
            kind: gs.kind().into(),
            secret_len: gs.secret_len().into(),
            res8: 0,
            id,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
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

    #[test]
    fn ap_asc_parse() {
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
    fn guest_secret_bin_null() {
        let gs = GuestSecret::Null;
        let gs_bytes = gs.auth();
        let exp = vec![0u8, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        assert_eq!(exp, gs_bytes.get());
        assert_eq!(&Vec::<u8>::new(), gs.confidential())
    }

    #[test]
    fn guest_secret_bin_ap() {
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
}
