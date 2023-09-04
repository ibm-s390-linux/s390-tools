// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

#[allow(unused_imports)] //used for more convenient docstring
use super::asrcb::AddSecretRequest;
use super::{ser_gsid, SECRET_ID_SIZE};
use crate::{
    request::{hash, openssl::MessageDigest, random_array, Secret},
    requires_feat, Result,
};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

const SECRET_SIZE: usize = 32;
/// A Secret to be added in [`AddSecretRequest`]
///
#[doc = requires_feat!(reqsecret)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GuestSecret {
    /// No guest secret
    Null,
    /// Association secret used to associate an extension card to a SE guest
    ///
    /// Create Associations using [`GuestSecret::association`]
    Association {
        /// Name of the secret
        name: String,
        #[serde(serialize_with = "ser_gsid", deserialize_with = "de_gsid")]
        /// SHA256 hash of [`GuestSecret::Association::name`]
        id: [u8; SECRET_ID_SIZE],
        /// Confidential actual assocuiation secret (32 bytes)
        #[serde(skip)]
        secret: Secret<[u8; SECRET_SIZE]>,
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
        O: Into<Option<[u8; SECRET_SIZE]>>,
    {
        let id = hash(MessageDigest::sha256(), name.as_bytes())?.to_vec();
        let secret = match secret.into() {
            Some(s) => s,
            None => random_array()?,
        };

        Ok(GuestSecret::Association {
            name: name.to_string(),
            id: id.try_into().unwrap(),
            secret: secret.into(),
        })
    }
}
fn de_gsid<'de, D>(de: D) -> Result<[u8; 32], D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct FieldVisitor;

    impl<'de> serde::de::Visitor<'de> for FieldVisitor {
        type Value = [u8; SECRET_ID_SIZE];
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a `32 bytes long hexstring` prepended with 0x")
        }
        fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if s.len() != SECRET_ID_SIZE * 2 + 2 {
                return Err(serde::de::Error::invalid_length(s.len(), &self));
            }
            let nb = s.strip_prefix("0x").ok_or_else(|| {
                serde::de::Error::invalid_value(serde::de::Unexpected::Str(s), &self)
            })?;
            crate::misc::parse_hex(nb)
                .try_into()
                .map_err(|_| serde::de::Error::invalid_value(serde::de::Unexpected::Str(s), &self))
        }
    }
    de.deserialize_identifier(FieldVisitor)
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_test::{assert_tokens, Token};

    //todo test GuestSecret::association
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
            id: exp_id,
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
            id,
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
}
