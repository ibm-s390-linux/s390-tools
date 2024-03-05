// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use crate::uv::{ListableSecretType, RetrieveCmd};
use serde::{Deserialize, Serialize, Serializer};
use std::fmt::Display;

/// Allowed sizes for AES keys
#[non_exhaustive]
#[derive(PartialEq, Eq, Debug)]
pub enum AesSizes {
    /// 128 bit key
    Bits128,
    /// 192 bit key
    Bits192,
    /// 256 bit key
    Bits256,
}

impl AesSizes {
    /// Construct the key-size from the bit-size.
    ///
    /// Returns [`None`] if the bit-size is not supported.
    pub fn from_bits(bits: u32) -> Option<Self> {
        match bits {
            128 => Some(Self::Bits128),
            192 => Some(Self::Bits192),
            256 => Some(Self::Bits256),
            _ => None,
        }
    }

    /// Returns the bit-size for the key-type
    const fn bit_size(&self) -> u32 {
        match self {
            Self::Bits128 => 128,
            Self::Bits192 => 192,
            Self::Bits256 => 256,
        }
    }
}

impl Display for AesSizes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.bit_size())
    }
}

/// Allowed sizes for AES-XTS keys
#[non_exhaustive]
#[derive(PartialEq, Eq, Debug)]
pub enum AesXtsSizes {
    /// Two AES 128 bit keys
    Bits128,
    /// Two AES 256 bit keys
    Bits256,
}

impl AesXtsSizes {
    /// Construct the key-size from the bit-size.
    ///
    /// It's a key containing two keys; bit-size is half the number of bits it has
    /// Returns [`None`] if the bit-size is not supported.
    pub fn from_bits(bits: u32) -> Option<Self> {
        match bits {
            128 => Some(Self::Bits128),
            256 => Some(Self::Bits256),
            _ => None,
        }
    }

    /// Returns the bit-size for the key-type
    ///
    /// It's a key containing two keys: bit-size is half the number of bits it has
    const fn bit_size(&self) -> u32 {
        match self {
            Self::Bits128 => 128,
            Self::Bits256 => 256,
        }
    }
}

impl Display for AesXtsSizes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.bit_size())
    }
}

/// Allowed sizes for HMAC-SHA keys
#[non_exhaustive]
#[derive(PartialEq, Eq, Debug)]
pub enum HmacShaSizes {
    /// SHA 256 bit
    Sha256,
    /// SHA 512 bit
    Sha512,
}

impl HmacShaSizes {
    /// Construct the key-size from the sha-size.
    ///
    /// FW expects maximum resistance keys (double the SHA size).
    /// The `sha_size` is half of the number of bits in the key
    /// Returns [`None`] if the `sha_size` is not supported.
    pub fn from_sha_size(sha_size: u32) -> Option<Self> {
        match sha_size {
            256 => Some(Self::Sha256),
            512 => Some(Self::Sha512),
            _ => None,
        }
    }

    /// Returns the sha-size for the key-type
    ///
    /// FW expects maximum resistance keys (double the SHA size).
    /// The `sha_size` is half of the number of bits in the key
    const fn sha_size(&self) -> u32 {
        match self {
            Self::Sha256 => 256,
            Self::Sha512 => 512,
        }
    }
}

impl Display for HmacShaSizes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.sha_size())
    }
}

/// Allowed curves for EC private keys
#[non_exhaustive]
#[derive(PartialEq, Eq, Debug)]
pub enum EcCurves {
    /// secp256r1 or prime256v1 curve
    Secp256R1,
    /// secp384p1 curve
    Secp384R1,
    /// secp521r1 curve
    Secp521R1,
    /// ed25519 curve
    Ed25519,
    /// ed448 curve
    Ed448,
}

impl EcCurves {
    const fn exp_size(&self) -> usize {
        match self {
            Self::Secp256R1 => 32,
            Self::Secp384R1 => 48,
            Self::Secp521R1 => 80,
            Self::Ed25519 => 32,
            Self::Ed448 => 64,
        }
    }

    /// Resizes the raw key to the expected size.
    ///
    /// See [`Vec::resize`]
    pub fn resize_raw_key(&self, mut raw: Vec<u8>) -> Vec<u8> {
        raw.resize(self.exp_size(), 0);
        raw
    }
}

// The names have to stay constant, otherwise the PEM contains invalid types
impl Display for EcCurves {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Secp256R1 => write!(f, "SECP256R1"),
            Self::Secp384R1 => write!(f, "SECP384R1"),
            Self::Secp521R1 => write!(f, "SECP521R1"),
            Self::Ed25519 => write!(f, "ED25519"),
            Self::Ed448 => write!(f, "ED448"),
        }
    }
}

/// Retrievable Secret types
#[non_exhaustive]
#[derive(PartialEq, Eq, Debug)]
pub enum RetrievableSecret {
    /// Plain-text secret
    PlainText,
    /// Protected AES key
    Aes(AesSizes),
    /// Protected AES-XTS key
    AesXts(AesXtsSizes),
    /// Protected HMAC-SHA key
    HmacSha(HmacShaSizes),
    /// Protected EC-private key
    Ec(EcCurves),
}

// The names have to stay constant, otherwise the PEM contains invalid/unknown types
impl Display for RetrievableSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Alternate representation: Omit sizes/curves
        if f.alternate() {
            match self {
                Self::PlainText => write!(f, "PLAINTEXT"),
                Self::Aes(_) => write!(f, "AES-KEY"),
                Self::AesXts(_) => write!(f, "AES-XTS-KEY"),
                Self::HmacSha(_) => write!(f, "HMAC-SHA-KEY"),
                Self::Ec(_) => write!(f, "EC-PRIVATE-KEY"),
            }
        } else {
            match self {
                Self::PlainText => write!(f, "PLAINTEXT"),
                Self::Aes(s) => write!(f, "AES-{s}-KEY"),
                Self::AesXts(s) => write!(f, "AES-XTS-{s}-KEY"),
                Self::HmacSha(s) => write!(f, "HMAC-SHA-{s}-KEY"),
                Self::Ec(c) => write!(f, "EC-{c}-PRIVATE-KEY"),
            }
        }
    }
}

impl RetrievableSecret {
    /// Report expected input types
    pub fn expected(&self) -> String {
        match self {
            Self::PlainText => format!("less than {}", RetrieveCmd::MAX_SIZE),
            Self::Aes(_) => "128, 192, or 256".to_string(),
            Self::AesXts(_) => "128 or 256".to_string(),
            Self::HmacSha(_) => "256 or 512".to_string(),
            Self::Ec(_) => "secp256r1, secp384r1, secp521r1, ed25519, or ed448".to_string(),
        }
    }
}

impl From<&RetrievableSecret> for u16 {
    fn from(value: &RetrievableSecret) -> Self {
        match value {
            RetrievableSecret::PlainText => ListableSecretType::PLAINTEXT,
            RetrievableSecret::Aes(AesSizes::Bits128) => ListableSecretType::AES_128_KEY,
            RetrievableSecret::Aes(AesSizes::Bits192) => ListableSecretType::AES_192_KEY,
            RetrievableSecret::Aes(AesSizes::Bits256) => ListableSecretType::AES_256_KEY,
            RetrievableSecret::AesXts(AesXtsSizes::Bits128) => ListableSecretType::AES_128_XTS_KEY,
            RetrievableSecret::AesXts(AesXtsSizes::Bits256) => ListableSecretType::AES_256_XTS_KEY,
            RetrievableSecret::HmacSha(HmacShaSizes::Sha256) => {
                ListableSecretType::HMAC_SHA_256_KEY
            }
            RetrievableSecret::HmacSha(HmacShaSizes::Sha512) => {
                ListableSecretType::HMAC_SHA_512_KEY
            }
            RetrievableSecret::Ec(EcCurves::Secp256R1) => ListableSecretType::ECDSA_P256_KEY,
            RetrievableSecret::Ec(EcCurves::Secp384R1) => ListableSecretType::ECDSA_P384_KEY,
            RetrievableSecret::Ec(EcCurves::Secp521R1) => ListableSecretType::ECDSA_P521_KEY,
            RetrievableSecret::Ec(EcCurves::Ed25519) => ListableSecretType::ECDSA_ED25519_KEY,
            RetrievableSecret::Ec(EcCurves::Ed448) => ListableSecretType::ECDSA_ED448_KEY,
        }
    }
}

// serializes to: <secret type nb> (String name)
impl Serialize for RetrievableSecret {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let id: u16 = self.into();
        serializer.serialize_str(&format!("{id} ({self})"))
    }
}

/// deserializes from the secret type nb only
impl<'de> Deserialize<'de> for RetrievableSecret {
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct RetrSecretVisitor;
        impl<'de> serde::de::Visitor<'de> for RetrSecretVisitor {
            type Value = RetrievableSecret;

            fn expecting(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
                fmt.write_str(
                    "a retrievable secret type: `<number> (String name)` number in [3,10]|[17,21]",
                )
            }
            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let (n, _) = s.split_once(' ').ok_or(serde::de::Error::invalid_value(
                    serde::de::Unexpected::Str(s),
                    &self,
                ))?;
                let id: u16 = n.parse().map_err(|_| {
                    serde::de::Error::invalid_value(serde::de::Unexpected::Str(n), &self)
                })?;
                let listable: ListableSecretType = id.into();
                match listable {
                    ListableSecretType::Retrievable(r) => Ok(r),
                    _ => Err(serde::de::Error::invalid_value(
                        serde::de::Unexpected::Unsigned(id.into()),
                        &self,
                    )),
                }
            }
        }
        de.deserialize_str(RetrSecretVisitor)
    }
}

#[cfg(test)]
mod test {
    use serde_test::{assert_tokens, Token};

    use super::*;

    #[test]
    fn retr_serde_plain() {
        let retr = RetrievableSecret::PlainText;
        assert_tokens(&retr, &[Token::Str("3 (PLAINTEXT)")]);
    }

    #[test]
    fn retr_serde_aes() {
        let retr = RetrievableSecret::Aes(AesSizes::Bits192);
        assert_tokens(&retr, &[Token::Str("5 (AES-192-KEY)")]);
    }

    #[test]
    fn retr_serde_aes_xts() {
        let retr = RetrievableSecret::AesXts(AesXtsSizes::Bits128);
        assert_tokens(&retr, &[Token::Str("7 (AES-XTS-128-KEY)")]);
    }

    #[test]
    fn retr_serde_hmac() {
        let retr = RetrievableSecret::HmacSha(HmacShaSizes::Sha256);
        assert_tokens(&retr, &[Token::Str("9 (HMAC-SHA-256-KEY)")]);
    }

    #[test]
    fn retr_serde_es() {
        let retr = RetrievableSecret::Ec(EcCurves::Secp521R1);
        assert_tokens(&retr, &[Token::Str("19 (EC-SECP521R1-PRIVATE-KEY)")]);
    }

    // Ensure that the string representation of the retrievable types stay constant, or PEM will have
    // different, incompatible types
    #[test]
    fn stable_type_names() {
        assert_eq!("PLAINTEXT", RetrievableSecret::PlainText.to_string());
        assert_eq!(
            "AES-128-KEY",
            RetrievableSecret::Aes(AesSizes::Bits128).to_string()
        );
        assert_eq!(
            "AES-192-KEY",
            RetrievableSecret::Aes(AesSizes::Bits192).to_string()
        );
        assert_eq!(
            "AES-256-KEY",
            RetrievableSecret::Aes(AesSizes::Bits256).to_string()
        );
        assert_eq!(
            "AES-XTS-128-KEY",
            RetrievableSecret::AesXts(AesXtsSizes::Bits128).to_string()
        );
        assert_eq!(
            "AES-XTS-256-KEY",
            RetrievableSecret::AesXts(AesXtsSizes::Bits256).to_string()
        );
        assert_eq!(
            "HMAC-SHA-256-KEY",
            RetrievableSecret::HmacSha(HmacShaSizes::Sha256).to_string()
        );
        assert_eq!(
            "HMAC-SHA-512-KEY",
            RetrievableSecret::HmacSha(HmacShaSizes::Sha512).to_string()
        );
        assert_eq!(
            "EC-SECP256R1-PRIVATE-KEY",
            RetrievableSecret::Ec(EcCurves::Secp256R1).to_string()
        );
        assert_eq!(
            "EC-SECP384R1-PRIVATE-KEY",
            RetrievableSecret::Ec(EcCurves::Secp384R1).to_string()
        );
        assert_eq!(
            "EC-SECP521R1-PRIVATE-KEY",
            RetrievableSecret::Ec(EcCurves::Secp521R1).to_string()
        );
        assert_eq!(
            "EC-ED25519-PRIVATE-KEY",
            RetrievableSecret::Ec(EcCurves::Ed25519).to_string()
        );
        assert_eq!(
            "EC-ED448-PRIVATE-KEY",
            RetrievableSecret::Ec(EcCurves::Ed448).to_string()
        );
    }
}
