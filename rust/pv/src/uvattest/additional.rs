// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use serde::Serialize;
use std::fmt::Display;

use crate::req::Keyslot;
use crate::static_assert;
use crate::{Error, Result};

use super::arcb::AttestationFlags;

/// Hash for additional-data stuff used for parsing [`AdditionalData`]
pub(super) const PHKH_SIZE: u32 = 0x20;
static_assert!(Keyslot::PHKH_SIZE == PHKH_SIZE);

/// Struct describing the additional-data of an Attestation Request
#[derive(Serialize, Debug)]
#[serde(default)]
pub struct AdditionalData<T>
where
    T: Serialize,
{
    #[serde(skip_serializing_if = "Option::is_none")]
    image_phkh: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attestation_phkh: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    unrecognized: Option<T>,
}

impl<T> Display for AdditionalData<T>
where
    T: Display + Serialize,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn write_field<T: Display>(
            f: &mut std::fmt::Formatter<'_>,
            name: &'static str,
            s: &Option<T>,
        ) -> std::fmt::Result {
            if let Some(hash) = s {
                writeln!(f, "{name}")?;
                match f.alternate() {
                    true => writeln!(f, "{hash:#}")?,
                    false => writeln!(f, "{hash}")?,
                };
            }
            Ok(())
        }
        write_field(f, "Image PHKH", &self.image_phkh)?;
        write_field(f, "Attestation PHKH", &self.attestation_phkh)?;
        write_field(f, "Unrecognized", &self.unrecognized)?;
        Ok(())
    }
}

fn read_value<'a>(
    data: &'a [u8],
    size: u32,
    read: bool,
    name: &'static str,
) -> Result<(Option<&'a [u8]>, &'a [u8])> {
    let size = size as usize;
    match read {
        true if data.len() >= size => Ok((Some(&data[..size]), &data[size..])),
        true => Err(Error::AddDataMissing(name)),
        false => Ok((None, data)),
    }
}

impl<T: Serialize> AdditionalData<T> {
    /// Provides a reference to the image public host key hash.
    ///
    /// This is the hash of the public host key of the corresponding private machine key that
    /// decrypted the Secure Execution guest.
    /// Contains a value if that value was requested by the attestation request.
    pub fn image_public_host_key_hash(&self) -> Option<&T> {
        self.image_phkh.as_ref()
    }

    /// Provides a reference to the attestation public host key hash.
    ///
    /// This is the hash of the public host key of the corresponding private machine key that
    /// decrypted the Attestation request.
    /// Contains a value if that value was requested by the attestation request.
    pub fn attestation_public_host_key_hash(&self) -> Option<&T> {
        self.attestation_phkh.as_ref()
    }

    /// Provides a reference to the data not known by this implementation.
    pub fn unrecognized(&self) -> Option<&T> {
        self.unrecognized.as_ref()
    }
}

impl<'a, T: Serialize + From<&'a [u8]> + Sized> AdditionalData<T> {
    /// Create Additional data from the u8-slice variant
    pub fn from_other(other: AdditionalData<&'a [u8]>) -> Self {
        let AdditionalData {
            image_phkh,
            attestation_phkh,
            unrecognized,
        } = other;
        Self {
            image_phkh: image_phkh.map(|i| i.into()),
            attestation_phkh: attestation_phkh.map(|i| i.into()),
            unrecognized: unrecognized.map(|i| i.into()),
        }
    }
}

impl<'a> AdditionalData<&'a [u8]> {
    /// Create from a slice of additional-data
    ///
    /// `data`: Unstructured additional-data
    /// `flags`: Flags indicating which additional-data field is present.
    ///
    /// # Error
    ///
    /// Fails if there is a mismatch between the data and the flags. Should not happen after a
    /// successful attestation verification.
    pub fn from_slice(data: &'a [u8], flags: &AttestationFlags) -> Result<Self> {
        let (image_phkh, data) = read_value(data, PHKH_SIZE, flags.image_phkh(), "Image PHKH")?;
        let (attestation_phkh, data) =
            read_value(data, PHKH_SIZE, flags.attest_phkh(), "Attestation PHKH")?;
        let unrecognized = (!data.is_empty()).then_some(data);

        Ok(Self {
            image_phkh,
            attestation_phkh,
            unrecognized,
        })
    }
}

#[cfg(test)]
mod test {
    use serde_test::Token;

    use super::*;
    #[test]
    fn ser() {
        let add = AdditionalData {
            image_phkh: 0_u8.into(),
            attestation_phkh: 1_u8.into(),
            unrecognized: 2_u8.into(),
        };

        serde_test::assert_ser_tokens(
            &add,
            &[
                Token::Struct {
                    name: "AdditionalData",
                    len: 3,
                },
                Token::Str("image_phkh"),
                Token::Some,
                Token::U8(0),
                Token::Str("attestation_phkh"),
                Token::Some,
                Token::U8(1),
                Token::Str("unrecognized"),
                Token::Some,
                Token::U8(2),
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn ser_no_att() {
        let add = AdditionalData {
            image_phkh: 0_u8.into(),
            attestation_phkh: None,
            unrecognized: 2_u8.into(),
        };

        serde_test::assert_ser_tokens(
            &add,
            &[
                Token::Struct {
                    name: "AdditionalData",
                    len: 2,
                },
                Token::Str("image_phkh"),
                Token::Some,
                Token::U8(0),
                Token::Str("unrecognized"),
                Token::Some,
                Token::U8(2),
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn ser_no_unrec() {
        let add = AdditionalData {
            image_phkh: 0_u8.into(),
            attestation_phkh: 1_u8.into(),
            unrecognized: None,
        };

        serde_test::assert_ser_tokens(
            &add,
            &[
                Token::Struct {
                    name: "AdditionalData",
                    len: 2,
                },
                Token::Str("image_phkh"),
                Token::Some,
                Token::U8(0),
                Token::Str("attestation_phkh"),
                Token::Some,
                Token::U8(1),
                Token::StructEnd,
            ],
        );
    }
    #[test]
    fn ser_no() {
        let add: AdditionalData<u8> = AdditionalData {
            image_phkh: None,
            attestation_phkh: None,
            unrecognized: None,
        };

        serde_test::assert_ser_tokens(
            &add,
            &[
                Token::Struct {
                    name: "AdditionalData",
                    len: 0,
                },
                Token::StructEnd,
            ],
        );
    }
}
