// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024
use super::arcb::AttestationFlags;
use crate::req::Keyslot;
use crate::static_assert;
use crate::{Error, Result};
use serde::Serialize;
use std::fmt::Display;
use zerocopy::FromBytes;

/// Hash for additional-data stuff used for parsing [`AdditionalData`]
pub(crate) type AttAddHash = [u8; ATT_ADD_HASH_SIZE as usize];
pub(crate) const ATT_ADD_HASH_SIZE: u32 = 0x20;
static_assert!(Keyslot::PHKH_SIZE == ATT_ADD_HASH_SIZE);

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
        write_field(f, "Attestation PHKH", &self.attestation_phkh)
    }
}

fn read_hash<'a>(
    data: &'a [u8],
    read: bool,
    name: &'static str,
) -> Result<(Option<&'a AttAddHash>, &'a [u8])> {
    match read {
        true => {
            let (v, data) =
                AttAddHash::slice_from_prefix(data, 1).ok_or(Error::AddDataMissing(name))?;
            // slice from prefix ensures that there is 1 element.
            Ok((Some(&v[0]), data))
        }
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
}

impl<'a, T: Serialize + From<&'a [u8]> + Sized> AdditionalData<T> {
    /// Create Additional data from the u8-slice variant
    pub fn from_other(other: AdditionalData<&'a [u8]>) -> Self {
        let AdditionalData {
            image_phkh,
            attestation_phkh,
        } = other;
        Self {
            image_phkh: image_phkh.map(|i| i.into()),
            attestation_phkh: attestation_phkh.map(|i| i.into()),
        }
    }
}

impl<'a> AdditionalData<&'a [u8]> {
    /// Create from a slice of additional-data
    ///
    /// `flags`: Flags indicating which additional-data field is present.
    ///
    /// # Error
    ///
    /// Fails if there is a mismatch between the data and the flags. Should not happen after a
    /// successful attestation verification.
    pub fn from_slice(data: &'a [u8], flags: &AttestationFlags) -> Result<Self> {
        let _data = data;
        let (image_phkh, _data) = read_hash(data, flags.image_phkh(), "Image PHKH")?;
        let (attestation_phkh, _data) = read_hash(data, flags.attest_phkh(), "Attestation PHKH")?;

        Ok(Self {
            image_phkh: image_phkh.map(|v| v.as_slice()),
            attestation_phkh: attestation_phkh.map(|v| v.as_slice()),
        })
    }
}
