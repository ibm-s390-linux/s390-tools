// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use std::mem::size_of;

use deku::{ctx::Endian, DekuRead, DekuWrite};
use openssl::{
    hash::{hash, MessageDigest},
    pkey::{PKey, PKeyRef, Public},
};
use pv::{request::EcPubKeyCoord, static_assert};
use serde::Serialize;

use crate::{
    error::{Error, Result},
    pv_utils::{serializing::ser_hex, try_copy_slice_to_array},
};

/// Try to hash the public EC key.
///
/// # Errors
///
/// This function will return an error if OpenSSL could not hash the key.
pub fn phkh_v1<T: AsRef<PKeyRef<Public>>>(key: T) -> Result<[u8; 32]> {
    let phk: EcPubKeyCoord = key.as_ref().try_into()?;
    let binding = hash(MessageDigest::sha256(), phk.as_ref())?;
    try_copy_slice_to_array(&binding)
}

#[derive(Debug, Clone, PartialEq, Eq, DekuRead, DekuWrite, Serialize)]
#[deku(endian = "endian", ctx = "endian: Endian", ctx_default = "Endian::Big")]
pub struct EcPubKeyCoordV1 {
    #[serde(serialize_with = "ser_hex")]
    pub coord: [u8; 160],
}

#[allow(clippy::fallible_impl_from)]
impl From<EcPubKeyCoord> for EcPubKeyCoordV1 {
    fn from(value: EcPubKeyCoord) -> Self {
        // SAFETY: `EcPubKeyCoord` has the same struct definition as
        //         `EcPubKeyCooardV1`.
        let coord = try_copy_slice_to_array(value.as_ref()).unwrap();
        Self { coord }
    }
}

#[allow(clippy::fallible_impl_from)]
impl From<EcPubKeyCoordV1> for EcPubKeyCoord {
    fn from(value: EcPubKeyCoordV1) -> Self {
        // SAFETY: `EcPubKeyCoord` has the same struct definition as
        //          `EcPubKeyCooardV1`.
        let coord = try_copy_slice_to_array(&value.coord).unwrap();
        // SAFETY: This call is safe because we do not expect, that
        //         EcPubKeyCoord is always a valid EC pub key.
        unsafe { Self::from_data(coord) }
    }
}

impl TryFrom<EcPubKeyCoordV1> for PKey<Public> {
    type Error = Error;

    fn try_from(value: EcPubKeyCoordV1) -> Result<Self, Error> {
        <EcPubKeyCoordV1 as Into<EcPubKeyCoord>>::into(value)
            .try_into()
            .map_err(Error::Crypto)
    }
}

#[repr(C)]
#[derive(Default, Debug, PartialEq, Eq, Clone, DekuRead, DekuWrite, Serialize)]
#[deku(endian = "endian", ctx = "endian: Endian", ctx_default = "Endian::Big")]
/// Binary key slot v1
pub struct BinaryKeySlotV1 {
    #[serde(serialize_with = "ser_hex")]
    /// Public host key hash
    pub(crate) phkh: [u8; 32],
    /// Wrapper key
    #[serde(serialize_with = "ser_hex")]
    pub(crate) wrpk: [u8; 32],
    /// Tag
    #[serde(serialize_with = "ser_hex")]
    pub(crate) kst: [u8; 16],
}
static_assert!(size_of::<BinaryKeySlotV1>() == 80);

impl TryFrom<Vec<u8>> for BinaryKeySlotV1 {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let data: [u8; 80] = try_copy_slice_to_array(&value)?;
        let bin = Self {
            phkh: data[..32].try_into().unwrap(),
            wrpk: data[32..64].try_into().unwrap(),
            kst: data[64..].try_into().unwrap(),
        };
        Ok(bin)
    }
}
