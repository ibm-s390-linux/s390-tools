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
use serde::{Deserialize, Serialize};

use crate::{
    error::{Error, Result},
    pv_utils::{serializing::serde_hex_array, try_copy_slice_to_array},
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

#[derive(Debug, Clone, PartialEq, Eq, DekuRead, DekuWrite, Serialize, Deserialize)]
#[deku(endian = "endian", ctx = "endian: Endian", ctx_default = "Endian::Big")]
pub struct EcPubKeyCoordV1 {
    #[serde(with = "serde_hex_array", rename = "coord_hex")]
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
#[derive(Default, Debug, PartialEq, Eq, Clone, DekuRead, DekuWrite, Serialize, Deserialize)]
#[deku(endian = "endian", ctx = "endian: Endian", ctx_default = "Endian::Big")]
/// Binary key slot v1
pub struct BinaryKeySlotV1 {
    #[serde(with = "serde_hex_array", rename = "phkh_hex")]
    /// Public host key hash
    pub phkh: [u8; 32],
    /// Wrapper key
    #[serde(with = "serde_hex_array", rename = "wrpk_hex")]
    pub wrpk: [u8; 32],
    /// Tag
    #[serde(with = "serde_hex_array", rename = "kst_hex")]
    pub kst: [u8; 16],
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

#[cfg(test)]
mod serde_tests {
    use super::*;

    #[test]
    fn roundtrip_ecpubkey_json() {
        let key = EcPubKeyCoordV1 { coord: [0x42; 160] };

        let json = serde_json::to_string(&key).expect("should serialize");
        assert_eq!(json,
            "{\"coord_hex\":\"42424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242\"}");
        let deserialized: EcPubKeyCoordV1 =
            serde_json::from_str(&json).expect("should deserialize");

        assert_eq!(key, deserialized);
    }

    #[test]
    fn roundtrip_keyslots_json() {
        let keyslots = vec![
            BinaryKeySlotV1 {
                phkh: [0x01; 32],
                wrpk: [0x02; 32],
                kst: [0x03; 16],
            },
            BinaryKeySlotV1 {
                phkh: [0x03; 32],
                wrpk: [0x04; 32],
                kst: [0x05; 16],
            },
        ];

        let json = serde_json::to_string(&keyslots).expect("should serialize");
        assert_eq!(json, "[{\"phkh_hex\":\"0101010101010101010101010101010101010101010101010101010101010101\",\"wrpk_hex\":\"0202020202020202020202020202020202020202020202020202020202020202\",\"kst_hex\":\"03030303030303030303030303030303\"},{\"phkh_hex\":\"0303030303030303030303030303030303030303030303030303030303030303\",\"wrpk_hex\":\"0404040404040404040404040404040404040404040404040404040404040404\",\"kst_hex\":\"05050505050505050505050505050505\"}]");
        let deserialized: Vec<BinaryKeySlotV1> =
            serde_json::from_str(&json).expect("should deserialize");

        assert_eq!(keyslots, deserialized);
    }
}
