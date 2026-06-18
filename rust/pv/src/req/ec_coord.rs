// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp.

use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcGroupRef, EcKey, EcPointRef};
use openssl::error::ErrorStack;
use openssl::hash::{DigestBytes, MessageDigest};
use openssl::nid::Nid;
use openssl::pkey::{PKey, PKeyRef, Private, Public};

use crate::crypto::hash;
use crate::Result;

/// Public key components of an [`openssl::ec::EcKey`] key.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct EcPubKeyCoord([u8; 160]);

impl AsRef<[u8]> for EcPubKeyCoord {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

const ECDH_PUB_KEY_COORD_POINT_SIZE: usize = 0x50;

impl EcPubKeyCoord {
    /// Returns the SHA256 hash of the [`EcPubKeyCoord`].
    ///
    /// If [`EcPubKeyCoord`] was built from a host-key, this value is the public host-key hash.
    pub fn sha256(&self) -> Result<DigestBytes> {
        hash(MessageDigest::sha256(), self.as_ref())
    }

    /// Construct a [`EcPubKeyCoord`]
    ///
    /// # Safety
    /// This function is marked unsafe, because data not representing two EC points violates the
    /// invariant of this struct.
    pub unsafe fn from_data(data: [u8; 160]) -> Self {
        EcPubKeyCoord(data)
    }
}

/// Get the pub ECDH coordinates in the format the Ultravisor expects it:
/// The two coordinates are padded to 80 bytes each.
fn get_pub_ecdh_points(pkey: &EcPointRef, grp: &EcGroupRef) -> Result<[u8; 160], ErrorStack> {
    let mut x = BigNum::new()?;
    let mut y = BigNum::new()?;
    let mut bn_ctx = BigNumContext::new()?;
    pkey.affine_coordinates(grp, &mut x, &mut y, &mut bn_ctx)?;
    let mut coord: Vec<u8> = x.to_vec_padded(ECDH_PUB_KEY_COORD_POINT_SIZE as i32)?;
    coord.append(&mut y.to_vec_padded(ECDH_PUB_KEY_COORD_POINT_SIZE as i32)?);
    Ok(coord.try_into().unwrap())
}

impl TryFrom<EcPubKeyCoord> for PKey<Public> {
    type Error = ErrorStack;

    fn try_from(value: EcPubKeyCoord) -> Result<Self, Self::Error> {
        let ecdh = value.as_ref();
        let grp = EcGroup::from_curve_name(Nid::SECP521R1)?;
        let x = BigNum::from_slice(&ecdh[..ECDH_PUB_KEY_COORD_POINT_SIZE])?;
        let y = BigNum::from_slice(&ecdh[ECDH_PUB_KEY_COORD_POINT_SIZE..])?;
        let ec_key = EcKey::from_public_key_affine_coordinates(&grp, &x, &y)?;
        Self::from_ec_key(ec_key)
    }
}

macro_rules! ecdh_from {
    ($type: ty) => {
        impl TryFrom<&PKeyRef<$type>> for EcPubKeyCoord {
            type Error = ErrorStack;

            fn try_from(key: &PKeyRef<$type>) -> Result<Self, Self::Error> {
                let k = key.ec_key()?;
                k.check_key()?;
                let grp = k.group();
                let pub_key = k.public_key();
                let coord = get_pub_ecdh_points(pub_key, grp)?;
                Ok(Self(coord))
            }
        }

        impl TryFrom<PKey<$type>> for EcPubKeyCoord {
            type Error = ErrorStack;

            fn try_from(key: PKey<$type>) -> Result<Self, Self::Error> {
                let key_ref = key.as_ref();
                key_ref.try_into()
            }
        }
    };
}

ecdh_from!(Private);
ecdh_from!(Public);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::get_test_asset;
    use crate::test_utils::*;

    #[test]
    fn ec_pub_ec_coord_from() {
        let (cust_key, _) = get_test_keys();
        let pub_key = get_test_asset!("keys/public_cust.bin");
        assert_eq!(pub_key.len(), 160);

        let ec_coord: EcPubKeyCoord = cust_key.as_ref().try_into().unwrap();
        assert_eq!(ec_coord.as_ref(), pub_key);
    }

    #[test]
    fn ec_pub_ec_coord_hash() {
        let exp = [
            0x5e, 0xe9, 0x05, 0xa9, 0xbe, 0x70, 0x36, 0x68, 0x15, 0xa4, 0x56, 0x41, 0xaf, 0xae,
            0x00, 0x97, 0x3b, 0x1f, 0x45, 0x29, 0x2f, 0x43, 0xbc, 0xd7, 0x63, 0x8e, 0xe2, 0xa7,
            0x3f, 0xd7, 0xc4, 0x5e,
        ];
        let (cust_key, _) = get_test_keys();
        let ec_coord: EcPubKeyCoord = cust_key.as_ref().try_into().unwrap();
        let hash = ec_coord.sha256().unwrap();

        assert_eq!(hash.as_ref(), &exp);
    }

    #[test]
    fn conversion_ecdh_and_vice_versa() {
        let (_, cust_pub) = get_test_keys();
        let phk: EcPubKeyCoord = cust_pub.clone().try_into().unwrap();

        assert_eq!(
            phk.as_ref(),
            &[
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 118, 136, 28, 216, 75, 139, 109, 231,
                18, 60, 126, 144, 14, 223, 120, 231, 247, 182, 132, 153, 145, 70, 177, 38, 59, 168,
                184, 108, 132, 71, 240, 138, 182, 212, 105, 194, 177, 40, 237, 158, 28, 53, 1, 88,
                5, 172, 211, 211, 2, 51, 211, 145, 34, 247, 226, 248, 170, 28, 43, 20, 123, 120,
                131, 180, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 195, 69, 86, 194, 92,
                249, 47, 41, 206, 102, 189, 68, 17, 77, 107, 123, 60, 120, 225, 58, 63, 144, 189,
                185, 0, 64, 246, 135, 110, 82, 98, 247, 120, 166, 26, 147, 125, 27, 52, 128, 46,
                178, 87, 227, 78, 6, 114, 221, 95, 42, 52, 122, 221, 170, 40, 32, 53, 9, 42, 112,
                195, 92, 46, 121, 115
            ]
        );
        let cust_pub_back: PKey<Public> = phk.try_into().unwrap();
        assert!(cust_pub.public_eq(&cust_pub_back));
    }
}
