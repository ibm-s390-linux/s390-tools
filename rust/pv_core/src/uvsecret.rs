// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

use crate::assert_size;
use crate::{
    request::{MagicValue, RequestMagic},
    Error, Result,
};
use byteorder::ByteOrder;
use std::{fmt::Display, mem::size_of};
use zerocopy::{BigEndian, Immutable, IntoBytes, U16};

/// The magic value used to identify an `AddSecretRequest`.
///
/// The magic value is ASCII:
/// ```rust
/// # use s390_pv_core::secret::AddSecretMagic;
/// # use s390_pv_core::request::MagicValue;
/// # fn main() {
/// # let magic =
/// b"asrcbM"
/// # ;
/// # assert!(AddSecretMagic::starts_with_magic(magic));
/// # }
/// ```
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoBytes, Immutable)]
pub struct AddSecretMagic {
    magic: [u8; 6], // [0x61, 0x73, 0x72, 0x63, 0x62, 0x4D]
    kind: U16<BigEndian>,
}
assert_size!(AddSecretMagic, 8);

impl MagicValue<6> for AddSecretMagic {
    // "asrcbM"
    const MAGIC: [u8; 6] = [0x61, 0x73, 0x72, 0x63, 0x62, 0x4D];
}

impl AddSecretMagic {
    /// Get the magic value.
    pub fn get(&self) -> RequestMagic {
        let mut res = RequestMagic::default();
        debug_assert!(res.len() == size_of::<Self>());
        // Panic: does not panic, buf is 8 bytes long
        self.write_to(&mut res).unwrap();
        res
    }

    /// Try to convert from a byte slice.
    ///
    /// Returns [`None`] if the byte slice does not contain a valid magic value variant.
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self> {
        if !Self::starts_with_magic(bytes) || bytes.len() < size_of::<Self>() {
            return Err(Error::NoAsrcb);
        }

        // Panic: Will not panic, bytes is at least 8 elements long
        let kind = byteorder::BigEndian::read_u16(&bytes[6..8]);
        let kind = UserDataType::try_from(kind)?;
        Ok(Self::from(kind))
    }

    /// Returns the [`UserDataType`] of this [`AddSecretMagic`].
    pub fn kind(&self) -> UserDataType {
        // Panic: Will never panic. The value is checked during construction of
        // the object for being one of the enum values.
        self.kind.get().try_into().unwrap()
    }
}

/// Types of (non architectured) user data for an add-secret request
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserDataType {
    /// Marker that the request does not contain any user data
    Null = 0x0000,
    /// Arbitrary user data (max 512 bytes)
    Unsigned = 0x0001,
    /// User data message signed with an EC key, (max 256 byte)
    SgnEcSECP521R1 = 0x0002,
    /// User data message signature with a RSA key of 2048 bit size, (max 256 byte)
    SgnRsa2048 = 0x0003,
    /// User data message signature with a RSA key of 3072 bit size, (max 128 byte)
    SgnRsa3072 = 0x0004,
}

impl UserDataType {
    /// Returns the maximum user-data size in bytes.
    pub fn max(&self) -> usize {
        match self {
            Self::Null => 0,
            Self::Unsigned => 512,
            Self::SgnEcSECP521R1 => 256,
            Self::SgnRsa2048 => 256,
            Self::SgnRsa3072 => 128,
        }
    }
}

impl Display for UserDataType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Null => "None",
                Self::Unsigned => "unsigned",
                Self::SgnEcSECP521R1 => "ECDSA signed",
                Self::SgnRsa2048 => "RSA 2048 signed",
                Self::SgnRsa3072 => "RSA 3072 signed",
            }
        )
    }
}

impl TryFrom<u16> for UserDataType {
    type Error = Error;

    fn try_from(value: u16) -> std::result::Result<Self, Self::Error> {
        if value == Self::Null as u16 {
            Ok(Self::Null)
        } else if value == Self::Unsigned as u16 {
            Ok(Self::Unsigned)
        } else if value == Self::SgnEcSECP521R1 as u16 {
            Ok(Self::SgnEcSECP521R1)
        } else if value == Self::SgnRsa2048 as u16 {
            Ok(Self::SgnRsa2048)
        } else if value == Self::SgnRsa3072 as u16 {
            Ok(Self::SgnRsa3072)
        } else {
            Err(Error::UnsupportedUserData(value))
        }
    }
}

impl From<UserDataType> for AddSecretMagic {
    fn from(kind: UserDataType) -> Self {
        Self {
            magic: Self::MAGIC,
            kind: (kind as u16).into(),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        request::MagicValue,
        secret::{AddSecretMagic, UserDataType},
        Error,
    };

    #[test]
    fn convert_user_data() {
        assert!(matches!(
            UserDataType::try_from(5),
            Err(Error::UnsupportedUserData(5))
        ));
    }

    #[test]
    fn magic_get() {
        let user_data = AddSecretMagic::from(UserDataType::SgnEcSECP521R1);

        assert_eq!(
            user_data.get(),
            [0x61, 0x73, 0x72, 0x63, 0x62, 0x4D, 0x00, 0x02]
        );
    }

    #[test]
    fn magic_try_from() {
        let bin = [0x61, 0x73, 0x72, 0x63, 0x62, 0x4D, 0x00, 0x02];

        let magic = AddSecretMagic::try_from_bytes(&bin).unwrap();
        assert_eq!(
            magic,
            AddSecretMagic {
                magic: AddSecretMagic::MAGIC,
                kind: (UserDataType::SgnEcSECP521R1 as u16).into()
            }
        );
    }
}
