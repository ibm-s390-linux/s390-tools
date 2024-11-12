// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use std::io::{BufRead, BufReader, Read};

use enum_dispatch::enum_dispatch;
use pv::misc::decode_hex;

use super::try_copy_slice_to_array;
use crate::error::{Error, Result};

/// The `enum_dispatch` macros needs at least one local trait to be implemented.
#[allow(unused)]
#[enum_dispatch(UvKeyHashes)]
trait UvKeyHashTrait: AsRef<[u8]> {}

#[derive(Debug, PartialEq, Eq)]
pub struct UvKeyHashV1([u8; 32]);

#[non_exhaustive]
#[enum_dispatch]
#[derive(PartialEq, Eq, Debug)]
pub enum UvKeyHash {
    UvKeyHashV1(UvKeyHashV1),
}

impl AsRef<[u8]> for UvKeyHash {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::UvKeyHashV1(hash) => hash.as_ref(),
        }
    }
}

impl UvKeyHashV1 {
    pub fn new<T: AsRef<[u8]>>(data: T) -> Result<Self> {
        let array = try_copy_slice_to_array(data.as_ref())?;
        Ok(Self(array))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct UvKeyHashesV1 {
    pub pchkh: UvKeyHashV1,
    pub pbhkh: UvKeyHashV1,
    pub res: [UvKeyHashV1; 13],
}

impl UvKeyHashV1 {
    pub const UV_KEY_HASH_NULL: Self = Self([0x0_u8; 32]);
}

impl AsRef<[u8]> for UvKeyHashV1 {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl TryFrom<&str> for UvKeyHashV1 {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let bytes = decode_hex(value)?;
        if bytes.len() != 32 {
            return Err(Error::InvalidTargetKeyHash);
        }

        Ok(Self(bytes.try_into().unwrap()))
    }
}

impl TryFrom<String> for UvKeyHashV1 {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

impl UvKeyHashesV1 {
    pub const SYS_UV_KEYS_ALL: &'static str = "/sys/firmware/uv/keys/all";

    /// Reads a `UvKeyHashesV1` from an [`std::io::Read`].
    ///
    /// # Errors
    ///
    /// This function will return an error if this functions encounters an I/O
    /// error, if a line could not be interpreted as `UvKeyHashV1` or if the
    /// count of hashes is less than 15.
    #[allow(clippy::similar_names)]
    pub fn read_from_io<R>(reader: R) -> Result<Self>
    where
        R: Read,
    {
        let buf_reader = BufReader::new(reader);
        let lines: Vec<String> = buf_reader
            .lines()
            .collect::<std::result::Result<Vec<_>, std::io::Error>>()?;
        let hashes: Vec<UvKeyHashV1> = lines
            .into_iter()
            .map(UvKeyHashV1::try_from)
            .collect::<std::result::Result<Vec<UvKeyHashV1>, Error>>()?;
        let hashes_count = hashes.len();
        if hashes_count < 15 {
            return Err(Error::InvalidUvKeyHashes);
        }

        let [pchkh, pbhkh, res @ ..]: [UvKeyHashV1; 15] =
            hashes.try_into().map_err(|_| Error::InvalidUvKeyHashes)?;
        Ok(Self { pchkh, pbhkh, res })
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use pv::misc::decode_hex;

    use crate::{pv_utils::uv_keys::UvKeyHashV1, uvdata::UvKeyHashesV1};

    #[test]
    fn from_reader() {
        let data = "0b729fd62241b339840d61b964a06bb6a1fd4976d9ebea2b4fb48d44de3a2461
8ec6bc2f77d5d6474b1417cf0a8c914f576245a5b9bb0eefacc7b821483ece7d
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
";
        let result = UvKeyHashesV1::read_from_io(Cursor::new(data)).expect("should not fail");
        assert_eq!(
            result,
            UvKeyHashesV1 {
                pchkh: UvKeyHashV1::new(
                    decode_hex("0b729fd62241b339840d61b964a06bb6a1fd4976d9ebea2b4fb48d44de3a2461")
                        .unwrap()
                )
                .unwrap(),
                pbhkh: UvKeyHashV1::new(
                    decode_hex("8ec6bc2f77d5d6474b1417cf0a8c914f576245a5b9bb0eefacc7b821483ece7d")
                        .unwrap()
                )
                .unwrap(),
                res: [UvKeyHashV1::UV_KEY_HASH_NULL; 13],
            }
        );
    }
}
