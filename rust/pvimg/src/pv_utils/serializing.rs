// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use deku::{
    reader::Reader, writer::Writer, DekuContainerRead, DekuContainerWrite, DekuError, DekuReader,
    DekuWriter,
};
use pv::request::{Confidential, Zeroize};

use crate::pv_utils::error::Result;

pub mod serde_hex_left_padded_u64 {
    use std::fmt::LowerHex;

    use serde::Deserializer;
    use serde::{Deserialize, Serialize, Serializer};

    pub fn serialize<S: Serializer, B: LowerHex>(
        data: &B,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        format!("{data:016x}").serialize(serializer)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let s = String::deserialize(deserializer)?;
        u64::from_str_radix(&s, 16).map_err(serde::de::Error::custom)
    }
}

pub mod serde_hex_array {
    use std::result::Result;

    use pv::misc::{decode_hex, encode_hex};
    use serde::{Deserialize, Deserializer, Serializer};

    use crate::pv_utils::try_copy_slice_to_array;

    pub fn serialize<S: Serializer, const COUNT: usize>(
        data: &[u8; COUNT],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&encode_hex(data))
    }

    #[allow(dead_code)]
    pub fn deserialize<'de, D: Deserializer<'de>, const COUNT: usize>(
        deserializer: D,
    ) -> Result<[u8; COUNT], D::Error> {
        let s = String::deserialize(deserializer)?;
        let decoded = decode_hex(s).map_err(serde::de::Error::custom)?;

        try_copy_slice_to_array(&decoded).map_err(serde::de::Error::custom)
    }
}

pub mod serde_hex_confidential_array {
    use std::result::Result;

    use pv::request::Confidential;
    use serde::{Deserializer, Serializer};

    use super::serde_hex_array;

    pub fn serialize<S: Serializer, const COUNT: usize>(
        data: &Confidential<[u8; COUNT]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serde_hex_array::serialize(data.value(), serializer)
    }

    #[allow(dead_code)]
    pub fn deserialize<'de, D: Deserializer<'de>, const COUNT: usize>(
        deserializer: D,
    ) -> Result<Confidential<[u8; COUNT]>, D::Error> {
        Ok(Confidential::new(serde_hex_array::deserialize(
            deserializer,
        )?))
    }
}

pub mod serde_base64 {
    use base64::prelude::*;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S, B>(bytes: B, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        B: AsRef<[u8]>,
    {
        let b64 = BASE64_STANDARD.encode(bytes.as_ref());
        serializer.serialize_str(&b64)
    }

    #[allow(dead_code)]
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        BASE64_STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

pub mod serde_base64_array {
    use base64::prelude::*;
    use serde::{Deserialize, Deserializer, Serializer};

    use crate::pv_utils::try_copy_slice_to_array;

    #[allow(dead_code)]
    pub fn serialize<S, const N: usize>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let b64 = BASE64_STANDARD.encode(bytes);
        serializer.serialize_str(&b64)
    }

    #[allow(dead_code)]
    pub fn deserialize<'de, D, const COUNT: usize>(deserializer: D) -> Result<[u8; COUNT], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let decoded = BASE64_STANDARD
            .decode(&s)
            .map_err(serde::de::Error::custom)?;
        try_copy_slice_to_array(&decoded).map_err(serde::de::Error::custom)
    }
}

/// Read a slice into a confidential array of type [`T`] and length [`N`].
///
/// # Errors
///
/// This function will return an error if the result could not be constructed or
/// if there was an I/O error.
pub fn confidential_read_slice<'a, Ctx, T, const COUNT: usize, R>(
    reader: &mut Reader<R>,
    ctx: Ctx,
) -> Result<Confidential<[T; COUNT]>, DekuError>
where
    Ctx: Copy,
    T: Default + DekuReader<'a, Ctx>,
    R: std::io::Read + std::io::Seek,
{
    Ok(Confidential::new(<[T; COUNT]>::from_reader_with_ctx(
        reader, ctx,
    )?))
}

/// Writes a confidential array into this writer.
///
/// # Errors
///
/// This function will return an error if there was an I/O error.
pub fn confidential_write_slice<Ctx, T, const COUNT: usize, W>(
    value: &Confidential<[T; COUNT]>,
    writer: &mut Writer<W>,
    ctx: Ctx,
) -> Result<(), DekuError>
where
    Ctx: Copy,
    T: Default + DekuWriter<Ctx>,
    W: std::io::Write + std::io::Seek,
{
    value.value().to_writer(writer, ctx)
}

/// Serializes `value` to bytes.
///
/// # Errors
///
/// This function will return an error if the value could not be serialized.
pub fn serialize_to_bytes<T>(value: &T) -> Result<Vec<u8>>
where
    T: DekuContainerWrite,
{
    Ok(value.to_bytes()?)
}

/// Deserializes `value` to `T`.
///
/// # Errors
///
/// This function will return an error if the given value could not be
/// deserialized.
pub fn deserialize_from_bytes<'a, T>(value: &'a [u8]) -> Result<T>
where
    T: DekuContainerRead<'a>,
{
    let ((_, rest), obj) = T::from_bytes((value, 0))?;
    assert_eq!(rest, 0);
    Ok(obj)
}

/// Returns the size (in bytes) of the serialized `value`.
///
/// # Errors
///
/// This function will return an error if the given value could not be
/// serialized.
pub fn bytesize<T>(value: &T) -> Result<usize>
where
    T: DekuContainerWrite,
{
    let data = serialize_to_bytes(value)?;
    Ok(data.len())
}

pub fn bytesize_confidential<T>(value: &Confidential<T>) -> Result<usize>
where
    T: DekuContainerWrite + Zeroize,
{
    let data = Confidential::new(serialize_to_bytes(value.value())?);
    Ok(data.value().len())
}

#[cfg(test)]
mod tests {
    use deku::{ctx::Endian, DekuContainerWrite, DekuRead, DekuWrite};
    use pv::request::Confidential;

    use crate::pv_utils::serializing::{confidential_read_slice, confidential_write_slice};

    #[test]
    fn read_and_write() {
        #[derive(DekuRead, DekuWrite)]
        #[deku(endian = "endian", ctx = "endian: Endian", ctx_default = "Endian::Big")]
        struct Test {
            #[deku(
                reader = "confidential_read_slice(deku::reader, endian)",
                writer = "confidential_write_slice(test, deku::writer, endian)"
            )]
            test: Confidential<[u32; 1]>,
        }

        const DATA: [u8; 4] = [15_u8, 1_u8, 2_u8, 3_u8];
        let test = Test::try_from(DATA.as_ref()).unwrap();
        assert_eq!(test.test.value()[0], 0x0f010203);
        assert_eq!(test.to_bytes().unwrap().as_slice(), &DATA);
    }

    #[test]
    fn test_serde_base64() {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct TestStruct {
            #[serde(with = "super::serde_base64")]
            data: Vec<u8>,
        }

        let original = TestStruct {
            data: vec![1, 2, 3, 4, 5],
        };

        let json = serde_json::to_string(&original).unwrap();
        assert!(json.contains("AQIDBAU="));

        let deserialized: TestStruct = serde_json::from_str(&json).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_serde_base64_with_array() {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct TestStruct {
            #[serde(with = "super::serde_base64_array")]
            data: [u8; 5],
        }

        let original = TestStruct {
            data: [1, 2, 3, 4, 5],
        };

        let json = serde_json::to_string(&original).unwrap();
        assert!(json.contains("AQIDBAU="));

        let deserialized: TestStruct = serde_json::from_str(&json).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_serde_hex_array() {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct TestStruct {
            #[serde(with = "super::serde_hex_array")]
            data: [u8; 5],
        }

        let original = TestStruct {
            data: [1, 2, 3, 4, 5],
        };

        let json = serde_json::to_string(&original).unwrap();
        assert!(json.contains("0102030405"));
        assert_eq!(&json, r#"{"data":"0102030405"}"#);

        let deserialized: TestStruct = serde_json::from_str(&json).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_serde_hex_array_invalid_length() {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct TestStruct {
            #[serde(with = "super::serde_hex_array")]
            data: [u8; 5],
        }

        // Try to deserialize with wrong length (3 bytes instead of 5)
        let json = r#"{"data":"010203"}"#;
        let result: Result<TestStruct, _> = serde_json::from_str(json);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Expected size 5"));
    }

    #[test]
    fn test_serde_base64_array_invalid_length() {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct TestStruct {
            #[serde(with = "super::serde_base64_array")]
            data: [u8; 5],
        }

        // Try to deserialize with wrong length (3 bytes instead of 5)
        let json = r#"{"data":"AQID"}"#; // Base64 for [1, 2, 3]
        let result: Result<TestStruct, _> = serde_json::from_str(json);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Expected size 5"));
    }
}
