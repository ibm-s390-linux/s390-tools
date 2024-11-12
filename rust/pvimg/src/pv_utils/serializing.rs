// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use std::fmt::LowerHex;

use deku::{
    reader::Reader, writer::Writer, DekuContainerRead, DekuContainerWrite, DekuError, DekuReader,
    DekuWriter,
};
use pv::request::{Confidential, Zeroize};
use serde::{Serialize, Serializer};
use utils::HexSlice;

use crate::pv_utils::error::Result;

pub fn ser_hex<A: AsRef<[u8]>, S: Serializer>(
    data: A,
    ser: S,
) -> std::result::Result<S::Ok, S::Error> {
    HexSlice::from(data.as_ref()).serialize(ser)
}

pub fn ser_lower_hex<S: Serializer, B: LowerHex>(
    data: &B,
    ser: S,
) -> std::result::Result<S::Ok, S::Error> {
    format!("{:#018x}", data).serialize(ser)
}

pub fn ser_hex_confidential<S: Serializer, const COUNT: usize>(
    data: &Confidential<[u8; COUNT]>,
    ser: S,
) -> std::result::Result<S::Ok, S::Error> {
    ser_hex(data.value(), ser)
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
}
