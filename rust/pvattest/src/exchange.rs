// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024
use anyhow::{anyhow, bail, Error, Result};
use byteorder::ByteOrder;
use pv::{assert_size, request::MagicValue, uv::AttestationCmd, uv::ConfigUid};
use std::{
    io::{ErrorKind, Read, Seek, SeekFrom, Write},
    mem::size_of,
};
use zerocopy::{AsBytes, BigEndian, FromBytes, FromZeroes, U32, U64};

const INV_EXCHANGE_FMT_ERROR_TEXT: &str = "The input has not the correct format:";

#[repr(C)]
#[derive(Debug, AsBytes, PartialEq, Eq, Default, FromZeroes, FromBytes)]
struct Entry {
    size: U32<BigEndian>,
    offset: U32<BigEndian>,
}
assert_size!(Entry, 8);

/// If size == 0 the offset is ignored. (entry does not exist)
/// If offset >0 and <0x40 -> invalid format
/// If offset == 0 and size > 0 no data saved, however the request will need this amount of memory
///     to succeed. Only makes sense for measurement and additional data. This however, is not
///     enforced.
impl Entry {
    fn new(size: u32, offset: u32) -> Self {
        Self {
            size: size.into(),
            offset: offset.into(),
        }
    }

    /// # Panic
    ///
    /// panics if `val` is larger than `max_size` bytes
    fn from_slice(val: Option<&[u8]>, max_size: u32, offset: &mut u32) -> Self {
        match val {
            Some(val) => {
                assert!(val.len() <= max_size as usize);
                let size = val.len() as u32;
                let res = Self::new(size, *offset);
                *offset += size;
                res
            }
            None => Self::default(),
        }
    }

    /// # Panic
    ///
    /// panics if `val` is larger than `max_size` bytes
    fn from_exp(val: Option<u32>) -> Self {
        if let Some(val) = val {
            Self::new(val, 0)
        } else {
            Self::default()
        }
    }

    fn from_none() -> Self {
        Self::default()
    }

    /// Reads data from stream if required
    fn read<R>(&self, reader: &mut R) -> Result<ExpOrData>
    where
        R: Read + Seek,
    {
        match self {
            Self { size, .. } if size.get() == 0 => Ok(ExpOrData::None),
            Self { size, offset } if offset.get() == 0 => Ok(ExpOrData::Exp(size.get())),
            Self { size, offset } => {
                reader.seek(SeekFrom::Start(offset.get() as u64))?;
                let mut buf = vec![0; size.get() as usize];
                reader.read_exact(&mut buf)?;
                Ok(ExpOrData::Data(buf))
            }
        }
    }
}

#[repr(C)]
#[derive(Debug, AsBytes, FromZeroes, FromBytes)]
struct ExchangeFormatV1Hdr {
    magic: U64<BigEndian>,
    version: U32<BigEndian>,
    size: U32<BigEndian>,
    reserved: U64<BigEndian>,
    /// v1 specific
    arcb: Entry,
    measurement: Entry,
    additional: Entry,
    user: Entry,
    config_uid: Entry,
}
assert_size!(ExchangeFormatV1Hdr, 0x40);

impl ExchangeFormatV1Hdr {
    fn new_request(arcb: &[u8], measurement: u32, additional: u32) -> Result<Self> {
        let mut offset: u32 = size_of::<Self>() as u32;
        let arcb_entry = Entry::from_slice(Some(arcb), AttestationCmd::ARCB_MAX_SIZE, &mut offset);
        let measurement_entry = Entry::from_exp(Some(measurement));
        let exp_add = match additional {
            0 => None,
            size => Some(size),
        };
        // TODO min and max size check?
        let additional_entry = Entry::from_exp(exp_add); //, AttestationCmd::ADDITIONAL_MAX_SIZE, &mut offset);
        let user_entry = Entry::from_none();
        let cuid_entry = Entry::from_none();

        Ok(Self {
            magic: U64::from_bytes(ExchangeMagic::MAGIC),
            version: ExchangeFormatVersion::One.into(),
            size: offset.into(),
            reserved: 0.into(),
            arcb: arcb_entry,
            measurement: measurement_entry,
            additional: additional_entry,
            user: user_entry,
            config_uid: cuid_entry,
        })
    }

    fn new_response(
        arcb: &[u8],
        measurement: &[u8],
        additional: Option<&[u8]>,
        user: Option<&[u8]>,
        config_uid: &[u8],
    ) -> Result<Self> {
        let mut offset: u32 = size_of::<Self>() as u32;
        let arcb_entry = Entry::from_slice(Some(arcb), AttestationCmd::ARCB_MAX_SIZE, &mut offset);
        let measurement_entry = Entry::from_slice(
            Some(measurement),
            AttestationCmd::MEASUREMENT_MAX_SIZE,
            &mut offset,
        );
        let additional_entry =
            Entry::from_slice(additional, AttestationCmd::ADDITIONAL_MAX_SIZE, &mut offset);
        let user_entry = Entry::from_slice(user, AttestationCmd::USER_MAX_SIZE, &mut offset);
        let cuid_entry = Entry::from_slice(Some(config_uid), 0x10, &mut offset);

        Ok(Self {
            magic: U64::from_bytes(ExchangeMagic::MAGIC),
            version: ExchangeFormatVersion::One.into(),
            size: offset.into(),
            reserved: 0.into(),
            arcb: arcb_entry,
            measurement: measurement_entry,
            additional: additional_entry,
            user: user_entry,
            config_uid: cuid_entry,
        })
    }
}

/// The magic value used to identify an [`ExchangeFormatRequest`]
///
/// The magic value is ASCII:
/// ```rust
/// # use s390_pv_core::attest::ExchangeMagic;
/// # use s390_pv_core::request::MagicValue;
/// # fn main() {
/// # let magic =
/// b"pvattest"
/// # ;
/// # assert!(ExchangeMagic::starts_with_magic(magic));
/// # }
/// ```
pub struct ExchangeMagic;
impl MagicValue<8> for ExchangeMagic {
    const MAGIC: [u8; 8] = [0x70, 0x76, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74];
}

/// Version identifier for an [`ExchangeFormatRequest`]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExchangeFormatVersion {
    /// Version 1 (= 0x0100)
    One = 0x0100,
}

impl<E: ByteOrder> TryFrom<U32<E>> for ExchangeFormatVersion {
    type Error = Error;

    fn try_from(value: U32<E>) -> Result<Self, Self::Error> {
        if value.get() == Self::One as u32 {
            Ok(Self::One)
        } else {
            bail!(
                "{INV_EXCHANGE_FMT_ERROR_TEXT} Unsupported version: ({})",
                value.get()
            );
        }
    }
}

impl<E: ByteOrder> From<ExchangeFormatVersion> for U32<E> {
    fn from(value: ExchangeFormatVersion) -> Self {
        (value as u32).into()
    }
}

/// A parsed exchange entry value
///
/// An entry can be all zero(None), just a size (Exp) or a offset+size to some data (Data)
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ExpOrData {
    Exp(u32),
    Data(Vec<u8>),
    None,
}

impl ExpOrData {
    /// calculates the (expected or real) size
    fn size(&self) -> u32 {
        match self {
            Self::Exp(s) => *s,
            // size is max u32 large as read in before
            Self::Data(v) => v.len() as u32,
            Self::None => 0,
        }
    }

    /// Returns data if self is [`ExpOrData::Data`]
    ///
    /// Consumes itself
    fn data(self) -> Option<Vec<u8>> {
        match self {
            Self::Data(v) => Some(v),
            _ => None,
        }
    }
}

impl From<Option<u32>> for ExpOrData {
    fn from(value: Option<u32>) -> Self {
        match value {
            Some(v) => Self::Exp(v),
            None => Self::None,
        }
    }
}

impl From<&ExpOrData> for Option<u32> {
    fn from(value: &ExpOrData) -> Self {
        match value {
            ExpOrData::Exp(v) => Some(*v),
            _ => None,
        }
    }
}

impl From<ExpOrData> for Option<Vec<u8>> {
    fn from(value: ExpOrData) -> Self {
        match value {
            ExpOrData::Exp(s) => Some(vec![0; s as usize]),
            ExpOrData::Data(d) => Some(d),
            ExpOrData::None => None,
        }
    }
}

/// The _exchange format_ is a simple file format to send labeled binary blobs between
/// pvattest instances on different machines.
#[derive(Debug, PartialEq, Eq)]
pub struct ExchangeFormatRequest {
    // all sizes are guaranteed to fit in the exchange format/UV Call at any time
    // pub to allow deconstruction of this struct
    pub arcb: Vec<u8>,
    pub exp_measurement: u32,
    pub exp_additional: u32,
}

/// The _exchange format_ is a simple file format to send labeled binary blobs between
/// pvattest instances on different machines.
#[derive(Debug, PartialEq, Eq)]
pub struct ExchangeFormatResponse {
    // all sizes are guaranteed to fit in the exchange format/UV Call at any time
    // pub to allow deconstruction of this struct
    pub arcb: Vec<u8>,
    pub measurement: Vec<u8>,
    pub additional: Option<Vec<u8>>,
    pub user: Option<Vec<u8>>,
    pub config_uid: ConfigUid,
}

impl ExchangeFormatRequest {
    /// Creates a new exchange context, with an attestation request, expected measurement and
    /// optional an additional data size. Useful for creating a attestation request.
    pub fn new(arcb: Vec<u8>, exp_measurement: u32, exp_additional: u32) -> Result<Self> {
        verify_size(
            exp_measurement,
            1,
            AttestationCmd::MEASUREMENT_MAX_SIZE,
            "Expected measurement size",
        )?;
        verify_size(
            exp_additional,
            0,
            AttestationCmd::ADDITIONAL_MAX_SIZE,
            "Expected additional data size",
        )?;
        verify_slice(&arcb, AttestationCmd::ARCB_MAX_SIZE, "Attestation request")?;

        Ok(Self {
            arcb,
            exp_measurement,
            exp_additional,
        })
    }

    fn write_v1<W>(&self, writer: &mut W) -> Result<()>
    where
        W: Write,
    {
        let hdr = ExchangeFormatV1Hdr::new_request(
            self.arcb.as_slice(),
            self.exp_measurement,
            self.exp_additional,
        )?;
        writer.write_all(hdr.as_bytes())?;
        writer.write_all(&self.arcb)?;
        Ok(())
    }

    /// Serializes the encapsulated data into the provides stream in the provided format
    pub fn write<W>(&self, writer: &mut W, version: ExchangeFormatVersion) -> Result<()>
    where
        W: Write,
    {
        match version {
            ExchangeFormatVersion::One => self.write_v1(writer),
        }
    }

    /// Reads and deserializes the exchange file in the provided stream
    ///
    /// # Errors
    ///
    /// Returns an error if the stream does not contain data in exchange format, CUID or user data
    /// do not fit, or any IO error that can appear during reading streams.
    pub fn read<R>(reader: &mut R) -> Result<Self>
    where
        R: Read + Seek,
    {
        let mut buf = vec![0; size_of::<ExchangeFormatV1Hdr>()];
        match reader.read_exact(&mut buf) {
            Ok(it) => it,
            // report hdr file to small for header
            Err(err) if err.kind() == ErrorKind::UnexpectedEof => {
                bail!("{INV_EXCHANGE_FMT_ERROR_TEXT} Invalid Header.");
            }
            Err(err) => return Err(err.into()),
        };

        if !ExchangeMagic::starts_with_magic(&buf) {
            bail!("{INV_EXCHANGE_FMT_ERROR_TEXT} Does not start with the magic value.",);
        }

        let hdr = ExchangeFormatV1Hdr::ref_from(buf.as_slice())
            .ok_or(anyhow!("{INV_EXCHANGE_FMT_ERROR_TEXT} Invalid Header."))?;

        match TryInto::<ExchangeFormatVersion>::try_into(hdr.version)? {
            ExchangeFormatVersion::One => (),
        }

        if stream_len(reader)? < hdr.size.get() as u64 {
            bail!("{INV_EXCHANGE_FMT_ERROR_TEXT} File size too small");
        }
        let arcb = hdr.arcb.read(reader)?.data().ok_or(anyhow!(
            "{INV_EXCHANGE_FMT_ERROR_TEXT} Contains no attestation request.",
        ))?;

        let measurement = hdr.measurement.read(reader)?.size();
        let additional = hdr.additional.read(reader)?.size();
        Self::new(arcb, measurement, additional)
    }
}

// Seek::stream_is unstable
// not expose to API users
// taken from rust std::io::seek;
fn stream_len<S>(seek: &mut S) -> Result<u64>
where
    S: Seek,
{
    let old_pos = seek.stream_position()?;
    let len = seek.seek(SeekFrom::End(0))?;

    // Avoid seeking a third time when we were already at the end of the
    // stream. The branch is usually way cheaper than a seek operation.
    if old_pos != len {
        seek.seek(SeekFrom::Start(old_pos))?;
    }

    Ok(len)
}

fn verify_size(size: u32, min_size: u32, max_size: u32, field: &'static str) -> Result<()> {
    if size < min_size {
        bail!("{INV_EXCHANGE_FMT_ERROR_TEXT} The {field} field is too small ({size})");
    }

    if size > max_size {
        bail!("{INV_EXCHANGE_FMT_ERROR_TEXT} The {field} field is too large ({size})");
    }

    Ok(())
}

/// check that a slice has at max `max_size` amount of bytes
fn verify_slice(val: &[u8], max_size: u32, field: &'static str) -> Result<()> {
    if val.len() > max_size as usize {
        bail!(
            "{INV_EXCHANGE_FMT_ERROR_TEXT} The {field} field is too large ({})",
            val.len()
        );
    }
    Ok(())
}

impl ExchangeFormatResponse {
    /// Creates a new exchange context, with an attestation request, measurement and
    /// cuid.
    pub fn new(
        arcb: Vec<u8>,
        measurement: Vec<u8>,
        additional: Option<Vec<u8>>,
        user: Option<Vec<u8>>,
        config_uid: ConfigUid,
    ) -> Result<Self> {
        // should not fail; Already checked during import.
        verify_slice(
            &arcb,
            AttestationCmd::ARCB_MAX_SIZE,
            "Attestation request data",
        )?;
        verify_slice(
            &measurement,
            AttestationCmd::MEASUREMENT_MAX_SIZE,
            "Attestation Measurement",
        )?;

        if let Some(additional) = &additional {
            verify_slice(
                additional,
                AttestationCmd::ADDITIONAL_MAX_SIZE,
                "Additional data",
            )?;
        }

        if let Some(user) = &user {
            verify_slice(user, AttestationCmd::USER_MAX_SIZE, "User data")?;
        }

        Ok(Self {
            arcb,
            measurement,
            additional,
            user,
            config_uid,
        })
    }

    fn write_v1<W>(&self, writer: &mut W) -> Result<()>
    where
        W: Write,
    {
        let hdr = ExchangeFormatV1Hdr::new_response(
            self.arcb.as_slice(),
            &self.measurement,
            self.additional.as_deref(),
            self.user.as_deref(),
            &self.config_uid,
        )?;
        writer.write_all(hdr.as_bytes())?;
        writer.write_all(&self.arcb)?;
        writer.write_all(&self.measurement)?;
        if let Some(data) = &self.additional {
            writer.write_all(data)?;
        }
        if let Some(data) = &self.user {
            writer.write_all(data)?;
        }
        writer.write_all(&self.config_uid)?;
        Ok(())
    }

    /// Serializes the encapsulated data into the provides stream in the provided format
    pub fn write<W>(&self, writer: &mut W, version: ExchangeFormatVersion) -> Result<()>
    where
        W: Write,
    {
        match version {
            ExchangeFormatVersion::One => self.write_v1(writer),
        }
    }

    /// Reads and deserializes the exchange file in the provided stream
    ///
    /// # Errors
    ///
    /// Returns an error if the stream does not contain data in exchange format, CUID or user data
    /// do not fit, or any IO error that can appear during reading streams.
    pub fn read<R>(reader: &mut R) -> Result<Self>
    where
        R: Read + Seek,
    {
        let mut buf = vec![0; size_of::<ExchangeFormatV1Hdr>()];
        match reader.read_exact(&mut buf) {
            Ok(it) => it,
            // report hdr file to small for header
            Err(err) if err.kind() == ErrorKind::UnexpectedEof => {
                bail!("{INV_EXCHANGE_FMT_ERROR_TEXT} Invalid Header.");
            }
            Err(err) => return Err(err.into()),
        };

        if !ExchangeMagic::starts_with_magic(&buf) {
            bail!("{INV_EXCHANGE_FMT_ERROR_TEXT} Does not start with the magic value.");
        }

        let hdr = ExchangeFormatV1Hdr::ref_from(buf.as_slice())
            .ok_or(anyhow!("{INV_EXCHANGE_FMT_ERROR_TEXT} Invalid Header."))?;

        match TryInto::<ExchangeFormatVersion>::try_into(hdr.version)? {
            ExchangeFormatVersion::One => (),
        }

        if stream_len(reader)? < hdr.size.get() as u64 {
            bail!("{INV_EXCHANGE_FMT_ERROR_TEXT} File size too small");
        }
        let arcb = hdr.arcb.read(reader)?.data().ok_or(anyhow!(
            "{INV_EXCHANGE_FMT_ERROR_TEXT} Contains no attestation request.",
        ))?;

        // TODO remove unwrap
        let measurement = hdr.measurement.read(reader)?.data().ok_or(anyhow!(
            "{INV_EXCHANGE_FMT_ERROR_TEXT} Contains no attestation response (Measurement missing).",
        ))?;
        let additional = hdr.additional.read(reader)?.data();
        let user = hdr.user.read(reader)?.data();
        let config_uid: ConfigUid = match hdr.config_uid.read(reader)?.data() {
            Some(v) => v.try_into().map_err(|_| {
anyhow!(
            "{INV_EXCHANGE_FMT_ERROR_TEXT} Configuration UID has an invalid size. Expected size 16, is {}",hdr.config_uid.size.get()
        )
            })?,
            None =>
            bail!("{INV_EXCHANGE_FMT_ERROR_TEXT} Contains no attestation response (CUID missing).")
,
        };
        Self::new(arcb, measurement, additional, user, config_uid)
    }

    /// Returns the measurement of this [`ExchangeFormatRequest`].
    pub fn measurement(&self) -> &[u8] {
        &self.measurement
    }

    /// Returns the additional data of this [`ExchangeFormatRequest`].
    pub fn additional(&self) -> Option<&[u8]> {
        self.additional.as_deref()
    }

    /// Returns the user data of this [`ExchangeFormatRequest`].
    pub fn user(&self) -> Option<&[u8]> {
        self.user.as_deref()
    }

    /// Returns the config UID of this [`ExchangeFormatRequest`].
    ///
    /// # Error
    /// Returns an error if the [`ExchangeFormatRequest`] contains no CUID,
    pub fn config_uid(&self) -> &ConfigUid {
        &self.config_uid
    }

    /// Returns a reference to the attestation request of this [`ExchangeFormatRequest`].
    pub fn arcb(&self) -> &[u8] {
        self.arcb.as_ref()
    }
}

#[cfg(test)]
mod test {

    use std::io::Cursor;

    use super::*;
    use pv::misc::read_file;

    #[test]
    fn exchange_from_slice() {
        let val = &[0; 17];
        let mut offset = 18;

        let entry = Entry::from_slice(Some(val), 20, &mut offset);
        assert_eq!(
            entry,
            Entry {
                size: 17.into(),
                offset: 18.into(),
            }
        );
        assert_eq!(offset, 18 + 17);
    }
    static ARCB: [u8; 16] = [0x11; 16];
    static MEASUREMENT: [u8; 64] = [0x12; 64];
    static ADDITIONAL: [u8; 32] = [0x13; 32];
    static CUID: [u8; 16] = [0x14; 16];
    static USER: [u8; 256] = [0x15; 256];

    fn test_read_write_request(
        path: &'static str,
        arcb: Vec<u8>,
        measurement: usize,
        additional: usize,
    ) {
        // TODO as 32 checks
        let ctx_write = ExchangeFormatRequest::new(arcb, measurement as u32, additional as u32)
            .expect("exchange fmt creation");

        // let mut out = create_file(path).unwrap();
        let mut out = vec![];
        ctx_write
            .write(&mut out, ExchangeFormatVersion::One)
            .unwrap();

        let buf = read_file(path, "test read exchange").unwrap();

        assert_eq!(out, buf);

        let ctx_read = ExchangeFormatRequest::read(&mut Cursor::new(&mut &buf)).unwrap();

        assert_eq!(ctx_read, ctx_write);
    }

    fn test_read_write_response(
        path: &'static str,
        arcb: Vec<u8>,
        measurement: Vec<u8>,
        additional: Option<Vec<u8>>,
        user: Option<Vec<u8>>,
        cuid: ConfigUid,
    ) {
        let ctx_write = ExchangeFormatResponse::new(arcb, measurement, additional, user, cuid)
            .expect("exchange fmt creation");

        // let mut out = create_file(path).unwrap();

        let mut out = vec![];
        ctx_write
            .write(&mut out, ExchangeFormatVersion::One)
            .unwrap();

        let buf = read_file(path, "test read exchange").unwrap();

        assert_eq!(out, buf);

        let ctx_read = ExchangeFormatResponse::read(&mut Cursor::new(&mut &buf)).unwrap();

        assert_eq!(ctx_read, ctx_write);
    }

    #[test]
    fn full_req() {
        test_read_write_request(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/assets/",
                "exp/exchange/full_req.bin"
            ),
            ARCB.to_vec(),
            MEASUREMENT.len(),
            ADDITIONAL.len(),
        );
    }

    #[test]
    fn add_req() {
        test_read_write_request(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/assets/",
                "exp/exchange/add_req.bin"
            ),
            ARCB.to_vec(),
            MEASUREMENT.len(),
            ADDITIONAL.len(),
        );
    }

    #[test]
    fn invalid_req() {
        ExchangeFormatRequest::new(ARCB.to_vec(), 0, ADDITIONAL.len() as u32).unwrap_err();
    }

    #[test]
    fn min_req() {
        test_read_write_request(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/assets/",
                "exp/exchange/min_req.bin"
            ),
            ARCB.to_vec(),
            MEASUREMENT.len(),
            0,
        );
    }

    #[test]
    fn full_resp() {
        test_read_write_response(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/assets/",
                "exp/exchange/full_resp.bin"
            ),
            ARCB.to_vec(),
            MEASUREMENT.to_vec(),
            ADDITIONAL.to_vec().into(),
            USER.to_vec().into(),
            CUID,
        );
    }

    #[test]
    fn add_resp() {
        test_read_write_response(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/assets/",
                "exp/exchange/add_resp.bin"
            ),
            ARCB.to_vec(),
            MEASUREMENT.to_vec(),
            ADDITIONAL.to_vec().into(),
            None,
            CUID,
        );
    }

    #[test]
    fn user_resp() {
        test_read_write_response(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/assets/",
                "exp/exchange/user_resp.bin"
            ),
            ARCB.to_vec(),
            MEASUREMENT.to_vec(),
            None,
            USER.to_vec().into(),
            CUID,
        );
    }
    #[test]
    fn min_resp() {
        test_read_write_response(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/assets/",
                "exp/exchange/min_resp.bin"
            ),
            ARCB.to_vec(),
            MEASUREMENT.to_vec(),
            None,
            None,
            CUID,
        )
    }

    #[test]
    fn resp_no_cuid() {
        let buf = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/",
            "exp/exchange/min_req.bin"
        ));
        let _ctx_read = ExchangeFormatResponse::read(&mut Cursor::new(&mut &buf)).unwrap_err();
    }

    #[test]
    fn resp_inv_magic() {
        let mut buf = read_file(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/assets/",
                "exp/exchange/min_req.bin"
            ),
            "test resp inv magic",
        )
        .unwrap();
        // tamper with the magic
        buf[0] = !buf[0];

        let _ctx_read = ExchangeFormatResponse::read(&mut Cursor::new(&mut &buf)).unwrap_err();
    }

    #[test]
    fn no_arcb() {
        let mut buf = read_file(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/assets/",
                "exp/exchange/min_req.bin"
            ),
            "test resp inv magic",
        )
        .unwrap();
        // delete the arcb entry
        buf[0x18..0x20].copy_from_slice(&[0; 8]);

        let _ctx_read = ExchangeFormatRequest::read(&mut Cursor::new(&mut &buf)).unwrap_err();
    }

    #[test]
    fn small() {
        let mut buf = read_file(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/assets/",
                "exp/exchange/min_req.bin"
            ),
            "test resp inv magic",
        )
        .unwrap();
        buf.pop();

        let _ctx_read = ExchangeFormatRequest::read(&mut Cursor::new(&mut &buf)).unwrap_err();
    }

    #[test]
    fn hdr() {
        // buffer smaller than the header but containing the magic
        let buf = [
            0x70, 0x76, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x1, 0x2, 0x3, 0x4,
        ];

        let _ctx_read = ExchangeFormatRequest::read(&mut Cursor::new(&mut &buf)).unwrap_err();
    }

    #[test]
    fn version() {
        let mut buf = read_file(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/assets/",
                "exp/exchange/min_req.bin"
            ),
            "test resp inv magic",
        )
        .unwrap();
        // tamper with the version
        buf[0x8] = 0xff;

        let _ctx_read = ExchangeFormatRequest::read(&mut Cursor::new(&mut &buf)).unwrap_err();
    }

    #[test]
    fn cuid_size() {
        let mut buf = read_file(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/assets/",
                "exp/exchange/min_resp.bin"
            ),
            "test resp inv magic",
        )
        .unwrap();
        // tamper with the cuid size
        buf[0x3b] = 0xf;

        let _ctx_read = ExchangeFormatResponse::read(&mut Cursor::new(&mut &buf)).unwrap_err();
    }
}
