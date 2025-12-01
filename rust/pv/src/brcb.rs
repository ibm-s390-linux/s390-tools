// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023, 2024

use std::{
    io::{Read, Seek, SeekFrom::Current},
    mem::size_of,
};

use log::{debug, warn};
use zerocopy::{BigEndian, FromBytes, Immutable, IntoBytes, KnownLayout, U32, U64};

// (SE) boot request control block aka SE header
use crate::{assert_size, request::MagicValue, static_assert, Error, Result, PAGESIZE};

/// Struct containing all SE-header tags.
///
/// Contains:
/// Page List Digest (pld)
/// Address List Digest (ald)
/// Tweak List Digest (tld)
/// SE-Header Tag (tag)
#[repr(C)]
#[derive(Debug, Clone, Copy, IntoBytes, PartialEq, Eq, FromBytes, Immutable, KnownLayout)]
pub struct BootHdrTags {
    pld: [u8; BootHdrHead::DIGEST_SIZE],
    ald: [u8; BootHdrHead::DIGEST_SIZE],
    tld: [u8; BootHdrHead::DIGEST_SIZE],
    tag: [u8; BootHdrHead::TAG_SIZE],
}
assert_size!(BootHdrTags, 0xd0);

impl AsRef<[u8]> for BootHdrTags {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl TryFrom<Vec<u8>> for BootHdrTags {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::ref_from_bytes(&value)
            .map_err(|_| Error::InvBootHdrSize(value.len()))
            .copied()
    }
}

/// Struct representing the Secure Execution boot image metadata
#[allow(unused)]
#[repr(C, packed)]
#[derive(Debug, Clone, FromBytes, IntoBytes, PartialEq, Eq, Immutable, KnownLayout)]
pub struct SeImgMetaData {
    /// Magic value
    magic: [u8; 8],
    /// Secure Execution header offset in the image
    hdr_off: U64<BigEndian>,
    /// Version
    version: U32<BigEndian>,
    /// IPIB offset in the image
    ipib_off: U64<BigEndian>,
}
assert_size!(SeImgMetaData, 28);

impl SeImgMetaData {
    /// Address in the Secure Execution boot image
    pub const OFFSET: u64 = 0xc000;
    /// V1 of the Secure Execution boot image metadata
    const V1: u32 = 0x1;

    /// Create v1 Secure Execution image metadata.
    pub fn new_v1(hdr_off: u64, ipib_off: u64) -> Self {
        Self {
            magic: Self::MAGIC,
            version: Self::V1.into(),
            hdr_off: hdr_off.into(),
            ipib_off: ipib_off.into(),
        }
    }

    fn seek_start<R>(img: &mut R) -> Result<bool>
    where
        R: Read + Seek,
    {
        const BUF_SIZE: i64 = 8;
        static_assert!(SeImgMetaData::MAGIC.len() == BUF_SIZE as usize);

        let mut buf = [0; BUF_SIZE as usize];
        match img.seek(std::io::SeekFrom::Start(Self::OFFSET)) {
            Ok(it) => it,
            Err(_) => return Ok(false),
        };
        match img.read_exact(&mut buf) {
            Ok(it) => it,
            Err(_) => return Ok(false),
        }

        if Self::starts_with_magic(&buf) {
            // go back to the beginning of the metadata
            img.seek(Current(-BUF_SIZE))?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Gets the bytes of this value.
    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        <Self as IntoBytes>::as_bytes(self)
    }

    /// Returns the version of this [`SeImgMetaData`].
    pub fn version(&self) -> u32 {
        self.version.into()
    }
}

/// Magic value for the metadata of a Secure Execution boot image
impl MagicValue<8> for SeImgMetaData {
    // ASCII `SeImgLnx`
    const MAGIC: [u8; 8] = [0x53, 0x65, 0x49, 0x6d, 0x67, 0x4c, 0x6e, 0x78];
}

/// Magic value for a SE-(boot)header
#[derive(Debug)]
pub struct BootHdrMagic;
impl MagicValue<8> for BootHdrMagic {
    const MAGIC: [u8; 8] = [0x49, 0x42, 0x4d, 0x53, 0x65, 0x63, 0x45, 0x78];
}

/// Tries to seek to the start of the Secure Execution header.
///
/// Returns `false` if no Secure Execution header found, `true` otherwise.
///
/// # Errors
///
/// In the very unlikely case an IO error can appear when seeking to the
/// beginning of the header.
pub fn seek_se_hdr_start<R>(img: &mut R) -> Result<bool>
where
    R: Read + Seek,
{
    const BUF_SIZE: i64 = 8;
    static_assert!(BootHdrMagic::MAGIC.len() == BUF_SIZE as usize);

    let old_position = img.stream_position()?;
    let max_iter: usize = if !SeImgMetaData::seek_start(img)? {
        // Search from the previous position.
        img.seek(std::io::SeekFrom::Start(old_position))?;
        0x15
    } else {
        let mut img_metadata_bytes = vec![0u8; size_of::<SeImgMetaData>()];
        // read in the header
        img.read_exact(&mut img_metadata_bytes)?;
        // Cannot fail because the buffer has the same size as SeImgMetaData.
        let img_metadata = SeImgMetaData::ref_from_bytes(&img_metadata_bytes).unwrap();
        let img_metadata_version = img_metadata.version();
        if img_metadata_version != SeImgMetaData::V1 {
            warn!("Unknown Secure Execution boot image version {img_metadata_version}");
        }

        img.seek(std::io::SeekFrom::Start(img_metadata.hdr_off.into()))?;
        1
    };

    let mut buf = [0; BUF_SIZE as usize];
    for _ in 0..max_iter {
        match img.read_exact(&mut buf) {
            Ok(it) => it,
            Err(_) => return Ok(false),
        };

        if BootHdrMagic::starts_with_magic(&buf) {
            // go back to the beginning of the header
            img.seek(Current(-BUF_SIZE))?;

            return Ok(true);
        }
        // goto next page start
        // or report invalid file format if file ends "early"
        match img.seek(Current(PAGESIZE as i64 - BUF_SIZE)) {
            Ok(it) => it,
            Err(_) => return Ok(false),
        };
    }
    Ok(false)
}

impl BootHdrTags {
    /// Returns a reference to the SE-header tag of this [`BootHdrTags`].
    pub fn tag(&self) -> &[u8; 16] {
        &self.tag
    }

    /// Creates a new [`BootHdrTags`]. Useful for writing tests.
    #[doc(hidden)]
    pub const fn new(pld: [u8; 64], ald: [u8; 64], tld: [u8; 64], tag: [u8; 16]) -> Self {
        Self { ald, tld, pld, tag }
    }

    /// Deserializes a (SE) boot header and extracts the tags.
    ///
    /// Searches for the header; if found extracts the tags.
    ///
    /// # Errors
    ///
    /// This function will return an error if the header could not be found in
    /// `img` or is invalid.
    pub fn from_se_image<R>(img: &mut R) -> Result<Self>
    where
        R: Read + Seek,
    {
        if !seek_se_hdr_start(img)? {
            debug!("No boot hdr found");
            return Err(Error::InvBootHdr);
        }
        // read in the header
        let mut hdr = vec![0u8; size_of::<BootHdrHead>()];
        img.read_exact(&mut hdr)?;

        // Very unlikely - seek_se_hdr_start should point to a header or error-out
        if !BootHdrMagic::starts_with_magic(&hdr) {
            debug!("Inv magic");
            return Err(Error::InvBootHdr);
        }

        let hdr_head = match BootHdrHead::read_from_prefix(hdr.as_mut_slice()) {
            Ok((hdr, _)) => hdr,
            Err(_) => {
                debug!("Boot hdr is too small");
                return Err(Error::InvBootHdr);
            }
        };

        // Some sanity checks
        if hdr_head.version.get() != 0x100 {
            debug!("Unsupported hdr-version: {:0>4x}", hdr_head.version.get());
            return Err(Error::InvBootHdr);
        }

        // go to the Boot header tag
        img.seek(Current(
            hdr_head.size.get() as i64
                - size_of::<BootHdrHead>() as i64
                - BootHdrHead::TAG_SIZE as i64,
        ))?;

        // read in the tag
        let mut tag = [0u8; BootHdrHead::TAG_SIZE];
        img.read_exact(tag.as_mut_slice())?;

        Ok(Self {
            pld: hdr_head.pld,
            ald: hdr_head.ald,
            tld: hdr_head.tld,
            tag,
        })
    }
}

#[repr(C)]
#[derive(Debug, Clone, FromBytes)]
struct BootHdrHead {
    magic: U64<BigEndian>,
    version: U32<BigEndian>,
    size: U32<BigEndian>,
    iv: [u8; 12],
    res1: u32,
    nks: U64<BigEndian>,
    sea: U64<BigEndian>,
    nep: U64<BigEndian>,
    pcf: U64<BigEndian>,
    user_pubkey: [u8; 160],
    pld: [u8; Self::DIGEST_SIZE],
    ald: [u8; Self::DIGEST_SIZE],
    tld: [u8; Self::DIGEST_SIZE],
}
assert_size!(BootHdrHead, 0x1A0);
impl BootHdrHead {
    const DIGEST_SIZE: usize = 0x40;
    const TAG_SIZE: usize = 0x10;
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::{get_test_asset, Error};

    const EXP_HDR: BootHdrTags = BootHdrTags {
        pld: [
            0xbe, 0x94, 0xb5, 0xea, 0xb3, 0xc1, 0xb1, 0x18, 0xc7, 0x57, 0xd7, 0xdb, 0x7e, 0xa0,
            0xf6, 0x5d, 0x9b, 0x64, 0x82, 0x3a, 0x8d, 0xc5, 0x5b, 0xf8, 0xa8, 0x72, 0x5b, 0x58,
            0x07, 0x2d, 0x9d, 0x42, 0x58, 0xc5, 0x3e, 0x8a, 0x5d, 0xa8, 0x2d, 0xfb, 0x21, 0x92,
            0xd9, 0x1d, 0x07, 0xbc, 0x1c, 0x39, 0xb9, 0x5d, 0x63, 0x21, 0xd3, 0xba, 0x16, 0xa7,
            0x51, 0xa6, 0xe3, 0xe3, 0x2f, 0x3e, 0x01, 0x61,
        ],
        ald: [
            0x28, 0x58, 0xc3, 0x36, 0x8b, 0x2a, 0x0a, 0xf0, 0xc5, 0xea, 0x0f, 0xde, 0x79, 0x05,
            0xeb, 0x15, 0xaf, 0x9c, 0xd1, 0xdd, 0x73, 0x71, 0x65, 0x93, 0x3c, 0xda, 0xa2, 0xb8,
            0x50, 0xb6, 0xa8, 0xe2, 0xf0, 0xf4, 0x2c, 0x7b, 0x36, 0xdd, 0x53, 0x81, 0x09, 0x62,
            0x88, 0xdc, 0x09, 0x2d, 0xaa, 0x8a, 0x6f, 0xac, 0xec, 0x25, 0x34, 0x13, 0x7b, 0xc9,
            0x4c, 0xa8, 0x0b, 0xda, 0x4f, 0xcb, 0x93, 0x28,
        ],
        tld: [
            0x48, 0x60, 0xeb, 0xcf, 0x7b, 0x9d, 0x24, 0xeb, 0x90, 0x9a, 0x79, 0x53, 0x56, 0xad,
            0x32, 0xc9, 0x36, 0xb6, 0x21, 0x65, 0x98, 0x8a, 0x9f, 0xfc, 0xd6, 0x61, 0x70, 0xdb,
            0xc5, 0x90, 0xc2, 0x30, 0x10, 0xd7, 0x95, 0x2f, 0xa8, 0x82, 0xd1, 0xbb, 0x79, 0x55,
            0x8f, 0x9b, 0xe0, 0xa5, 0x49, 0xd8, 0xd7, 0xa9, 0x4a, 0xe7, 0x20, 0xe5, 0xc0, 0x76,
            0x0a, 0x82, 0x5d, 0x47, 0x9f, 0xe6, 0x7a, 0xf5,
        ],
        tag: [
            0x92, 0x30, 0x9d, 0x45, 0x89, 0xb9, 0xa8, 0x5b, 0x42, 0x7f, 0x87, 0x53, 0x17, 0x1d,
            0x15, 0x20,
        ],
    };

    #[test]
    fn from_se_image_hdr() {
        let bin_hdr = get_test_asset!("exp/secure_guest.hdr");
        let hdr_tags = BootHdrTags::from_se_image(&mut Cursor::new(*bin_hdr)).unwrap();
        assert_eq!(hdr_tags, EXP_HDR);
    }

    #[test]
    fn from_se_image_fail() {
        let bin_hdr = get_test_asset!("exp/secure_guest.hdr");
        let short_hdr = &bin_hdr[1..];

        assert!(matches!(
            BootHdrTags::from_se_image(&mut Cursor::new(short_hdr)),
            Err(Error::InvBootHdr)
        ));

        // mess up magic
        let mut bin_hdr_copy = *bin_hdr;
        bin_hdr_copy.swap(0, 1);
        assert!(matches!(
            BootHdrTags::from_se_image(&mut Cursor::new(bin_hdr_copy)),
            Err(Error::InvBootHdr)
        ));

        // header is at a non expected position
        let mut img = vec![0u8; PAGESIZE];
        img[0x008..0x288].copy_from_slice(bin_hdr);
        assert!(matches!(
            BootHdrTags::from_se_image(&mut Cursor::new(img)),
            Err(Error::InvBootHdr)
        ));
    }

    #[test]
    fn from_se_image_img() {
        let mut img = vec![0u8; 0x13000];
        let bin_hdr = get_test_asset!("exp/secure_guest.hdr");
        img[0x12000..0x12280].copy_from_slice(bin_hdr);
        let hdr_tags = BootHdrTags::from_se_image(&mut Cursor::new(img)).unwrap();
        assert_eq!(hdr_tags, EXP_HDR);
    }

    #[test]
    fn tags_convert_u8() {
        let bin_hdr = get_test_asset!("exp/secure_guest.hdr");
        let hdr_tags = BootHdrTags::from_se_image(&mut Cursor::new(*bin_hdr)).unwrap();
        let ser: &[u8] = hdr_tags.as_ref();
        let mut ser = ser.to_vec();

        let der: BootHdrTags = ser.clone().try_into().unwrap();
        assert_eq!(hdr_tags, der);

        ser.pop();
        let der: Result<BootHdrTags> = ser.clone().try_into();
        assert!(matches!(der, Err(Error::InvBootHdrSize(_))));

        ser.push(17);
        ser.push(17);
        let der: Result<BootHdrTags> = ser.clone().try_into();
        assert!(matches!(der, Err(Error::InvBootHdrSize(_))));
    }

    #[test]
    fn se_img_metadata() {
        let metadata = SeImgMetaData::new_v1(0x14000, 0x16000);
        let data = [
            83, 101, 73, 109, 103, 76, 110, 120, 0, 0, 0, 0, 0, 1, 64, 0, 0, 0, 0, 1, 0, 0, 0, 0,
            0, 1, 96, 0,
        ];
        assert_eq!(metadata.as_bytes(), &data);
        assert_eq!(SeImgMetaData::ref_from_bytes(&data), Ok(&metadata));

        assert_eq!(metadata.version(), SeImgMetaData::V1);
    }
}
