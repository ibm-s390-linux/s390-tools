// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023, 2024

use std::{
    io::{Read, Seek, SeekFrom::Current},
    mem::size_of,
};

// (SE) boot request control block aka SE header
use crate::{assert_size, request::MagicValue, static_assert, Error, Result, PAGESIZE};
use log::debug;
use zerocopy::{AsBytes, BigEndian, FromBytes, FromZeroes, U32, U64};

/// Struct containing all SE-header tags.
///
/// Contains:
/// Page List Digest (pld)
/// Address List Digest (ald)
/// Tweak List Digest (tld)
/// SE-Header Tag (tag)
#[repr(C)]
#[derive(Debug, Clone, Copy, AsBytes, PartialEq, Eq, FromBytes, FromZeroes)]
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
        Self::ref_from(&value)
            .ok_or_else(|| Error::InvBootHdrSize(value.len()))
            .copied()
    }
}

/// Magic value for a SE-(boot)header
#[derive(Debug)]
pub struct BootHdrMagic;
impl MagicValue<8> for BootHdrMagic {
    const MAGIC: [u8; 8] = [0x49, 0x42, 0x4d, 0x53, 0x65, 0x63, 0x45, 0x78];
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

    /// Returns `false` if no SE-header found, `true` otherwise.
    /// In the very unlikely case an IO error can appear
    /// when seeking to the beginning of the header.
    fn seek_se_hdr_start<R>(img: &mut R) -> Result<bool>
    where
        R: Read + Seek,
    {
        const MAX_ITER: usize = 0x15;
        const BUF_SIZE: i64 = 8;
        static_assert!(BootHdrMagic::MAGIC.len() == BUF_SIZE as usize);

        let mut buf = [0; BUF_SIZE as usize];
        for _ in [0; MAX_ITER] {
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
        if !Self::seek_se_hdr_start(img)? {
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
            Some(hdr) => hdr,
            None => {
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

        Ok(BootHdrTags {
            pld: hdr_head.pld,
            ald: hdr_head.ald,
            tld: hdr_head.tld,
            tag,
        })
    }
}

#[repr(C)]
#[derive(Debug, Clone, FromBytes, FromZeroes)]
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
    use crate::get_test_asset;
    use crate::Error;

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
}
