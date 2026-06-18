// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp.

use zerocopy::{BigEndian, FromBytes, Immutable, IntoBytes, U32};

use crate::assert_size;

/// Representation of the shared parts of the request header.
/// Used by [`ReqEncrCtx`]
#[repr(C)]
#[derive(Debug, Copy, Clone, IntoBytes, FromBytes, Immutable)]
pub struct RequestHdr {
    magic: [u8; 8],
    pub(crate) rqvn: U32<BigEndian>,
    pub(crate) rql: U32<BigEndian>,
    iv: [u8; 12],
    reserved1c: [u8; 4],
    reserved20: [u8; 7],
    nks: u8,
    reserved28: u32,
    pub(crate) sea: U32<BigEndian>,
}
assert_size!(RequestHdr, 48);

impl RequestHdr {
    pub(crate) fn new(
        rqvn: u32,
        rql: u32,
        iv: [u8; 12],
        nks: u8,
        sea: u32,
        magic: Option<[u8; 8]>,
    ) -> Self {
        Self {
            magic: magic.unwrap_or_default(),
            rqvn: rqvn.into(),
            rql: rql.into(),
            iv,
            reserved1c: [0; 4],
            reserved20: [0; 7],
            nks,
            reserved28: 0,
            sea: sea.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use zerocopy::IntoBytes;

    use super::*;

    static TEST_MAGIC: [u8; 8] = 0x12345689abcdef00u64.to_be_bytes();

    #[test]
    fn req_hdr() {
        let hdr = RequestHdr::new(0x200, 22, [0x11; 12], 15, 44, None);
        let hdr_bin = hdr.as_bytes();
        let hdr_bin_exp = [
            0u8, 0, 0, 0, 0, 0, 0, 0, // magic
            0, 0, 2, 0, // vers
            0, 0, 0, 22, // size
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, // iv
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // res
            15, // nks
            0, 0, 0, 0, // res
            0, 0, 0, 44, // sea
        ];
        assert_eq!(hdr_bin, &hdr_bin_exp);
    }

    #[test]
    fn req_hdr2() {
        let mut hdr = RequestHdr::new(0x200, 0x1234, [0x11; 12], 15, 44, Some(TEST_MAGIC));
        let hdr_bin = hdr.as_mut_bytes();
        let hdr_bin_exp = [
            0x12, 0x34, 0x56, 0x89, 0xab, 0xcd, 0xef, 0, // magic
            0, 0, 2, 0, // vers
            0, 0, 0x12, 0x34, // size
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, // iv
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // res
            15, // nks
            0, 0, 0, 0, // res
            0, 0, 0, 44, // sea
        ];
        assert_eq!(hdr_bin, &hdr_bin_exp);
    }
}
