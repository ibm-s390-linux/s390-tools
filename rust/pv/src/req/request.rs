// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp.
use std::mem::size_of;

use openssl::pkey::{PKey, Public};
use zerocopy::{FromBytes, Immutable, KnownLayout};

use crate::crypto::{decrypt_aead, SymKey, SymKeyType};
use crate::req::context::ReqEncrCtx;
use crate::req::header::RequestHdr;
use crate::request::Confidential;
use crate::{Error, Result};

/// A trait representing a request for the Ultravisor.
///
/// All requests share a few things:
/// * All requests need to be encrypted on a trusted machine
/// * All requests have at least one Hostkeyslot
///
/// The encryption setup is handled by [`ReqEncrCtx`]. Implementers need to pass the data to the
/// `ReqEncrCtx` when implementing `encrypt`. A hostkey should be represented by
/// [`Keyslot`](super::Keyslot) during encryption.
///
/// An UV request consists of an authenticated area (AAD), an encrypted area (Encr) and a 16 byte
/// tag. The AAD contains a general header and Request type defined data (including Keyslots). It
/// is encrypted with an Request protection key (symmetric). This key is encrypted with a
/// (generated) private key and the public key of the host system (Host key)
/// ```none
///  _______________________________________________________________
///  | MAGIC (8)                       Version Number (4)  Size (4)|
///  |                     IV (12)                     Reserved (4)|
///  | Reserved (7) Num keyslots (1)   Reserved(4)    Encr Size (4)|
///  |     ---------------------------------------------------     |
///  |                Request type dependent AAD data              |
///  |     ----------------------------------------------------    |
///  |            Encrypted (request type dependent) data          |
///  |     ----------------------------------------------------    |
///  |                   AES GCM Tag (16)                          |
///  |_____________________________________________________________|
/// ```
pub trait Request {
    /// Encrypt the request into its binary format
    ///
    /// # Errors
    ///
    /// This function will return an error if the encryption fails, the request does not have at
    /// least a hostkey, or other implementation dependent contracts are not met.
    fn encrypt(&self, ctx: &ReqEncrCtx) -> Result<Vec<u8>>;
    /// Add a host-key to this request
    ///
    /// Must be called at least once, otherwise {`Request::encrypt`} will fail
    fn add_hostkey(&mut self, hostkey: PKey<Public>);
}

/// A struct to represent some parts of a binary/encrypted request.
#[derive(Debug)]
#[allow(clippy::len_without_is_empty)]
pub struct BinReqValues<'a> {
    iv: &'a [u8],
    aad: &'a [u8],
    req_dep_aad: &'a [u8],
    encr: &'a [u8],
    tag: &'a [u8],
    version: u32,
    len: usize,
}

impl<'a> BinReqValues<'a> {
    pub(crate) const TAG_LEN: usize = SymKeyType::AES_256_GCM_TAG_LEN;

    /// Get the locations from this request.
    ///
    /// Does minimal sanity test, just tests to prevent panics.
    /// `req` may be larger than the actual request.
    pub(crate) fn get(req: &'a [u8]) -> Result<Self> {
        let (hdr, _) = RequestHdr::read_from_prefix(req).map_err(|_| Error::BinRequestSmall)?;
        let rql = hdr.rql.get() as usize;
        let sea = hdr.sea.get() as usize;

        if rql < req.len() || sea + Self::TAG_LEN > rql {
            return Err(Error::BinRequestSmall);
        }
        let aad_size = rql - sea - Self::TAG_LEN;
        if aad_size < size_of::<RequestHdr>() {
            return Err(Error::BinRequestSmall);
        }

        let iv = &req[0x10..0x1c];
        let aad = &req[..aad_size];
        let req_dep_aad = &req[size_of::<RequestHdr>()..aad_size];
        let encr = &req[aad_size..(aad_size + sea)];
        let tag = &req[rql - Self::TAG_LEN..];

        Ok(Self {
            iv,
            aad,
            req_dep_aad,
            encr,
            tag,
            version: hdr.rqvn.get(),
            len: rql,
        })
    }

    /// Returns the version of this [`BinReqValues`].
    pub(crate) fn version(&self) -> u32 {
        self.version
    }

    /// Returns the length of this [`BinReqValues`].
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Returns the size of the encrypted area
    pub(crate) fn sea(&self) -> u32 {
        self.encr.len() as u32
    }

    /// Decrypts the encrypted area with the provided key
    pub(crate) fn decrypt(&self, key: &SymKey) -> Result<Confidential<Vec<u8>>> {
        let result = decrypt_aead(key, self.iv, self.aad, self.encr, self.tag)?;
        Ok(result.into_plain())
    }

    /// Returns a reference to the request dependent authenticated area of this [`BinReqValues`]
    /// already interpreted.
    ///
    /// If target struct is larger than the request depended-AAD None is returned. See
    /// [`FromBytes::ref_from_prefix`]
    pub(crate) fn req_dep_aad<T>(&self) -> Option<&T>
    where
        T: FromBytes + Sized + Immutable + KnownLayout,
    {
        T::ref_from_prefix(self.req_dep_aad).map(|s| s.0).ok()
    }

    /// Returns a reference to the tag of this [`BinReqValues`].
    pub(crate) fn tag(&self) -> &[u8] {
        self.tag
    }
}

#[cfg(test)]
mod tests {
    use zerocopy::IntoBytes;

    use super::*;
    use crate::get_test_asset;
    use crate::req::header::RequestHdr;
    use crate::req::{Aad, Keyslot, ReqEncrCtx};
    use crate::request::SymKey;
    use crate::test_utils::*;

    static TEST_MAGIC: [u8; 8] = 0x12345689abcdef00u64.to_be_bytes();

    #[test]
    fn encr_build_aad() {
        let (cust_key, host_key) = get_test_keys();
        let ks = Keyslot::new(host_key);
        let ctx = ReqEncrCtx::new_aes_256(
            Some([0x11; 12]),
            Some(cust_key),
            Some(SymKey::Aes256([0x17; 32].into())),
        )
        .unwrap();
        let v = [0x55; 8];
        let aad = Aad::Plain(&v);
        let aad = ctx
            .build_aad(0x200, &vec![aad, Aad::Ks(&ks)], 16, Some(TEST_MAGIC))
            .unwrap();

        let mut aad_exp = vec![
            0x12, 0x34, 0x56, 0x89, 0xab, 0xcd, 0xef, 0, // progr
            0, 0, 2, 0, // vers
            0, 0, 0, 168, // size
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, // iv
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // res
            1, // nks
            0, 0, 0, 0, // res
            0, 0, 0, 16, // sea
            0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, // aad
        ];
        aad_exp.extend_from_slice(get_test_asset!("exp/keyslot.bin"));
        assert_eq!(&aad, &aad_exp);
    }

    #[test]
    fn encr_build_aad_nks_no() {
        let ctx = ReqEncrCtx::new_aes_256(Some([0x11; 12]), None, None).unwrap();

        let aad = Vec::<Aad>::new();

        let aad = ctx.build_aad(0x200, &aad, 16, Some(TEST_MAGIC));
        assert!(matches!(aad, Err(Error::NoHostkey)));
    }

    #[test]
    fn encr_build_aad_nks_many() {
        let (_, host_key) = get_test_keys();
        let ctx = ReqEncrCtx::new_aes_256(Some([0x11; 12]), None, None).unwrap();

        let ks: Vec<Keyslot> = (0..257).map(|_| Keyslot::new(host_key.clone())).collect();
        let mut aad = Vec::<Aad>::new();
        ks.iter().for_each(|ks| aad.push(Aad::Ks(ks)));

        let aad = ctx.build_aad(0x200, &aad, 16, Some(TEST_MAGIC));
        assert!(matches!(aad, Err(Error::ManyHostkeys)));
    }
    #[test]
    fn encr_build_aad_nks() {
        let (_, host_key) = get_test_keys();
        let ctx = ReqEncrCtx::new_aes_256(Some([0x11; 12]), None, None).unwrap();

        let ks = [
            Keyslot::new(host_key.clone()),
            Keyslot::new(host_key.clone()),
            Keyslot::new(host_key),
        ];
        let mut aad = Vec::<Aad>::new();
        ks.iter().for_each(|ks| aad.push(Aad::Ks(ks)));

        let aad = ctx.build_aad(0x200, &aad, 16, Some(TEST_MAGIC)).unwrap();

        assert_eq!(aad.get(39).unwrap(), &3u8);
    }

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
