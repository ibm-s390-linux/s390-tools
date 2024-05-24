// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

use crate::assert_size;
use crate::crypto::{
    decrypt_aes_gcm, derive_key, encrypt_aes_gcm, gen_ec_key, random_array, AesGcmResult, SymKey,
    SymKeyType, AES_256_GCM_TAG_SIZE,
};
use crate::misc::to_u32;
use crate::request::Confidential;
use crate::{Error, Result};
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroupRef, EcPointRef};
use openssl::error::ErrorStack;
use openssl::hash::{hash, MessageDigest};
use openssl::pkey::{PKey, PKeyRef, Private, Public};
use pv_core::request::{RequestMagic, RequestVersion};
use std::convert::TryInto;
use std::mem::size_of;
use zerocopy::{AsBytes, BigEndian, FromBytes, FromZeroes, U32};

/// Encrypt a _secret_ using self and a given private key.
pub trait Encrypt {
    /// Encrypts `secret` using `self` and `priv_key` the encryption.
    ///
    /// # Returns
    /// the encrypted data.
    ///
    /// # Errors
    ///
    /// This function will return an error if OpenSSL could not encrypt the secret.
    fn encrypt(&self, secret: &[u8], priv_key: &PKeyRef<Private>) -> Result<Vec<u8>> {
        let mut res = Vec::with_capacity(80);
        self.encrypt_to(secret, priv_key, &mut res)?;
        Ok(res)
    }

    /// Encrypts `secret` using `self` and `priv_key` the encryption.
    /// Appends the encrypted data to `to`
    ///
    /// # Returns
    /// The encrypted data.
    ///
    /// # Errors
    ///
    /// This function will return an error if OpenSSL could not encrypt the secret.
    fn encrypt_to(
        &self,
        secret: &[u8],
        priv_key: &PKeyRef<Private>,
        to: &mut Vec<u8>,
    ) -> Result<()>;
}

/// Types of Authenticated Data
#[allow(missing_debug_implementations)]
pub enum Aad<'a> {
    /// Authenticated Keyslot
    Ks(&'a Keyslot),
    /// Unchanged authenticated data
    Plain(&'a [u8]),
    /// Authenticated  data that has to be encrypted in beforehand
    Encr(&'a dyn Encrypt),
}

/// IBM Z Host key-slot
///
/// Layout in binary format:
/// ```none
/// _______________________________________________________________
/// |   Public Host Key Hash (32)                                 |
/// |   Wrapped(=Encrypted) Request Protection Key(32)            |
/// |   Key Slot Tag (16)                                         |
/// |_____________________________________________________________|
/// ```
#[derive(Debug, Clone)]
pub struct Keyslot(PKey<Public>);

impl Keyslot {
    /// Size of a host-key hash
    pub const PHKH_SIZE: u32 = 0x20;

    /// Creates a new Keyslot from the provided public key
    pub fn new(hostkey: PKey<Public>) -> Self {
        Self(hostkey)
    }
}

impl Encrypt for Keyslot {
    /// Encrypts the given request protection key `prot_key`.
    ///
    /// The AES256 encryption key is derived from `self` as public key, and `priv_key` as private
    /// key.
    ///
    /// # Returns
    /// The encrypted Keyslot.
    ///
    /// # Errors
    ///
    /// This function will return an error if OpenSSL could not encrypt the secret.
    fn encrypt_to(
        &self,
        prot_key: &[u8],
        priv_key: &PKeyRef<Private>,
        to: &mut Vec<u8>,
    ) -> Result<()> {
        let derived_key = derive_key(priv_key, &self.0)?;
        let mut wrpk_and_kst =
            encrypt_aes_gcm(&derived_key.into(), &[0; 12], &[], prot_key)?.data();
        let phk: EcdhPubkeyCoord = self.0.as_ref().try_into()?;

        to.reserve(80);
        to.extend_from_slice(&hash(MessageDigest::sha256(), phk.as_ref())?);
        to.append(&mut wrpk_and_kst);
        Ok(())
    }
}

/// Context used to manage the encryption of requests.
/// Intended to be used by [`Request`] implementations
#[derive(Debug)]
pub struct ReqEncrCtx {
    iv: [u8; 12],
    priv_key: PKey<Private>,
    prot_key: SymKey,
}
impl ReqEncrCtx {
    /// Create a new encryption context that uses AES256.
    ///
    /// * `iv` - Initialization vector for the request encryption
    /// * `priv_key` - Private key to wrap [`Keyslot`]
    /// * `prot_key` - Symmetric key for request encryption. Part of [`Keyslot`]
    ///
    /// If an argument is set to `None` a ranom is generated
    ///
    /// # Errors
    ///
    /// This function will return an error if OpenSSL could not generate a random value.
    pub fn new_aes_256<I, P, S>(iv: I, priv_key: P, prot_key: S) -> Result<Self>
    where
        I: Into<Option<[u8; 12]>>,
        P: Into<Option<PKey<Private>>>,
        S: Into<Option<SymKey>>,
    {
        let iv = iv.into().unwrap_or(random_array()?);
        let priv_key = priv_key.into().unwrap_or(gen_ec_key()?);
        let prot_key = prot_key
            .into()
            .unwrap_or(SymKey::random(SymKeyType::Aes256)?);
        Ok(ReqEncrCtx {
            iv,
            priv_key,
            prot_key,
        })
    }

    /// Create a new encryption context with random input values.
    ///
    /// # Errors
    ///
    /// This function will return an error if OpenSSL could not generate a random value.
    pub fn random(ket_tp: SymKeyType) -> Result<Self> {
        match ket_tp {
            SymKeyType::Aes256 => Self::new_aes_256(None, None, None),
        }
    }

    /// Build the authenticated data for a request.
    /// # Returns
    /// ```none
    /// _______________________________________________________________
    /// | MAGIC (8)                       Version Number (4)  Size (4)|
    /// |                     IV (12)                     Reserved (4)|
    /// | Reserved (7) Num keyslots (1)   Reserved(4)    Encr Size (4)|
    /// |     ---------------------------------------------------     |
    /// |                Request type dependent AAD data              |
    /// |-------------------------------------------------------------|
    /// ```
    pub fn build_aad<O>(
        &self,
        version: RequestVersion,
        aad: &Vec<Aad>,
        encr_size: usize,
        magic: O,
    ) -> Result<Vec<u8>>
    where
        O: Into<Option<RequestMagic>>,
    {
        self.build_aad_impl(version, aad, encr_size, magic.into())
    }

    /// Concrete implementation for [`ReqEncrCtx::build_aad`].
    fn build_aad_impl(
        &self,
        version: RequestVersion,
        aad: &Vec<Aad>,
        encr_size: usize,
        magic: Option<RequestMagic>,
    ) -> Result<Vec<u8>> {
        let nks = aad.iter().filter(|a| matches!(a, Aad::Ks(_))).count();
        let nks: u8 = match nks {
            0 => Err(Error::NoHostkey),
            n if n > u8::MAX as usize => Err(Error::ManyHostkeys),
            n => Ok(n as u8),
        }?;
        let mut auth_data: Vec<u8> = Vec::with_capacity(2048);

        // reserve space for the request header
        auth_data.resize(size_of::<RequestHdr>(), 0);

        for a in aad {
            match a {
                Aad::Plain(p) => auth_data.extend_from_slice(p),
                Aad::Ks(ks) => {
                    ks.encrypt_to(self.prot_key.value(), &self.priv_key, &mut auth_data)?
                }
                Aad::Encr(e) => {
                    e.encrypt_to(self.prot_key.value(), &self.priv_key, &mut auth_data)?
                }
            }
        }

        let rql = to_u32(auth_data.len() + encr_size + 16).ok_or_else(|| {
            pv_core::Error::Specification("Configured request size to large".to_string())
        })?;
        let sea = to_u32(encr_size)
            .ok_or_else(|| pv_core::Error::Specification("Encrypted size to large".to_string()))?;

        let req_hdr = RequestHdr::new(version, rql, self.iv, nks, sea, magic);
        // copy request header to the start of the request
        auth_data[..size_of::<RequestHdr>()].copy_from_slice(req_hdr.as_bytes());
        Ok(auth_data)
    }

    /// Get the public coordinates from the private key (Customer private key)
    /// # Errors
    ///
    /// This function will return an error if the public key could not be extracted by OpenSSL.
    /// Very unlikely.
    pub fn key_coords(&self) -> Result<EcdhPubkeyCoord> {
        self.priv_key.as_ref().try_into().map_err(Error::Crypto)
    }

    /// Encrypt confidential Data with this encryption context and provide a GCM tag.
    ///
    /// * `aad` - additional authentic data
    /// * `conf` - data to be encrypted
    ///
    /// # Returns
    /// [`Vec<u8>`] with the following content:
    /// 1. `aad`
    /// 2. `encr(conf)`
    /// 3. `aes gcm tag`
    ///
    /// # Errors
    ///
    /// This function will return an error if the data could not be encrypted by OpenSSL.
    pub(crate) fn encrypt_aead(&self, aad: &[u8], conf: &[u8]) -> Result<AesGcmResult> {
        encrypt_aes_gcm(&self.prot_key, &self.iv, aad, conf)
    }

    /// Returns a reference to the request protection key of this [`ReqEncrCtx`].
    pub fn prot_key(&self) -> &SymKey {
        &self.prot_key
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct EcdhPubkeyCoord([u8; 160]);
impl AsRef<[u8]> for EcdhPubkeyCoord {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// Get the pub ECDH coordinates in the format the Ultravisor expects it:
/// The two coordinates are padded to 80 bytes each.
fn get_pub_ecdh_points(pkey: &EcPointRef, grp: &EcGroupRef) -> Result<[u8; 160], ErrorStack> {
    const ECDH_PUB_KEY_COORD_POINT_SIZE: i32 = 0x50;
    let mut x = BigNum::new()?;
    let mut y = BigNum::new()?;
    let mut bn_ctx = BigNumContext::new()?;
    pkey.affine_coordinates(grp, &mut x, &mut y, &mut bn_ctx)?;
    let mut coord: Vec<u8> = x.to_vec_padded(ECDH_PUB_KEY_COORD_POINT_SIZE)?;
    coord.append(&mut y.to_vec_padded(ECDH_PUB_KEY_COORD_POINT_SIZE)?);
    Ok(coord.try_into().unwrap())
}

macro_rules! ecdh_from {
    ($type: ty) => {
        impl TryFrom<&PKeyRef<$type>> for EcdhPubkeyCoord {
            type Error = ErrorStack;

            fn try_from(key: &PKeyRef<$type>) -> Result<Self, Self::Error> {
                let k = key.ec_key()?;
                k.check_key()?;
                let grp = k.group();
                let pub_key = k.public_key();
                let coord = get_pub_ecdh_points(pub_key, grp)?;
                Ok(EcdhPubkeyCoord(coord))
            }
        }
    };
}

ecdh_from!(Private);
ecdh_from!(Public);

/// Representation of the shared parts of the request header.
/// Used by [`ReqEncrCtx`]
#[repr(C)]
#[derive(Debug, Copy, Clone, AsBytes, FromBytes, FromZeroes)]
struct RequestHdr {
    magic: [u8; 8],
    rqvn: U32<BigEndian>,
    rql: U32<BigEndian>,
    iv: [u8; 12],
    reserved1c: [u8; 4],
    reserved20: [u8; 7],
    nks: u8,
    reserved28: u32,
    sea: U32<BigEndian>,
}
assert_size!(RequestHdr, 48);

impl RequestHdr {
    fn new(rqvn: u32, rql: u32, iv: [u8; 12], nks: u8, sea: u32, magic: Option<[u8; 8]>) -> Self {
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

/// A trait representing a request for the Ultravisor.
///
/// All requests share a few things:
/// * All requests need to be encrypted on a trusted machine
/// * All requests have at least one Hostkeyslot
///
/// The encryption setup is handled by [`ReqEncrCtx`]. Implementers need to pass the data to the
/// `ReqEncrCtx` when implementing `encrypt`. A hostkey should be represented by [`Keyslot`] during
/// encryption.
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
    pub(crate) const TAG_LEN: usize = AES_256_GCM_TAG_SIZE;

    /// Get the locations from this request.
    ///
    /// Does minimal sanity test, just tests to prevent panics.
    /// `req` may be larger than the actual request.
    pub fn get(req: &'a [u8]) -> Result<Self> {
        let hdr = RequestHdr::read_from_prefix(req).ok_or(Error::BinRequestSmall)?;
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
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Returns the length of this [`BinReqValues`].
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns the size of the encrypted area
    pub fn sea(&self) -> u32 {
        self.encr.len() as u32
    }

    /// Decrypts the encrypted area with the provided key
    pub fn decrypt(&self, key: &SymKey) -> Result<Confidential<Vec<u8>>> {
        decrypt_aes_gcm(key, self.iv, self.aad, self.encr, self.tag)
    }

    /// Returns a reference to the request dependent authenticated area of this [`BinReqValues`]
    /// already interpreted.
    ///
    /// If target struct is larger than the request depended-AAD None is returned. See
    /// [`FromBytes::ref_from_prefix`]
    pub fn req_dep_aad<T>(&self) -> Option<&T>
    where
        T: FromBytes + Sized,
    {
        T::ref_from_prefix(self.req_dep_aad)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::get_test_asset;
    use crate::request::SymKey;
    use crate::test_utils::*;
    use openssl::ec::EcGroup;
    use openssl::nid::Nid;

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
        let hdr_bin = hdr.as_bytes_mut();
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

    #[test]
    fn keyslot() {
        let (cust_key, host_key) = get_test_keys();
        let exp_keyslot = get_test_asset!("exp/keyslot.bin").to_vec();

        let keyslot = Keyslot::new(host_key);
        let encr_ks = keyslot.encrypt(&[0x17u8; 32], &cust_key).unwrap();

        assert_eq!(exp_keyslot, encr_ks);

        let encr_ks = keyslot.encrypt(&[0x16u8; 32], &cust_key).unwrap();
        assert_ne!(exp_keyslot, encr_ks);
    }

    #[test]
    fn get_pub_ecdh_points() {
        let (cust_key, _) = get_test_keys();

        let pub_key = get_test_asset!("keys/public_cust.bin");

        assert_eq!(pub_key.len(), 160);

        let points = cust_key.ec_key().unwrap();
        let points = points.public_key();
        let grp = EcGroup::from_curve_name(Nid::SECP521R1).unwrap();

        let points = super::get_pub_ecdh_points(points, &grp).unwrap();

        assert_eq!(&points, pub_key);
    }
}
