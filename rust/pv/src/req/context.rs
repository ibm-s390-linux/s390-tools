// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp.

use std::mem::size_of;

use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use pv_core::request::{RequestMagic, RequestVersion};
use zerocopy::IntoBytes;

use super::ec_coord::EcPubKeyCoord;
use super::encrypt::{Aad, Encrypt};
use super::header::RequestHdr;
use crate::crypto::{
    encrypt_aead, gen_ec_key, random_array, AeadEncryptionResult, SymKey, SymKeyType,
};
use crate::misc::to_u32;
use crate::{Error, Result};

/// Context used to manage the encryption of requests.
/// Intended to be used by [`Request`](super::Request) implementations
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
    /// * `priv_key` - Private key to wrap [`Keyslot`](super::Keyslot)
    /// * `prot_key` - Symmetric key for request encryption. Part of [`Keyslot`](super::Keyslot)
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
        let priv_key = priv_key.into().unwrap_or(gen_ec_key(Nid::SECP521R1)?);
        let prot_key = prot_key
            .into()
            .unwrap_or(SymKey::random(SymKeyType::Aes256Gcm)?);
        Ok(Self {
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
            SymKeyType::Aes256Gcm => Self::new_aes_256(None, None, None),
            SymKeyType::Aes256Xts => Err(Error::NoAeadKey),
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
    pub fn key_coords(&self) -> Result<EcPubKeyCoord> {
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
    pub(crate) fn encrypt_aead(&self, aad: &[u8], conf: &[u8]) -> Result<AeadEncryptionResult> {
        encrypt_aead(&self.prot_key, &self.iv, aad, conf)
    }

    /// Returns a reference to the request protection key of this [`ReqEncrCtx`].
    pub fn prot_key(&self) -> &SymKey {
        &self.prot_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::get_test_asset;
    use crate::req::keyslot::Keyslot;
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
}
