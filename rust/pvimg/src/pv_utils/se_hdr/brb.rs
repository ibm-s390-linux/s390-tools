// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024
use std::{
    io::{Read, Seek, SeekFrom},
    mem::size_of,
};

use deku::{ctx::Endian, prelude::*};
use enum_dispatch::enum_dispatch;
use pv::{
    request::{
        openssl::pkey::{PKey, PKeyRef, Private, Public},
        seek_se_hdr_start, Aes256XtsKey, Confidential, SymKey, SymKeyType,
    },
    static_assert,
};
use serde::Serialize;

pub use super::hdr_v1::{SeHdrBinV1, SeHdrDataV1};
use super::{PlaintextControlFlagsV1, SecretControlFlagsV1};
use crate::{
    misc::PAGESIZE,
    pv_utils::{
        error::{Error, Result},
        serializing::{ser_hex, serialize_to_bytes},
        uvdata::{
            AeadCipherTrait, AeadDataTrait, AeadPlainDataTrait, KeyExchangeTrait, UvDataPlainTrait,
            UvDataTrait,
        },
        uvdata_builder::{AeadCipherBuilderTrait, KeyExchangeBuilderTrait},
        PSW,
    },
};

#[repr(u32)]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, DekuRead, DekuWrite, Serialize)]
#[deku(
    endian = "endian",
    id_type = "u32",
    ctx = "endian: Endian",
    ctx_default = "Endian::Big"
)]
pub enum SeHdrVersion {
    /// Secure Execution header v1
    V1 = 0x100,
}

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq, DekuRead, DekuWrite, Serialize)]
#[deku(endian = "endian", ctx = "endian: Endian", ctx_default = "Endian::Big")]
pub struct SeHdrCommon {
    #[serde(serialize_with = "ser_hex")]
    pub magic: [u8; 8],
    pub version: SeHdrVersion,
}
static_assert!(::std::mem::size_of::<SeHdrCommon>() == 12);

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq, DekuRead, DekuWrite, Serialize)]
#[deku(endian = "endian", ctx = "endian: Endian", ctx_default = "Endian::Big")]
pub struct SeHdrCommonWithSize {
    pub magic: [u8; 8],
    pub version: SeHdrVersion,
    pub sehs: u32,
}
static_assert!(::std::mem::size_of::<SeHdrCommonWithSize>() == 16);

impl SeHdrCommon {
    /// Magic value for a SE-header (FIXME as soon as `concat_bytes!(b"IBMSecEx`") is stable)
    pub(crate) const MAGIC: &'static [u8; 8] = &[73, 66, 77, 83, 101, 99, 69, 120];

    pub(crate) const fn new(version: SeHdrVersion) -> Self {
        Self {
            magic: *Self::MAGIC,
            version,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, DekuRead, DekuWrite, Serialize)]
#[deku(endian = "Endian::Big")]
/// Secure Execution header structure
pub struct SeHdr {
    /// Common Secure Execution header part
    #[serde(flatten)]
    pub common: SeHdrCommon,
    #[serde(flatten)]
    #[deku(ctx = "common.version")]
    pub data: SeHdrVersioned,
}

#[derive(Clone, PartialEq, Eq, Debug, DekuRead, DekuWrite, Serialize)]
#[deku(endian = "Endian::Big")]
/// Plain data Secure Execution header structure
pub struct SeHdrPlain {
    #[serde(flatten)]
    pub common: SeHdrCommon,
    #[serde(flatten)]
    #[deku(ctx = "common.version")]
    pub data: SeHdrData,
}

#[enum_dispatch(AeadCipherTrait, AeadDataTrait, KeyExchangeTrait)]
#[derive(Clone, PartialEq, Eq, Debug, DekuRead, DekuWrite, Serialize)]
#[serde(untagged)]
#[deku(ctx = "_endian: Endian, version: SeHdrVersion", id = "version")]
pub enum SeHdrVersioned {
    #[deku(id = "SeHdrVersion::V1")]
    SeHdrBinV1(SeHdrBinV1),
}

#[enum_dispatch(
    AeadCipherTrait,
    AeadPlainDataTrait,
    KeyExchangeTrait,
    KeyExchangeBuilderTrait
)]
#[derive(Clone, PartialEq, Eq, Debug, DekuRead, DekuWrite, Serialize)]
#[serde(untagged)]
#[deku(ctx = "_endian: Endian, version: SeHdrVersion", id = "version")]
pub enum SeHdrData {
    #[deku(id = "SeHdrVersion::V1")]
    SeHdrDataV1(SeHdrDataV1),
}

impl AeadCipherBuilderTrait for SeHdrData {
    fn set_iv(&mut self, iv: &[u8]) -> Result<()> {
        match self {
            Self::SeHdrDataV1(data) => data.set_iv(iv),
        }
    }
}

#[enum_dispatch(SeHdrData)]
pub trait SeHdrPubBuilderTrait {
    // Payload related methods
    fn set_components(&mut self, meta: ComponentMetadata) -> Result<()>;
    fn set_pcf(&mut self, pcf: &PlaintextControlFlagsV1) -> Result<()>;
}

#[allow(dead_code)]
#[enum_dispatch(SeHdrData)]
pub trait SeHdrConfBuilderTrait {
    fn generate_cck(&self) -> Result<SymKey>;
    fn set_cck(&mut self, cck: Confidential<Vec<u8>>) -> Result<()>;
    fn set_psw(&mut self, psw: &PSW);
    fn set_scf(&mut self, scf: &SecretControlFlagsV1) -> Result<()>;
}

#[enum_dispatch(SeHdr)]
#[allow(unused)]
pub trait SeHdrTrait: UvDataTrait {}

#[enum_dispatch(SeHdr)]
#[allow(unused)]
pub trait SeHdrPlainTrait: UvDataPlainTrait {}

impl AeadCipherTrait for SeHdr {
    fn aead_key_type(&self) -> SymKeyType {
        self.data.aead_key_type()
    }

    fn iv(&self) -> &[u8] {
        self.data.iv()
    }

    fn aead_tag_size(&self) -> usize {
        self.data.aead_tag_size()
    }
}

impl AeadDataTrait for SeHdr {
    fn aad(&self) -> Result<Vec<u8>> {
        Ok([serialize_to_bytes(&self.common)?, self.data.aad()?].concat())
    }

    fn data(&self) -> Vec<u8> {
        self.data.data()
    }

    fn tag(&self) -> Vec<u8> {
        self.data.tag()
    }
}

impl KeyExchangeTrait for SeHdr {
    fn contains_hash<H: AsRef<[u8]>>(&self, hash: H) -> bool {
        self.data.contains_hash(hash)
    }

    fn contains<K: AsRef<PKeyRef<Public>>>(&self, key: K) -> Result<bool> {
        self.data.contains(key)
    }

    fn cust_pub_key(&mut self) -> Result<PKey<Public>> {
        self.data.cust_pub_key()
    }

    fn key_type(&self) -> SymKeyType {
        self.aead_key_type()
    }
}

impl UvDataTrait for SeHdr {
    type P = SeHdrPlain;
}

impl SeHdr {
    /// Seek to the start of the next Secure Execution header.
    ///
    /// # Errors
    ///
    /// This function will return an error if no Secure Execution header was
    /// found or the IO operation has failed.
    pub fn seek_sehdr<R: Read + Seek>(reader: &mut R, addr: Option<u64>) -> Result<()> {
        if let Some(addr) = addr {
            reader.seek(SeekFrom::Start(addr))?;
        }
        if !seek_se_hdr_start(reader)? {
            return Err(Error::NoSeHdrFound);
        }
        Ok(())
    }

    /// Serializes the [`SeHdr`] to a byte vector.
    ///
    /// # Errors
    ///
    /// This function will return an error if the Secure Execution header could
    /// not be serialized.
    pub fn as_bytes(&self) -> Result<Vec<u8>> {
        serialize_to_bytes(self)
    }

    /// Deserializes a Secure Execution header from an I/O stream.
    ///
    /// # Errors
    ///
    /// This function will return an error if no Secure Execution header could
    /// be read, e.g. because no Secure Execution header was found.
    pub fn try_from_io<R>(mut reader: R) -> Result<Self>
    where
        R: Read,
    {
        let common_size = size_of::<SeHdrCommonWithSize>();
        let mut data = vec![0_u8; common_size];

        reader.read_exact(&mut data)?;

        let (_, common) = SeHdrCommonWithSize::from_bytes((&data, 0))?;
        if &common.magic != SeHdrCommon::MAGIC {
            return Err(Error::NoSeHdrFound);
        }
        let sehs = common.sehs.try_into()?;

        // DoS attack prevention
        if sehs > 1024 * PAGESIZE {
            return Err(Error::InvalidSeHdr);
        }

        if sehs <= common_size {
            return Err(Error::InvalidSeHdr);
        }

        data.resize(sehs, 0);
        reader.read_exact(&mut data[common_size..])?;
        Self::try_from_data(&data).map_err(|_| Error::InvalidSeHdr)
    }
}

impl AeadCipherBuilderTrait for SeHdrPlain {
    fn set_iv(&mut self, iv: &[u8]) -> Result<()> {
        self.data.set_iv(iv)
    }
}

impl KeyExchangeBuilderTrait for SeHdrPlain {
    fn add_keyslot(
        &mut self,
        hostkey: &PKeyRef<Public>,
        aead_key: &SymKey,
        priv_key: &PKeyRef<Private>,
    ) -> Result<()> {
        self.data.add_keyslot(hostkey, aead_key, priv_key)
    }

    fn clear_keyslots(&mut self) -> Result<()> {
        self.data.clear_keyslots()
    }

    fn generate_private_key(&self) -> Result<PKey<Private>> {
        self.data.generate_private_key()
    }

    fn set_cust_public_key(&mut self, key: &PKeyRef<Private>) -> Result<()> {
        self.data.set_cust_public_key(key)
    }
}

#[derive(Debug, Clone)]
pub struct ComponentMetadataV1 {
    pub ald: [u8; 64],
    pub pld: [u8; 64],
    pub tld: [u8; 64],
    pub nep: u64,
    pub key: Aes256XtsKey,
}

/// The `enum_dispatch` macros needs at least one local trait to be implemented.
#[allow(unused)]
#[enum_dispatch]
trait ComponentMetadataTrait {}

#[non_exhaustive]
#[enum_dispatch(ComponentMetadataTrait)]
#[derive(Debug)]
pub enum ComponentMetadata {
    ComponentMetadataV1(ComponentMetadataV1),
}

impl KeyExchangeTrait for SeHdrPlain {
    fn contains<K: AsRef<PKeyRef<Public>>>(&self, key: K) -> Result<bool> {
        self.data.contains(key)
    }

    fn cust_pub_key(&mut self) -> Result<PKey<Public>> {
        self.data.cust_pub_key()
    }

    fn key_type(&self) -> SymKeyType {
        self.data.key_type()
    }

    fn contains_hash<H: AsRef<[u8]>>(&self, hash: H) -> bool {
        self.data.contains_hash(hash)
    }
}

impl UvDataPlainTrait for SeHdrPlain {
    type C = SeHdr;
}

impl AeadPlainDataTrait for SeHdrPlain {
    fn aad(&self) -> Result<Vec<u8>> {
        let data_aad = self.data.aad()?;

        Ok([serialize_to_bytes(&self.common)?, data_aad].concat())
    }

    fn data(&self) -> Result<Confidential<Vec<u8>>> {
        self.data.data()
    }

    fn tag(&self) -> Vec<u8> {
        self.data.tag()
    }
}

impl AeadCipherTrait for SeHdrPlain {
    fn aead_key_type(&self) -> SymKeyType {
        self.data.aead_key_type()
    }

    fn iv(&self) -> &[u8] {
        self.data.iv()
    }

    fn aead_tag_size(&self) -> usize {
        self.data.aead_tag_size()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::SeHdr;
    use crate::error::Error;

    #[test]
    fn test_sehdr_try_from_io() {
        // Invalid SeHdr as `sehs` is set to 0
        assert!(matches!(
            SeHdr::try_from_io(Cursor::new([
                73, 66, 77, 83, 101, 99, 69, 120, 0, 0, 1, 0, 0, 0, 0, 0, 2, 0, 8
            ])),
            Err(Error::InvalidSeHdr)
        ));

        // Invalid SeHdr as the `sehs` is too large.
        assert!(matches!(
            SeHdr::try_from_io(Cursor::new([
                73, 66, 77, 83, 101, 99, 69, 120, 0, 0, 1, 0, 0, 0, 1, 255, 65, 65, 65, 65, 67, 0,
                65, 17, 65, 0, 65, 65, 65, 65, 65, 65, 91, 91, 180, 91, 91, 91, 91, 91, 91, 91, 91,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 241, 241,
                241, 241, 241, 91, 91, 91, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112,
                112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 80,
                112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112,
                112, 112, 112, 112, 91, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112,
                112, 112, 112, 112, 112, 112, 112, 0, 0, 0, 0, 101, 99, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 65, 65, 65, 65, 67, 0, 65, 17, 65, 0, 65, 65, 65, 65,
                65, 65, 91, 91, 180, 91, 91, 91, 91, 91, 91, 91, 91, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 241, 241, 241, 241, 241, 91, 91, 91, 112,
                112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112,
                112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 80, 112, 112, 112, 112, 112, 112,
                112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 91, 112, 112,
                112, 112, 112, 112, 112, 112, 112, 112, 112, 112, 73, 66, 77, 83, 101, 99, 69, 120,
                0, 112, 112, 0, 1, 0, 0, 0, 0, 101, 99, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 65, 65, 65, 65, 67, 0, 65, 17, 65, 0, 65, 65, 65, 65, 65, 65, 91,
                91, 180, 91, 91, 91, 91, 91, 91, 91, 91, 91, 91, 91, 91, 91, 91, 91, 91, 91, 91,
                91, 91, 112, 112, 112, 112, 112, 73, 66, 77, 83, 101, 99, 69, 120, 0, 0, 1, 0, 0,
                0, 0, 48, 53, 53, 53, 53, 53, 53, 53, 91, 91, 91, 241, 241, 46, 49, 49, 0, 49, 49,
                0, 0, 112, 112, 112, 91, 0, 0, 0, 0, 9, 0, 49, 50, 22, 241, 241, 241, 241, 241,
                241, 241, 241, 241, 241, 241, 91, 91, 91, 91, 91, 255, 251, 0, 0, 91, 91, 91, 91,
                91, 91, 91, 91, 91, 91, 91, 0, 0, 91, 0, 0, 10, 91, 91, 91, 65, 65, 65, 65
            ])),
            Err(Error::InvalidSeHdr)
        ));
    }
}
