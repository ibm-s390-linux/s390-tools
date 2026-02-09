// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024
use std::mem::{size_of, size_of_val};

use deku::{ctx::Endian, prelude::*};
use openssl::{
    nid::Nid,
    pkey::{PKeyRef, Public},
};
use pv::request::{
    gen_ec_key,
    openssl::pkey::{PKey, Private},
    random_array, Aes256XtsKey, Confidential, EcPubKeyCoord, Encrypt, Keyslot, SymKey, SymKeyType,
    Zeroize, SHA_512_HASH_LEN,
};
use serde::{Deserialize, Serialize};

use super::keys::phkh_v1;
use crate::{
    error::Error,
    misc::PAGESIZE,
    pv_utils::{
        error::Result,
        se_hdr::{
            brb::{
                ComponentMetadata, ComponentMetadataV1, SeHdrCommon, SeHdrConfBuilderTrait,
                SeHdrPlainTrait, SeHdrPubBuilderTrait, SeHdrTrait,
            },
            keys::{BinaryKeySlotV1, EcPubKeyCoordV1},
        },
        serializing::{
            bytesize, bytesize_confidential, confidential_read_slice, confidential_write_slice,
            serde_base64, serde_hex_array, serde_hex_confidential_array, serde_hex_left_padded_u64,
            serialize_to_bytes,
        },
        try_copy_slice_to_array,
        uvdata::{
            AeadCipherTrait, AeadDataTrait, AeadPlainDataTrait, KeyExchangeTrait, UvDataPlainTrait,
            UvDataTrait,
        },
        uvdata_builder::{AeadCipherBuilderTrait, KeyExchangeBuilderTrait},
        PlaintextControlFlagsV1, SecretControlFlagsV1, PSW,
    },
};

#[derive(Debug)]
struct HdrSizesV1 {
    pub phs: u64,
    pub sea: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, DekuRead, DekuWrite, Serialize, Deserialize)]
#[deku(endian = "endian", ctx = "endian: Endian", ctx_default = "Endian::Big")]
pub struct SeHdrAadV1 {
    #[deku(assert = "*sehs <= SeHdrDataV1::MAX_SIZE.try_into().unwrap()")]
    pub sehs: u32,
    #[serde(with = "serde_hex_array", rename = "iv_hex")]
    pub iv: [u8; SymKeyType::AES_256_GCM_IV_LEN],
    #[serde(skip)]
    res1: u32,
    #[deku(assert = "*nks <= (*sehs).into()", update = "self.keyslots.len()")]
    pub nks: u64,
    #[deku(assert = "*sea <= (*sehs).into()")]
    pub sea: u64,
    pub nep: u64,
    #[serde(with = "serde_hex_left_padded_u64", rename = "pcf_hex")]
    pub pcf: u64,
    pub cust_pub_key: EcPubKeyCoordV1,
    #[serde(with = "serde_hex_array", rename = "pld_hex")]
    pub pld: [u8; SHA_512_HASH_LEN],
    #[serde(with = "serde_hex_array", rename = "ald_hex")]
    pub ald: [u8; SHA_512_HASH_LEN],
    #[serde(with = "serde_hex_array", rename = "tld_hex")]
    pub tld: [u8; SHA_512_HASH_LEN],
    #[deku(count = "nks")]
    pub keyslots: Vec<BinaryKeySlotV1>,
}

impl SeHdrAadV1 {
    const KEY_TYPE: SymKeyType = SymKeyType::Aes256Gcm;
}

impl KeyExchangeTrait for SeHdrAadV1 {
    fn contains<K: AsRef<PKeyRef<Public>>>(&self, key: K) -> Result<bool> {
        let phkh = phkh_v1(key)?;
        Ok(self.contains_hash(phkh))
    }

    fn cust_pub_key(&mut self) -> Result<PKey<Public>> {
        self.cust_pub_key.clone().try_into()
    }

    fn key_type(&self) -> SymKeyType {
        Self::KEY_TYPE
    }

    fn contains_hash<H: AsRef<[u8]>>(&self, hash: H) -> bool {
        for slot in &self.keyslots {
            if hash.as_ref() != slot.phkh {
                continue;
            }
            return true;
        }
        false
    }
}

#[derive(PartialEq, Eq, Debug, Clone, DekuRead, DekuWrite, Serialize, Deserialize)]
#[deku(endian = "endian", ctx = "endian: Endian", ctx_default = "Endian::Big")]
pub struct SeHdrConfV1 {
    #[serde(with = "serde_hex_confidential_array", rename = "cck_hex")]
    #[deku(
        reader = "confidential_read_slice(deku::reader, endian)",
        writer = "confidential_write_slice(cck, deku::writer, endian)"
    )]
    cck: Confidential<[u8; 32]>,
    #[serde(with = "serde_hex_confidential_array", rename = "xts_hex")]
    #[deku(
        reader = "confidential_read_slice(deku::reader, endian)",
        writer = "confidential_write_slice(xts, deku::writer, endian)"
    )]
    xts: Aes256XtsKey,
    psw: PSW,
    #[serde(with = "serde_hex_left_padded_u64", rename = "scf_hex")]
    pub scf: u64,
    #[serde(skip)]
    #[deku(assert_eq = "0")]
    noi: u32,
    #[serde(skip)]
    res2: u32,
    #[serde(skip)]
    #[deku(count = "noi")]
    opt_items: Vec<u8>,
}

impl Zeroize for SeHdrConfV1 {
    fn zeroize(&mut self) {
        self.cck.zeroize();
        self.xts.zeroize();
        self.psw.zeroize();
        self.scf.zeroize();
        self.noi.zeroize();
        self.res2.zeroize();
        self.opt_items.zeroize();
    }
}

#[derive(Default, PartialEq, Eq, Debug, Clone, DekuRead, DekuWrite, Serialize, Deserialize)]
#[deku(endian = "endian", ctx = "endian: Endian", ctx_default = "Endian::Big")]
pub struct SeHdrTagV1 {
    #[serde(with = "serde_hex_array", rename = "tag_hex")]
    tag: [u8; SymKeyType::AES_256_GCM_TAG_LEN],
}

mod ser_confidential_confv1 {
    use pv::request::Confidential;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::SeHdrConfV1;

    pub fn serialize<S: Serializer>(
        encrypted: &Confidential<SeHdrConfV1>,
        ser: S,
    ) -> Result<S::Ok, S::Error> {
        encrypted.value().serialize(ser)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Confidential<SeHdrConfV1>, D::Error> {
        let conf = SeHdrConfV1::deserialize(deserializer)?;
        Ok(Confidential::new(conf))
    }
}

/// Secure Execution Header definition
#[derive(Debug, Clone, PartialEq, Eq, DekuRead, DekuWrite, Serialize, Deserialize)]
#[deku(endian = "big")]
pub struct SeHdrDataV1 {
    #[serde(flatten)]
    pub aad: SeHdrAadV1,
    #[serde(flatten, with = "ser_confidential_confv1")]
    #[deku(
        reader = "confidential_read_sehdrconf_v1(deku::reader)",
        writer = "confidential_write_sehdrconf_v1(data, deku::writer)"
    )]
    pub data: Confidential<SeHdrConfV1>,
    #[serde(flatten)]
    tag: SeHdrTagV1,
}

/// Reads from a `reader` and creates a confidential `SeHdrConfV1`.
///
/// # Errors
///
/// This function will return an error if there was an I/O error or the
/// `SeHdrConfV1` could not be constructed.
fn confidential_read_sehdrconf_v1<R>(
    reader: &mut Reader<R>,
) -> Result<Confidential<SeHdrConfV1>, DekuError>
where
    R: std::io::Read + std::io::Seek,
{
    Ok(Confidential::new(SeHdrConfV1::from_reader_with_ctx(
        reader,
        (),
    )?))
}

/// Writes a `Confidential<SeHdrConf1>` into this `writer`.
///
/// # Errors
///
/// This function will return an error if there was an I/O error.
fn confidential_write_sehdrconf_v1<W>(
    value: &Confidential<SeHdrConfV1>,
    writer: &mut Writer<W>,
) -> Result<(), DekuError>
where
    W: std::io::Write + std::io::Seek,
{
    value.value().to_writer(writer, ())
}

impl SeHdrDataV1 {
    const MAX_SIZE: usize = 2 * PAGESIZE;
    const PCF_DEFAULT: u64 = 0x0;
    const SCF_DEFAULT: u64 = 0x0;

    /// Creates a new `SeHdrDataV1`. It initializes the CCK and IV with random
    /// data.
    ///
    /// # Errors
    ///
    /// This function will return an error if there was not enough entropy to
    /// create the random data or another error has occurred.
    pub fn new(psw: PSW, components: ComponentMetadataV1) -> Result<Self> {
        // Safety: The CCK is also 32 bytes large.
        let cck = SymKey::random(SymKeyType::Aes256Gcm)?.try_into().unwrap();
        let mut ret = Self {
            aad: SeHdrAadV1 {
                sehs: 0,
                pcf: Self::PCF_DEFAULT,
                ald: components.ald,
                pld: components.pld,
                tld: components.tld,
                nep: components.nep,
                sea: 0,
                iv: random_array()?,
                res1: 0,
                nks: 0,
                cust_pub_key: EcPubKeyCoordV1 { coord: [0_u8; 160] },
                keyslots: vec![],
            },
            data: SeHdrConfV1 {
                cck,
                scf: Self::SCF_DEFAULT,
                psw,
                xts: components.key,
                noi: 0,
                res2: 0,
                opt_items: vec![],
            }
            .into(),
            tag: SeHdrTagV1::default(),
        };
        let hdr_size = ret.size()?;
        let phs = hdr_size.phs.try_into()?;
        if phs > Self::MAX_SIZE {
            return Err(Error::InvalidSeHdrTooLarge {
                given: phs,
                maximum: Self::MAX_SIZE,
            });
        }
        ret.aad.sehs = phs.try_into()?;
        ret.aad.sea = hdr_size.sea;
        Ok(ret)
    }

    fn size(&self) -> Result<HdrSizesV1> {
        let sea = bytesize_confidential(&self.data)?;
        let mut phs = bytesize(&self.aad)?
            .checked_add(size_of::<SeHdrCommon>())
            .ok_or(Error::UnexpectedOverflow)?;
        phs = phs
            .checked_add(bytesize(&self.tag)?)
            .ok_or(Error::UnexpectedOverflow)?;
        phs = phs.checked_add(sea).ok_or(Error::UnexpectedOverflow)?;

        Ok(HdrSizesV1 {
            sea: sea.try_into()?,
            phs: phs.try_into()?,
        })
    }

    /// Return the expected size of an constructed `SeHdrDataV1` with `n` key
    /// slots.
    ///
    /// # Errors
    ///
    /// This function will return an error if there was an arithmetic overflow
    /// or.
    pub fn expected_size(nks: usize) -> Result<usize> {
        let cck = [0x0; 32].into();
        let hdr = Self {
            aad: SeHdrAadV1 {
                sehs: 0,
                pcf: Self::PCF_DEFAULT,
                ald: [0x0; SHA_512_HASH_LEN],
                pld: [0x0; SHA_512_HASH_LEN],
                tld: [0x0; SHA_512_HASH_LEN],
                nep: 0,
                sea: 0,
                iv: [0x0_u8; SymKeyType::AES_256_GCM_IV_LEN],
                res1: 0,
                nks: 0,
                cust_pub_key: EcPubKeyCoordV1 { coord: [0_u8; 160] },
                keyslots: vec![],
            },
            data: SeHdrConfV1 {
                cck,
                scf: Self::SCF_DEFAULT,
                psw: PSW { mask: 0, addr: 0 },
                xts: [0x0; SymKeyType::AES_256_XTS_KEY_LEN].into(),
                noi: 0,
                res2: 0,
                opt_items: vec![],
            }
            .into(),
            tag: SeHdrTagV1::default(),
        };
        let hdr_size: usize = hdr.size()?.phs.try_into().unwrap();

        hdr_size
            .checked_add(
                size_of::<BinaryKeySlotV1>()
                    .checked_mul(nks)
                    .ok_or(Error::UnexpectedOverflow)?,
            )
            .ok_or(Error::UnexpectedOverflow)
    }
}

impl UvDataPlainTrait for SeHdrDataV1 {
    type C = SeHdrBinV1;
}
impl SeHdrPlainTrait for SeHdrDataV1 {}

impl KeyExchangeBuilderTrait for SeHdrDataV1 {
    fn add_keyslot(
        &mut self,
        hostkey: &PKeyRef<Public>,
        aead_key: &SymKey,
        priv_key: &PKeyRef<Private>,
    ) -> Result<()> {
        let keyslot = Keyslot::new(hostkey.to_owned());
        let keyslot_bin = keyslot.encrypt(aead_key.value(), priv_key)?.try_into()?;
        let keyslot_bin_size = u32::try_from(size_of_val(&keyslot_bin)).unwrap();
        self.aad.keyslots.push(keyslot_bin);
        self.aad.nks = self
            .aad
            .nks
            .checked_add(1)
            .ok_or(Error::UnexpectedOverflow)?;
        self.aad.sehs = self
            .aad
            .sehs
            .checked_add(keyslot_bin_size)
            .ok_or(Error::UnexpectedOverflow)?;
        Ok(())
    }

    fn generate_private_key(&self) -> Result<PKey<Private>> {
        Ok(gen_ec_key(Nid::SECP521R1)?)
    }

    fn set_cust_public_key(&mut self, key: &PKeyRef<Private>) -> Result<()> {
        self.aad.cust_pub_key = TryInto::<EcPubKeyCoord>::try_into(key)?.into();
        Ok(())
    }

    fn clear_keyslots(&mut self) -> Result<()> {
        let old_nks: usize = self.aad.nks.try_into().unwrap();
        let keyslot_bin_size = size_of::<BinaryKeySlotV1>();
        self.aad.keyslots.clear();
        self.aad.nks = 0;
        self.aad.sehs -= u32::try_from(
            old_nks
                .checked_mul(keyslot_bin_size)
                .ok_or(Error::UnexpectedOverflow)?,
        )
        .unwrap();
        Ok(())
    }
}

impl KeyExchangeTrait for SeHdrDataV1 {
    fn contains<K: AsRef<PKeyRef<Public>>>(&self, key: K) -> Result<bool> {
        self.aad.contains(key)
    }

    fn cust_pub_key(&mut self) -> Result<PKey<Public>> {
        self.aad.cust_pub_key()
    }

    fn key_type(&self) -> SymKeyType {
        self.aad.key_type()
    }

    fn contains_hash<H: AsRef<[u8]>>(&self, hash: H) -> bool {
        self.aad.contains_hash(hash)
    }
}

impl SeHdrConfBuilderTrait for SeHdrDataV1 {
    fn set_psw(&mut self, psw: &PSW) {
        self.data.value_mut().psw = psw.clone();
    }

    fn set_scf(&mut self, scf: &SecretControlFlagsV1) -> Result<()> {
        self.data.value_mut().scf = scf.into();
        Ok(())
    }

    fn set_cck(&mut self, cck: Confidential<Vec<u8>>) -> Result<()> {
        self.data.value_mut().cck = cck.try_into()?;
        Ok(())
    }

    fn generate_cck(&self) -> Result<SymKey> {
        Ok(SymKey::random(SymKeyType::Aes256Gcm)?)
    }
}

impl SeHdrPubBuilderTrait for SeHdrDataV1 {
    fn set_pcf(&mut self, pcf: &PlaintextControlFlagsV1) -> Result<()> {
        self.aad.pcf = pcf.into();
        Ok(())
    }

    fn set_components(&mut self, meta: ComponentMetadata) -> Result<()> {
        let ComponentMetadataV1 {
            ald,
            pld,
            tld,
            nep,
            key,
        }: ComponentMetadataV1 = meta
            .try_into()
            .map_err(|_| Error::InvalidComponentMetadata)?;
        self.data.value_mut().xts = key;
        self.aad.ald = ald;
        self.aad.pld = pld;
        self.aad.tld = tld;
        self.aad.nep = nep;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, DekuRead, DekuWrite, Serialize, Deserialize)]
#[deku(endian = "big")]
pub struct SeHdrBinV1 {
    #[serde(flatten)]
    pub aad: SeHdrAadV1,
    #[serde(with = "serde_base64", rename = "cipher_data_b64")]
    #[deku(bytes_read = "aad.sea")]
    pub cipher_data: Vec<u8>,
    #[serde(flatten)]
    pub tag: SeHdrTagV1,
}

impl SeHdrBinV1 {
    pub fn new(d: &[u8]) -> Result<Self> {
        Self::try_from_data(d)
    }

    pub(crate) fn try_from_data(data: &[u8]) -> Result<Self> {
        let (_rest, val) = Self::from_bytes((data, 0))?;
        Ok(val)
    }
}

impl UvDataTrait for SeHdrBinV1 {
    type P = SeHdrDataV1;
}
impl SeHdrTrait for SeHdrBinV1 {}

impl AeadCipherTrait for SeHdrBinV1 {
    fn aead_key_type(&self) -> SymKeyType {
        self.key_type()
    }

    fn iv(&self) -> &[u8] {
        &self.aad.iv
    }

    fn aead_tag_size(&self) -> usize {
        SymKeyType::AES_256_GCM_TAG_LEN
    }
}

impl AeadCipherBuilderTrait for SeHdrDataV1 {
    fn set_iv(&mut self, iv: &[u8]) -> Result<()> {
        self.aad.iv = try_copy_slice_to_array(iv)?;
        Ok(())
    }
}

impl KeyExchangeTrait for SeHdrBinV1 {
    fn contains<K: AsRef<PKeyRef<Public>>>(&self, key: K) -> Result<bool> {
        self.aad.contains(key)
    }

    fn cust_pub_key(&mut self) -> Result<PKey<Public>> {
        self.aad.cust_pub_key()
    }

    fn key_type(&self) -> SymKeyType {
        self.aad.key_type()
    }

    fn contains_hash<H: AsRef<[u8]>>(&self, hash: H) -> bool {
        self.aad.contains_hash(hash)
    }
}

impl AeadDataTrait for SeHdrBinV1 {
    fn aad(&self) -> Result<Vec<u8>> {
        serialize_to_bytes(&self.aad)
    }

    fn data(&self) -> Vec<u8> {
        self.cipher_data.to_owned()
    }

    fn tag(&self) -> Vec<u8> {
        serialize_to_bytes(&self.tag).unwrap()
    }
}

impl AeadPlainDataTrait for SeHdrDataV1 {
    fn aad(&self) -> Result<Vec<u8>> {
        serialize_to_bytes(&self.aad)
    }

    fn data(&self) -> Result<Confidential<Vec<u8>>> {
        Ok(serialize_to_bytes(self.data.value())?.into())
    }

    fn tag(&self) -> Vec<u8> {
        serialize_to_bytes(&self.tag).unwrap()
    }
}

impl AeadCipherTrait for SeHdrDataV1 {
    fn aead_key_type(&self) -> SymKeyType {
        self.aad.key_type()
    }

    fn iv(&self) -> &[u8] {
        &self.aad.iv
    }

    fn aead_tag_size(&self) -> usize {
        SymKeyType::AES_256_GCM_TAG_LEN
    }
}

#[cfg(test)]
mod tests {

    use std::io::Cursor;

    use pv::test_utils::get_test_key_and_cert;

    use super::*;
    use crate::pv_utils::{BuilderTrait, SeHdr, SeHdrBuilder, SeHdrVersion};

    #[test]
    fn iv_keys_auto_generation_test() {
        let (_, host_key) = get_test_key_and_cert();
        let host_keys = [host_key.public_key().unwrap()];
        let mut builder = SeHdrBuilder::new(
            SeHdrVersion::V1,
            PSW {
                addr: 1234,
                mask: 5678,
            },
            ComponentMetadataV1 {
                ald: [0x1; SHA_512_HASH_LEN],
                pld: [0x2; SHA_512_HASH_LEN],
                tld: [0x3; SHA_512_HASH_LEN],
                nep: 1,
                key: Confidential::new([0x0_u8; SymKeyType::AES_256_XTS_KEY_LEN]),
            },
        )
        .expect("should not fail");
        builder.add_hostkeys(&host_keys).expect("should not fail");
    }

    #[test]
    fn chain_test() {
        let (_, host_key) = get_test_key_and_cert();
        let host_keys = [host_key.public_key().unwrap()];
        let xts_key = Confidential::new([0x3; SymKeyType::AES_256_XTS_KEY_LEN]);
        let meta = ComponentMetadataV1 {
            ald: [0x1; SHA_512_HASH_LEN],
            pld: [0x2; SHA_512_HASH_LEN],
            tld: [0x3; SHA_512_HASH_LEN],
            nep: 3,
            key: xts_key,
        };
        let cck: Confidential<Vec<u8>> = [0x42; 32].to_vec().into();
        let psw = PSW {
            addr: 1234,
            mask: 5678,
        };

        let mut builder = SeHdrBuilder::new(SeHdrVersion::V1, psw.clone(), meta.clone())
            .expect("should not fail");

        builder
            .add_hostkeys(&host_keys)
            .expect("should not fail")
            .with_components(meta.clone())
            .expect("should not fail")
            .with_cck(cck.clone())
            .expect("should not fail");
        let prot_key = builder.prot_key().to_owned();
        let bin = builder.build().expect("should not fail");

        let reader = Cursor::new(bin.as_bytes().expect("should not fail"));
        let hdr = SeHdr::try_from_io(reader).unwrap();

        let hdr_plain = hdr.decrypt(&prot_key).unwrap();
        assert_eq!(hdr_plain.common.version, SeHdrVersion::V1);
        let hdr_data_v1: SeHdrDataV1 = hdr_plain.data.try_into().expect("should not fail");
        assert_eq!(meta.ald, hdr_data_v1.aad.ald);
        assert_eq!(meta.pld, hdr_data_v1.aad.pld);
        assert_eq!(meta.tld, hdr_data_v1.aad.tld);
        assert_eq!(psw, hdr_data_v1.data.value().psw);
        assert_eq!(cck.value(), hdr_data_v1.data.value().cck.value());
    }

    #[test]
    fn max_size_sehdr_test() {
        const MAX_HOST_KEYS: usize = 95;

        let (_, host_key) = get_test_key_and_cert();
        let pub_key = host_key.public_key().unwrap();
        let host_keys_max: Vec<_> = (0..MAX_HOST_KEYS).map(|_| pub_key.clone()).collect();
        let too_many_host_keys: Vec<_> = (0..MAX_HOST_KEYS + 1).map(|_| pub_key.clone()).collect();
        let xts_key = Confidential::new([0x3; SymKeyType::AES_256_XTS_KEY_LEN]);
        let meta = ComponentMetadataV1 {
            ald: [0x1; SHA_512_HASH_LEN],
            pld: [0x2; SHA_512_HASH_LEN],
            tld: [0x3; SHA_512_HASH_LEN],
            nep: 3,
            key: xts_key,
        };
        let psw = PSW {
            addr: 1234,
            mask: 5678,
        };

        let mut builder = SeHdrBuilder::new(SeHdrVersion::V1, psw.clone(), meta.clone())
            .expect("should not fail");
        builder
            .add_hostkeys(&host_keys_max)
            .expect("should not fail")
            .with_components(meta.clone())
            .expect("should not fail");
        let bin = builder.build().expect("should not fail");
        assert_eq!(bin.common.version, SeHdrVersion::V1);
        let hdr_v1: SeHdrBinV1 = bin.data.try_into().expect("should not fail");
        assert_eq!(hdr_v1.aad.sehs, 8160);

        let mut builder = SeHdrBuilder::new(SeHdrVersion::V1, psw.clone(), meta.clone())
            .expect("should not fail");

        builder
            .add_hostkeys(&too_many_host_keys)
            .expect("should not fail")
            .with_components(meta)
            .expect("should not fail");
        assert!(matches!(builder.build(), Err(Error::InvalidSeHdr)));
    }

    #[test]
    fn roundtrip_se_hdr_tag_v1_json() {
        let tag = SeHdrTagV1 {
            tag: [0x42; SymKeyType::AES_256_GCM_TAG_LEN],
        };

        let json = serde_json::to_string(&tag).expect("should serialize");
        assert_eq!(json, "{\"tag_hex\":\"42424242424242424242424242424242\"}");
        let deserialized: SeHdrTagV1 = serde_json::from_str(&json).expect("should deserialize");

        assert_eq!(tag, deserialized);
    }

    #[test]
    fn roundtrip_se_hdr_conf_v1_json() {
        let conf = SeHdrConfV1 {
            cck: Confidential::new([0x11; 32]),
            xts: Confidential::new([0x22; SymKeyType::AES_256_XTS_KEY_LEN]),
            psw: PSW {
                addr: 0x1000,
                mask: 0x2000,
            },
            scf: 0x42,
            noi: 0,
            res2: 0,
            opt_items: vec![],
        };

        let json = serde_json::to_string(&conf).expect("should serialize");
        assert_eq!(json, "{\"cck_hex\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"xts_hex\":\"22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222\",\"psw\":{\"mask_hex\":\"0000000000002000\",\"addr_hex\":\"0000000000001000\"},\"scf_hex\":\"0000000000000042\"}");
        let deserialized: SeHdrConfV1 = serde_json::from_str(&json).expect("should deserialize");

        assert_eq!(conf, deserialized);
    }

    #[test]
    fn roundtrip_se_hdr_aad_v1_json() {
        let aad = SeHdrAadV1 {
            sehs: 1024,
            iv: [0x33; SymKeyType::AES_256_GCM_IV_LEN],
            res1: 0,
            nks: 2,
            sea: 512,
            nep: 10,
            pcf: 0x100,
            cust_pub_key: EcPubKeyCoordV1 { coord: [0x44; 160] },
            pld: [0x55; SHA_512_HASH_LEN],
            ald: [0x66; SHA_512_HASH_LEN],
            tld: [0x77; SHA_512_HASH_LEN],
            keyslots: vec![],
        };

        let json = serde_json::to_string(&aad).expect("should serialize");
        assert_eq!(json, "{\"sehs\":1024,\"iv_hex\":\"333333333333333333333333\",\"nks\":2,\"sea\":512,\"nep\":10,\"pcf_hex\":\"0000000000000100\",\"cust_pub_key\":{\"coord_hex\":\"44444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444\"},\"pld_hex\":\"55555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555\",\"ald_hex\":\"66666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666\",\"tld_hex\":\"77777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777\",\"keyslots\":[]}");
        let deserialized: SeHdrAadV1 = serde_json::from_str(&json).expect("should deserialize");

        assert_eq!(aad, deserialized);
    }

    #[test]
    fn roundtrip_se_hdr_bin_v1_json() {
        let bin = SeHdrBinV1 {
            aad: SeHdrAadV1 {
                sehs: 1024,
                iv: [0x33; SymKeyType::AES_256_GCM_IV_LEN],
                res1: 0,
                nks: 0,
                sea: 64,
                nep: 10,
                pcf: 0x100,
                cust_pub_key: EcPubKeyCoordV1 { coord: [0x44; 160] },
                pld: [0x55; SHA_512_HASH_LEN],
                ald: [0x66; SHA_512_HASH_LEN],
                tld: [0x77; SHA_512_HASH_LEN],
                keyslots: vec![],
            },
            cipher_data: vec![0x88; 64],
            tag: SeHdrTagV1 {
                tag: [0x99; SymKeyType::AES_256_GCM_TAG_LEN],
            },
        };

        let json = serde_json::to_string(&bin).expect("should serialize");
        assert_eq!(json, "{\"sehs\":1024,\"iv_hex\":\"333333333333333333333333\",\"nks\":0,\"sea\":64,\"nep\":10,\"pcf_hex\":\"0000000000000100\",\"cust_pub_key\":{\"coord_hex\":\"44444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444\"},\"pld_hex\":\"55555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555\",\"ald_hex\":\"66666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666\",\"tld_hex\":\"77777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777\",\"keyslots\":[],\"cipher_data_b64\":\"iIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiA==\",\"tag_hex\":\"99999999999999999999999999999999\"}");
        let deserialized: SeHdrBinV1 = serde_json::from_str(&json).expect("should deserialize");

        assert_eq!(bin, deserialized);
    }
}
