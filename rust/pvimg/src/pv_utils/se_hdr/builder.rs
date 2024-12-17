// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use pv::request::Confidential;

use super::{hdr_v1::SeHdrDataV1, SeHdr};
use crate::pv_utils::{
    error::{Error, Result},
    se_hdr::{
        brb::{SeHdrCommon, SeHdrConfBuilderTrait, SeHdrData, SeHdrPubBuilderTrait},
        ComponentMetadata, SeHdrPlain, SeHdrVersion,
    },
    uvdata::UvDataPlainTrait,
    uvdata_builder::{
        AeadCipherBuilderTrait, BuilderTrait, KeyExchangeBuilderTrait, UvDataBuilder,
    },
    PlaintextControlFlagsV1, SecretControlFlagsV1, PSW,
};

/// `SeHdrBuilder`
pub type SeHdrBuilder<'a> = UvDataBuilder<'a, SeHdrPlain>;

impl SeHdrBuilder<'_> {
    pub fn new<M: Into<ComponentMetadata>>(
        version: SeHdrVersion,
        psw: PSW,
        components_meta: M,
    ) -> Result<Self> {
        let (data, aead_key, priv_key) = match version {
            SeHdrVersion::V1 => {
                let mut data = SeHdrDataV1::new(
                    psw,
                    components_meta
                        .into()
                        .try_into()
                        .map_err(|_| Error::InvalidComponentMetadata)?,
                )?;
                let aead_key = data.generate_aead_key()?;
                let priv_key = data.generate_private_key()?;
                data.set_cust_public_key(&priv_key)?;
                (SeHdrData::SeHdrDataV1(data), aead_key, priv_key)
            }
        };
        let common = SeHdrCommon::new(version);
        let hdr = SeHdrPlain { common, data };
        Ok(Self {
            plain_data: hdr,
            target_keys: Vec::new(),
            prot_key: aead_key,
            expert_mode: false,
            priv_key,
        })
    }

    pub fn with_cck(&mut self, cck: Confidential<Vec<u8>>) -> Result<&mut Self> {
        self.plain_data
            .data
            .set_cck(cck)
            .map_err(|err| Error::InvalidCCK {
                source: Box::new(err),
            })?;
        Ok(self)
    }

    pub fn with_components<M: Into<ComponentMetadata>>(&mut self, meta: M) -> Result<&mut Self> {
        self.plain_data.data.set_components(meta.into())?;
        Ok(self)
    }

    pub fn with_pcf(&mut self, flags: &PlaintextControlFlagsV1) -> Result<&mut Self> {
        self.plain_data.data.set_pcf(flags)?;
        Ok(self)
    }

    pub fn with_scf(&mut self, flags: &SecretControlFlagsV1) -> Result<&mut Self> {
        self.plain_data.data.set_scf(flags)?;
        Ok(self)
    }
}

impl BuilderTrait for SeHdrBuilder<'_> {
    type T = SeHdr;

    fn build(self) -> Result<Self::T> {
        // At least one target key must be set
        if self.target_keys.is_empty() {
            return Err(Error::NoHostkey);
        }

        self.plain_data.encrypt(&self.prot_key)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use pv::{
        request::{Confidential, SymKeyType, SHA_512_HASH_LEN},
        test_utils::get_test_key_and_cert,
    };

    use super::*;
    use crate::pv_utils::{
        se_hdr::ComponentMetadataV1,
        uvdata::{AeadDataTrait, AeadPlainDataTrait},
        UvDataTrait,
    };

    #[test]
    fn builder_test() {
        use pv::test_utils::get_test_key_and_cert;

        let (cust_key, host_key) = get_test_key_and_cert();
        let host_keys = [host_key.public_key().unwrap()];
        let xts_key = Confidential::new([0x3; SymKeyType::AES_256_XTS_KEY_LEN]);
        let xts_key2 = Confidential::new([0x3; SymKeyType::AES_256_XTS_KEY_LEN]);
        let mut builder = SeHdrBuilder::new(
            SeHdrVersion::V1,
            PSW {
                addr: 1234,
                mask: 5678,
            },
            ComponentMetadata::ComponentMetadataV1(ComponentMetadataV1 {
                ald: [0x1; SHA_512_HASH_LEN],
                pld: [0x2; SHA_512_HASH_LEN],
                tld: [0x3; SHA_512_HASH_LEN],
                nep: 1,
                key: xts_key,
            }),
        )
        .expect("should not fail");

        //        builder.add_comp_data(addr, tweak, )?;
        builder
            .with_components(ComponentMetadataV1 {
                ald: [0x1; SHA_512_HASH_LEN],
                pld: [0x2; SHA_512_HASH_LEN],
                tld: [0x3; SHA_512_HASH_LEN],
                nep: 1,
                key: xts_key2,
            })
            .expect("should not fail");
        builder
            .with_priv_key(&cust_key)
            .expect_err("Error expected as expert mode is not enabled");

        builder.expert_mode = true;
        builder.with_priv_key(&cust_key).expect("should not fail");

        // Set CCK
        // Too large key
        builder
            .with_cck([49; SymKeyType::AES_256_GCM_KEY_LEN - 1].to_vec().into())
            .expect_err("should fail");
        // Too small key
        builder
            .with_cck([49; SymKeyType::AES_256_GCM_KEY_LEN + 1].to_vec().into())
            .expect_err("should fail");

        builder
            .with_cck([49; SymKeyType::AES_256_GCM_KEY_LEN].to_vec().into())
            .expect("should not fail");

        // Set protection key
        // Too large key
        builder
            .with_aead_key(Confidential::new([50; 33].into()))
            .expect_err("should fail");
        // Too small key
        builder
            .with_aead_key(Confidential::new([50; 31].into()))
            .expect_err("should fail");

        builder
            .with_aead_key(Confidential::new([50; 32].into()))
            .expect("should not fail");

        // Set IV
        // Too large IV
        builder.with_iv(&[51; 13]).expect_err("should fail");
        // Too small IV
        builder.with_iv(&[51; 11]).expect_err("should fail");

        builder.with_iv(&[51; 12]).expect("should not fail");

        builder.add_hostkeys(&host_keys).expect("should not fail");

        let prot_key = builder.prot_key().clone();
        let bin = builder.build().expect("wuhu");
        assert_eq!(bin.common.version, SeHdrVersion::V1);
        assert_eq!(bin.as_bytes().expect("should not fail").len(), 640);
        assert_eq!(
            bin.as_bytes().expect("should not fail"),
            [
                73, 66, 77, 83, 101, 99, 69, 120, 0, 0, 1, 0, 0, 0, 2, 128, 51, 51, 51, 51, 51, 51,
                51, 51, 51, 51, 51, 51, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
                128, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 199, 93, 52, 249, 22, 82, 219, 69, 123, 11, 32, 156, 70, 164, 145,
                164, 78, 226, 177, 110, 35, 194, 216, 218, 241, 22, 103, 138, 98, 242, 76, 227, 50,
                197, 153, 95, 8, 69, 107, 102, 177, 109, 213, 90, 146, 197, 7, 241, 227, 26, 247,
                140, 100, 168, 46, 122, 84, 27, 21, 19, 80, 21, 242, 2, 134, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 1, 64, 128, 88, 167, 241, 165, 195, 80, 151, 83, 58, 2, 169,
                56, 121, 231, 222, 103, 186, 40, 11, 206, 131, 101, 236, 148, 178, 185, 8, 245,
                137, 195, 169, 152, 216, 190, 30, 99, 7, 215, 74, 224, 26, 220, 70, 130, 95, 246,
                187, 111, 160, 92, 17, 71, 207, 226, 204, 244, 162, 79, 61, 131, 61, 218, 112, 2,
                2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
                3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
                3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 65, 92, 37,
                165, 209, 156, 56, 30, 97, 151, 51, 225, 193, 183, 251, 216, 139, 221, 28, 49, 216,
                130, 213, 173, 224, 75, 151, 4, 60, 80, 16, 240, 229, 82, 102, 228, 113, 137, 5,
                64, 29, 48, 138, 18, 148, 179, 136, 59, 221, 205, 98, 76, 41, 121, 59, 220, 160,
                12, 56, 212, 171, 77, 85, 253, 38, 196, 235, 112, 49, 183, 94, 171, 221, 120, 96,
                65, 149, 102, 55, 59, 180, 25, 143, 227, 222, 144, 3, 77, 240, 4, 217, 205, 199,
                175, 123, 1, 191, 76, 78, 99, 115, 131, 5, 160, 112, 142, 117, 125, 30, 239, 7, 51,
                239, 66, 173, 61, 243, 199, 20, 71, 115, 107, 113, 139, 68, 200, 219, 233, 84, 220,
                108, 242, 133, 71, 91, 154, 160, 171, 4, 32, 67, 90, 107, 216, 149, 141, 210, 20,
                125, 4, 39, 73, 163, 75, 1, 148, 78, 245, 135, 76, 68, 42, 164, 174, 185, 216, 29,
                60, 76, 28, 232, 191, 209, 218, 134, 184, 110, 154, 227, 144, 66, 213, 145, 93,
                157, 150, 61, 80, 69, 238, 6, 190, 191, 202, 172, 221, 159, 190, 62, 253, 67, 162,
                142, 245, 109, 23, 26, 102, 113, 101, 23, 64, 85, 249, 255, 250, 30, 28, 136, 135,
                187, 109, 118, 222
            ]
        );

        let decrypted = bin.decrypt(&prot_key).expect("BUG");
        assert_eq!(bin.common, decrypted.common);
        assert_eq!(
            bin.aad().expect("should not fail"),
            decrypted.aad().expect("should not fail")
        );
        assert_ne!(
            &bin.data(),
            decrypted.data().expect("should not fail").value()
        );
        let _decrypted_hdrv1: SeHdrDataV1 = decrypted.data.try_into().expect("BUG");
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
        let cck = Confidential::new([0x42; 32].to_vec());
        let mut builder = SeHdrBuilder::new(
            SeHdrVersion::V1,
            PSW {
                addr: 1234,
                mask: 5678,
            },
            meta,
        )
        .expect("should not fail");

        let prot_key = builder.prot_key().to_owned();
        builder
            .add_hostkeys(&host_keys)
            .expect("should not fail")
            .with_cck(cck)
            .expect("should not fail");
        let bin = builder.build().expect("should not fail");

        let reader = Cursor::new(bin.as_bytes().expect("should not fail"));
        let hdr = SeHdr::try_from_io(reader).unwrap();
        let hdr_plain = hdr.decrypt(&prot_key).unwrap();
        assert_eq!(hdr_plain.common.version, SeHdrVersion::V1);
        assert_eq!(hdr_plain.common.version, hdr.common.version);
        let _hdr_data_v1: SeHdrDataV1 = hdr_plain.data.try_into().expect("should not fail");
    }
}
