// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024
use super::{additional::ATT_ADD_HASH_SIZE, AttNonce};
use crate::{
    assert_size,
    attest::{AttestationMagic, AttestationMeasAlg},
    crypto::random_array,
    misc::Flags,
    req::{Aad, BinReqValues, Keyslot, ReqEncrCtx},
    request::{Confidential, MagicValue, Request, RequestVersion, SymKey, Zeroize},
    static_assert,
    uv::UvFlags,
    Error, Result,
};
use openssl::pkey::{PKey, Public};
use std::mem::size_of;
use zerocopy::{AsBytes, BigEndian, FromBytes, FromZeroes, U32};

#[cfg(doc)]
use crate::{
    request::SymKeyType,
    uv::AttestationCmd,
    verify::{CertVerifier, HkdVerifier},
};

/// Retrieve Attestation Request Control Block
///
/// An ARCB holds an Attestation Measurement key to attest a SE-guest.
/// The (architectural optional) nonce is always used and freshly generated for a new
/// [`AttestationRequest`].
///
/// Layout:
/// ```none
/// _______________________________________________________________
/// |                   generic header (48)
/// |     ---------------------------------------------------     |
/// |  Plaintext Attestation flags (8)                            |
/// |  Measurement Algorithm Identifier (4)                       |
/// |  Reserved(4)                                                |
/// |  Customer Public Key (160) generated for each request       |
/// |  N Keyslots(80 each)                                        |
/// |     ---------------------------------------------------     |
/// |  Measurement key (64)                                       | Encrypted
/// |  Optional Nonce (0 or  16)                                  | Encrypted
/// |     ---------------------------------------------------     |
/// |                   AES GCM Tag (16)                          |
/// |_____________________________________________________________|
/// ```
///
/// # Example
/// Create an Attestation request with default flags (= use a nonce)
///
/// ```rust,no_run
/// # use s390_pv::attest::{AttestationFlags, AttestationMeasAlg, AttestationRequest, AttestationVersion};
/// # use s390_pv::request::{SymKeyType, Request, ReqEncrCtx};
/// # fn main() -> s390_pv::Result<()> {
/// let att_version = AttestationVersion::One;
/// let meas_alg = AttestationMeasAlg::HmacSha512;
/// let mut arcb = AttestationRequest::new(att_version, meas_alg, AttestationFlags::default())?;
/// // read-in hostkey document(s). Not verified for brevity.
/// let hkd = s390_pv::misc::read_certs(&std::fs::read("host-key-document.crt")?)?;
/// // IBM issued HKD certificates typically have one X509
/// let hkd = hkd.first().unwrap().public_key()?;
/// arcb.add_hostkey(hkd);
/// // you can add multiple hostkeys
/// // arcb.add_hostkey(another_hkd);
/// // encrypt it
/// let ctx = ReqEncrCtx::random(SymKeyType::Aes256)?;
/// let arcb = arcb.encrypt(&ctx)?;
/// # Ok(())
/// # }
/// ```
/// # See Also
///
/// * [`AttestationFlags`]
/// * [`AttestationMeasAlg`]
/// * [`AttestationVersion`]
/// * [`SymKeyType`]
/// * [`Request`]
/// * [`ReqEncrCtx`]
/// * [`AttestationCmd`]
/// * [`HkdVerifier`], [`CertVerifier`]
#[derive(Debug)]
pub struct AttestationRequest {
    version: AttestationVersion,
    aad: AttestationAuthenticated,
    keyslots: Vec<Keyslot>,
    conf: Confidential<ReqConfData>,
}

impl AttestationRequest {
    /// Create a new retrieve attestation measurement request
    pub fn new(
        version: AttestationVersion,
        mai: AttestationMeasAlg,
        mut flags: AttestationFlags,
    ) -> Result<Self> {
        // This implementation enforces using a nonce
        flags.set_nonce();
        Ok(Self {
            version,
            aad: AttestationAuthenticated::new(flags, mai),
            keyslots: vec![],
            conf: ReqConfData::random()?,
        })
    }

    /// Returns a reference to the flags of this [`AttestationRequest`].
    pub fn flags(&self) -> &AttestationFlags {
        &self.aad.flags
    }

    /// Returns a copy of the confidential data of this [`AttestationRequest`].
    ///
    /// Gives a copy of the confidential data of this request for further
    /// processing. This data should be never exposed in cleartext to anyone but
    /// the creator and the verifier of this request.
    pub fn confidential_data(&self) -> AttestationConfidential {
        let conf = self.conf.value();
        AttestationConfidential::new(conf.meas_key.to_vec(), conf.nonce.into())
    }

    fn aad(&self, ctx: &ReqEncrCtx) -> Result<Vec<u8>> {
        let cust_pub_key = ctx.key_coords()?;
        let mut aad: Vec<Aad> = Vec::with_capacity(self.keyslots.len() + 2);
        aad.push(Aad::Plain(self.aad.as_bytes()));
        aad.push(Aad::Plain(cust_pub_key.as_ref()));
        self.keyslots.iter().for_each(|k| aad.push(Aad::Ks(k)));
        ctx.build_aad(
            self.version.into(),
            &aad,
            size_of::<ReqConfData>(),
            AttestationMagic::MAGIC,
        )
    }

    /// Decrypts the request and extracts the authenticated and confidential data
    ///
    /// Deconstructs the `arcb` and decrypts it using `arpk`
    ///
    /// # Error
    ///
    /// Returns an error if the request is malformed or the decryption failed
    pub fn decrypt_bin(
        arcb: &[u8],
        arpk: &SymKey,
    ) -> Result<(AttestationAuthenticated, AttestationConfidential)> {
        if !AttestationMagic::starts_with_magic(arcb) {
            return Err(Error::NoArcb);
        }

        let values = BinReqValues::get(arcb)?;

        match values.version().try_into()? {
            AttestationVersion::One => (),
        };
        let auth: &AttestationAuthenticated = values.req_dep_aad().ok_or(Error::BinRequestSmall)?;

        let mai = auth.mai.try_into()?;
        let keysize = match mai {
            v @ AttestationMeasAlg::HmacSha512 => v.exp_size(),
        } as usize;

        if keysize > values.sea() as usize {
            return Err(Error::BinArcbSeaSmall(values.sea()));
        }

        let decr = values.decrypt(arpk)?;

        // size sanitized by fence before
        let meas_key = &decr.value()[..keysize];
        let nonce = if decr.value().len() == size_of::<ReqConfData>() {
            Some(
                (&decr.value()[keysize..decr.value().len()])
                    .try_into()
                    .unwrap(),
            )
        } else {
            None
        };
        let conf = AttestationConfidential::new(meas_key.to_vec(), nonce);

        Ok((auth.to_owned(), conf))
    }
}

/// Confidential Data of an attestation request
///
/// contains a measurement key and an optional nonce
#[derive(Debug)]
pub struct AttestationConfidential {
    measurement_key: Confidential<Vec<u8>>,
    nonce: Option<Confidential<AttNonce>>,
}

impl AttestationConfidential {
    /// Returns a reference to the measurement key of this [`AttestationConfidential`].
    pub fn measurement_key(&self) -> &[u8] {
        self.measurement_key.value()
    }

    /// Returns a reference to the nonce of this [`AttestationConfidential`].
    pub fn nonce(&self) -> &Option<Confidential<AttNonce>> {
        &self.nonce
    }

    fn new(measurement_key: Vec<u8>, nonce: Option<AttNonce>) -> Self {
        Self {
            measurement_key: measurement_key.into(),
            nonce: nonce.map(Confidential::new),
        }
    }
}

impl Request for AttestationRequest {
    fn encrypt(&self, ctx: &ReqEncrCtx) -> Result<Vec<u8>> {
        let conf = self.conf.value().as_bytes();
        let aad = self.aad(ctx)?;
        ctx.encrypt_aead(&aad, conf).map(|res| res.data())
    }

    fn add_hostkey(&mut self, hostkey: PKey<Public>) {
        self.keyslots.push(Keyslot::new(hostkey))
    }
}

/// Versions for [`AttestationRequest`]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationVersion {
    /// Version 1 (= 0x0100)
    One = 0x0100,
}

impl TryFrom<u32> for AttestationVersion {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self> {
        if value == Self::One as u32 {
            Ok(Self::One)
        } else {
            Err(Error::BinArcbInvVersion(value))
        }
    }
}

impl From<AttestationVersion> for RequestVersion {
    fn from(val: AttestationVersion) -> Self {
        val as RequestVersion
    }
}

/// Authenticated additional Data of an [`AttestationRequest`]
#[repr(C)]
#[derive(Debug, AsBytes, FromZeroes, FromBytes, Clone, Copy)]
pub struct AttestationAuthenticated {
    flags: AttestationFlags,
    mai: U32<BigEndian>,
    res: u32,
}
assert_size!(AttestationAuthenticated, 0x10);

impl AttestationAuthenticated {
    fn new(flags: AttestationFlags, mai: AttestationMeasAlg) -> Self {
        Self {
            flags,
            mai: mai.into(),
            res: 0,
        }
    }

    /// Returns a reference to the flags of this [`AttestationAuthenticated`].
    pub fn flags(&self) -> &AttestationFlags {
        &self.flags
    }

    /// Returns the [`AttestationMeasAlg`] of this [`AttestationAuthenticated`].
    ///
    /// # Panics
    ///
    /// Panics if the library failed to set up the MAI correctly.
    pub fn mai(&self) -> AttestationMeasAlg {
        AttestationMeasAlg::try_from(self.mai).expect("ReqAuthData invariant hurt. Invalid MAI")
    }
}

/// Attestation flags
#[repr(C)]
#[derive(Default, Debug, AsBytes, FromZeroes, FromBytes, Clone, Copy)]
pub struct AttestationFlags(UvFlags);
static_assert!(AttestationFlags::FLAG_TO_ADD_SIZE.len() < 64);

impl AttestationFlags {
    /// Maps the flag to the (maximum) required size for the additional data
    pub(crate) const FLAG_TO_ADD_SIZE: [u32; 4] = [0, 0, ATT_ADD_HASH_SIZE, ATT_ADD_HASH_SIZE];

    /// Returns the maximum size this flag requires for additional data
    pub fn expected_additional_size(&self) -> u32 {
        Self::FLAG_TO_ADD_SIZE
            .iter()
            .enumerate()
            .fold(0, |size, (b, s)| size + self.0.is_set(b as u8) as u32 * s)
    }

    /// Flag 1 - use a nonce
    ///
    /// This attestation implementation forces the use of a nonce, so this will always be on and
    /// the function is non-public
    fn set_nonce(&mut self) {
        self.0.set_bit(1);
    }

    /// Flag 2 - request the image public host-key hash
    ///
    /// Asks the Ultravisor to provide the host-key hash that unpacked the SE-image to be added in
    /// additional data. Requires 32 bytes.
    pub fn set_image_phkh(&mut self) {
        self.0.set_bit(2);
    }

    /// Check weather the image public host key hash flag is on
    pub fn image_phkh(&self) -> bool {
        self.0.is_set(2)
    }

    /// Flag 3 - request the attestation public host-key hash
    ///
    /// Asks the Ultravisor to provide the host-key hash that unpacked the attestation request to
    /// be added in additional data. Requires 32 bytes.
    pub fn set_attest_phkh(&mut self) {
        self.0.set_bit(3);
    }

    /// Check weather the attestation public host key hash flag is on
    pub fn attest_phkh(&self) -> bool {
        self.0.is_set(3)
    }
}

#[repr(C)]
#[derive(Debug, AsBytes)]
struct ReqConfData {
    meas_key: [u8; 64],
    nonce: AttNonce,
}
assert_size!(ReqConfData, 80);

impl ReqConfData {
    fn random() -> Result<Confidential<Self>> {
        Ok(Confidential::new(Self {
            meas_key: random_array()?,
            nonce: random_array()?,
        }))
    }
}

impl Zeroize for ReqConfData {
    fn zeroize(&mut self) {
        self.meas_key.zeroize();
        self.nonce.zeroize();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::{get_test_asset, request::SymKey, test_utils::get_test_keys};

    const ARPK: [u8; 32] = [0x17; 32];
    const NONCE: [u8; 16] = [0xab; 16];
    const MEAS: [u8; 64] = [0x77; 64];

    fn mk_arcb() -> Vec<u8> {
        let (cust_key, host_key) = get_test_keys();
        let ctx = ReqEncrCtx::new_aes_256(
            Some([0x55; 12]),
            Some(cust_key),
            Some(SymKey::Aes256(ARPK.into())),
        )
        .unwrap();

        let mut flags = AttestationFlags::default();
        flags.set_image_phkh();
        flags.set_attest_phkh();

        let mut arcb = AttestationRequest::new(
            AttestationVersion::One,
            AttestationMeasAlg::HmacSha512,
            flags,
        )
        .unwrap();

        // manually set confidential data (API does not allow this)
        arcb.conf.value_mut().nonce = NONCE;
        arcb.conf.value_mut().meas_key = MEAS;

        arcb.add_hostkey(host_key);
        arcb.encrypt(&ctx).unwrap()
    }

    #[test]
    fn arcb() {
        let request = mk_arcb();
        let exp = get_test_asset!("exp/arcb.bin");

        assert_eq!(request, exp);
    }

    #[test]
    fn decrypt_bin() {
        let request = mk_arcb();
        let arpk = SymKey::Aes256(ARPK.into());
        let (_, conf) = AttestationRequest::decrypt_bin(&request, &arpk).unwrap();
        assert_eq!(conf.measurement_key(), &MEAS);
        assert_eq!(conf.nonce().as_ref().unwrap().value(), &NONCE);
    }

    #[test]
    fn decrypt_bin_fail_magic() {
        let arpk = SymKey::Aes256(ARPK.into());
        let mut tamp_arcb = mk_arcb();

        // tamper magic
        tamp_arcb[0] = 17;
        let ret = AttestationRequest::decrypt_bin(&tamp_arcb, &arpk);
        assert!(matches!(ret, Err(Error::NoArcb)));
    }

    #[test]
    fn decrypt_bin_fail_mai() {
        let arpk = SymKey::Aes256(ARPK.into());
        let mut tamp_arcb = mk_arcb();

        // tamper MAI
        tamp_arcb[0x3b] = 17;
        let ret = AttestationRequest::decrypt_bin(&tamp_arcb, &arpk);
        println!("{ret:?}");
        assert!(matches!(
            ret,
            Err(Error::PvCore(pv_core::Error::BinArcbInvAlgorithm(17)))
        ));
    }

    #[test]
    fn decrypt_bin_fail_aad() {
        let arpk = SymKey::Aes256(ARPK.into());
        let mut tamp_arcb = mk_arcb();

        // tamper AAD
        tamp_arcb[0x3c] = 17;
        let ret = AttestationRequest::decrypt_bin(&tamp_arcb, &arpk);
        assert!(matches!(ret, Err(Error::GcmTagMismatch)));
    }
}
