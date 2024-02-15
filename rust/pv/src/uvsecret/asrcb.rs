// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

use super::user_data::UserData;
use crate::{
    assert_size,
    crypto::AesGcmResult,
    misc::Flags,
    request::{
        hkdf_rfc_5869,
        openssl::{
            pkey::{PKey, Private, Public},
            Md,
        },
        uvsecret::{ExtSecret, GuestSecret},
        Aad, BootHdrTags, Keyslot, ReqEncrCtx, Request, Secret,
    },
    uv::{ConfigUid, UvFlags},
    Result,
};
use pv_core::request::RequestVersion;
use zerocopy::AsBytes;

/// Internal wrapper for Guest Secret, so that we can dump it in the form the UV wants it to be
#[derive(Debug)]
struct BinGuestSecret(GuestSecret);
impl BinGuestSecret {
    /// Reference to the confidential data
    fn confidential(&self) -> &[u8] {
        match &self.0 {
            GuestSecret::Null => &[],
            GuestSecret::Association { secret, .. } => secret.value().as_slice(),
        }
    }
    fn dump_auth(&self) -> Vec<u8> {
        match &self.0 {
            GuestSecret::Null => vec![0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            GuestSecret::Association { id, .. } => {
                let mut buf = vec![0; 48];
                buf[3] = 2;
                buf[7] = 0x20;
                buf[16..48].copy_from_slice(id.as_ref());
                buf
            }
        }
    }
}

impl From<GuestSecret> for BinGuestSecret {
    fn from(secret: GuestSecret) -> Self {
        BinGuestSecret(secret)
    }
}

/// Authenticated data w/o user data
#[repr(C)]
#[derive(Debug, Clone, Copy, AsBytes)]
struct ReqAuthData {
    flags: UvFlags,
    boot_tags: BootHdrTags,
    cuid: ConfigUid,
    reserved90: [u8; 0x100],
}
assert_size!(ReqAuthData, 0x1e8);

impl ReqAuthData {
    fn new<F: Into<UvFlags>>(boot_tags: BootHdrTags, flags: F) -> Self {
        ReqAuthData {
            flags: flags.into(),
            boot_tags,
            cuid: [0; 0x10],
            reserved90: [0; 0x100],
        }
    }
}

#[derive(Debug)]
struct ReqConfData {
    secret: BinGuestSecret,
    extension_secret: Secret<[u8; 32]>,
}

impl ReqConfData {
    fn to_bytes(&self) -> Secret<Vec<u8>> {
        let secret = self.secret.confidential();

        let mut v = vec![0; secret.len() + 32];
        if !secret.is_empty() {
            v[..secret.len()].copy_from_slice(secret);
        }
        v[secret.len()..32 + secret.len()]
            .copy_from_slice(self.extension_secret.value().as_slice());
        v.into()
    }
}

/// Flags for [`AddSecretRequest`]
#[derive(Default, Clone, Copy, Debug)]
pub struct AddSecretFlags(UvFlags);
impl AddSecretFlags {
    /// Enables the disable-dump flag
    ///
    /// After the request was dispatched successfully,
    /// the UV will not provide any dump decryption information for the SE-guest anymore.
    pub fn set_disable_dump(&mut self) {
        self.0.set_bit(0)
    }
}

impl From<&u64> for AddSecretFlags {
    fn from(v: &u64) -> Self {
        Self(v.into())
    }
}

impl From<AddSecretFlags> for UvFlags {
    fn from(f: AddSecretFlags) -> Self {
        f.0
    }
}

/// Versions for [`AddSecretRequest`]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddSecretVersion {
    /// Version 1 (= 0x0100)
    One = 0x0100,

    #[cfg(not(doc))]
    #[cfg(any(debug_assertions, test))]
    /// Only for testing
    Inv = 0,
}

impl From<AddSecretVersion> for RequestVersion {
    fn from(val: AddSecretVersion) -> Self {
        val as RequestVersion
    }
}

/// Add-secret request Control Block
///
/// An ASRCB wraps a secret to transport it securely to the Ultravisor.
///
/// Layout:
///```none
/// _______________________________________________________________
/// |                   generic header (48)
/// |     ---------------------------------------------------     |
/// |  Plaintext Add-Secret flags (8)                             |
/// |  SE header tags: PLD(64) ALD(64) TLD(64) HeaderTag(16)      |
/// |  Configuration unique ID(16) (Attestation)                  |
/// |       Optional, defaults to 0                               |
/// |  Reserved(256)                                              |
/// |  User Data(512) (reserved)                                  |
/// |  Customer Public Key (160) generated for each request       |
/// |  N Keyslots(80 each)                                        |
/// |  Secret header (Secret dependent)                           |
/// |     ---------------------------------------------------     |
/// |  Secret to add (Secret type dependent)(may be 0 bytes)      | Encrypted
/// |  Extension secret(32) Optional, defaults to 0               | Encrypted
/// |     ---------------------------------------------------     |
/// |                   AES GCM Tag (16)                          |
/// |_____________________________________________________________|
///```
#[derive(Debug)]
pub struct AddSecretRequest {
    version: AddSecretVersion,
    aad: ReqAuthData,
    keyslots: Vec<Keyslot>,
    conf: ReqConfData,
    user_data: UserData,
}

impl AddSecretRequest {
    /// Offset of the user-data in the add-secret request in bytes
    pub(super) const V1_USER_DATA_OFFS: usize = 0x218;

    /// Create a new add-secret request.
    ///
    /// The request has no extension secret, no configuration UID, no host-keys,
    /// and no user data
    ///
    pub fn new(
        version: AddSecretVersion,
        secret: GuestSecret,
        boot_tags: BootHdrTags,
        flags: AddSecretFlags,
    ) -> Self {
        AddSecretRequest {
            conf: ReqConfData {
                extension_secret: Secret::new([0; 32]),
                secret: secret.into(),
            },
            aad: ReqAuthData::new(boot_tags, flags),
            keyslots: vec![],
            version,
            user_data: UserData::Null,
        }
    }

    /// Sets the Configuration Unique Id of this [`AddSecretRequest`].
    pub fn set_cuid(&mut self, cuid: ConfigUid) {
        self.aad.cuid = cuid;
    }

    /// Sets the extension secret of this [`AddSecretRequest`].
    ///
    /// # Errors
    ///
    /// This function will return an error if the key derivation fails for a [`ExtSecret::Derived`].
    pub fn set_ext_secret(&mut self, ext_secret: ExtSecret) -> Result<()> {
        const DER_EXT_SECRET_INFO: &[u8] = "IBM Z Ultravisor Add-Secret".as_bytes();
        self.conf.extension_secret = match ext_secret {
            ExtSecret::Simple(s) => s,
            ExtSecret::Derived(cck) => hkdf_rfc_5869(
                Md::sha512(),
                cck.value(),
                self.aad.boot_tags.seht(),
                DER_EXT_SECRET_INFO,
            )?
            .into(),
        };
        Ok(())
    }

    /// Returns a reference to the guest secret of this [`AddSecretRequest`].
    pub fn guest_secret(&self) -> &GuestSecret {
        &self.conf.secret.0
    }

    /// Add user-data to the Add-Secret request
    ///
    /// (Signed) user-data is a non-architectual feature. It allows to add arbitrary
    /// data (message) to the request, that is signed optionally with an user defined key.
    /// Allowed keys are:
    /// - no key (up to 512 bytes of message)
    /// - EC SECP521R1 (up to 256 byte message)
    /// - RSA 2048 bit (up to 256 byte message)
    /// - RSA 3072 bit (up to 128 byte message)
    ///
    /// The signature can be verified during the verification of the secret-request  on the target machine.
    pub fn set_user_data(&mut self, msg: Vec<u8>, skey: Option<PKey<Private>>) -> Result<()> {
        self.user_data = UserData::new(skey, msg)?;
        Ok(())
    }

    /// compiles the authenticated area of this request
    fn aad(&self, ctx: &ReqEncrCtx, conf_len: usize) -> Result<Vec<u8>> {
        let cust_pub_key = ctx.key_coords()?;
        let secr_auth = self.conf.secret.dump_auth();
        let user_data = self.user_data.data();

        let mut aad: Vec<Aad> = Vec::with_capacity(5 + self.keyslots.len());
        aad.push(Aad::Plain(self.aad.as_bytes()));
        if let Some(data) = user_data.0 {
            aad.push(Aad::Plain(data));
        }
        if let Some(data) = &user_data.1 {
            aad.push(Aad::Plain(data));
        }
        aad.push(Aad::Plain(cust_pub_key.as_ref()));
        self.keyslots.iter().for_each(|k| aad.push(Aad::Ks(k)));
        aad.push(Aad::Plain(&secr_auth));

        ctx.build_aad(self.version.into(), &aad, conf_len, self.user_data.magic())
    }

    #[doc(hidden)]
    #[cfg(any(debug_assertions, test))]
    pub fn aad_and_conf(&self, ctx: &ReqEncrCtx) -> Result<(Vec<u8>, Vec<u8>)> {
        let conf = self.conf.to_bytes();
        let aad = self.aad(ctx, conf.value().len())?;
        Ok((aad, conf.value().to_owned()))
    }

    #[doc(hidden)]
    #[cfg(any(debug_assertions, test))]
    pub fn no_encrypt(&self, ctx: &ReqEncrCtx) -> Result<Vec<u8>> {
        let (mut res, mut conf) = self.aad_and_conf(ctx)?;
        res.append(&mut conf);
        res.append(&mut vec![0x24; 32]);
        Ok(res)
    }

    /// encrypt data, sign request with user-provided signing key, insert signature into aad,
    /// calculate request tag
    fn encrypt_with_signed_user_data(&self, ctx: &ReqEncrCtx) -> Result<Vec<u8>> {
        //encrypt data w/o aead
        let conf = self.conf.to_bytes();
        let aad = self.aad(ctx, conf.value().len())?;
        let AesGcmResult {
            mut buf,
            aad_range,
            encr_range,
            ..
        } = ctx.encrypt_aead(&aad, conf.value())?;

        drop(aad);

        // sign aad+encrypted data (w/o tag) with user signning key
        // add signature to authenticated data starting with USER_DATA_OFFS
        self.user_data.sign(
            &mut buf[aad_range.start..encr_range.end],
            Self::V1_USER_DATA_OFFS,
        )?;

        // encrypt again with signed data
        buf[encr_range.clone()].copy_from_slice(conf.value());
        ctx.encrypt_aead(&buf[aad_range], &buf[encr_range])
            .map(|res| res.data())
    }
}

impl Request for AddSecretRequest {
    fn encrypt(&self, ctx: &ReqEncrCtx) -> Result<Vec<u8>> {
        match self.user_data {
            UserData::Null | UserData::Unsigned(_) => {
                let conf = self.conf.to_bytes();
                let aad = self.aad(ctx, conf.value().len())?;
                ctx.encrypt_aead(&aad, conf.value()).map(|res| res.data())
            }
            _ => self.encrypt_with_signed_user_data(ctx),
        }
    }

    fn add_hostkey(&mut self, hostkey: PKey<Public>) {
        self.keyslots.push(Keyslot::new(hostkey))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn guest_secret_bin_null() {
        let gs: BinGuestSecret = GuestSecret::Null.into();
        let gs_bytes = gs.dump_auth();
        let exp = vec![0u8, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        assert_eq!(exp, gs_bytes);
        assert_eq!(&Vec::<u8>::new(), gs.confidential())
    }

    #[test]
    fn guest_secret_bin_ap() {
        let gs: BinGuestSecret = GuestSecret::Association {
            name: "test".to_string(),
            id: [1; 32].into(),
            secret: [2; 32].into(),
        }
        .into();
        let gs_bytes_auth = gs.dump_auth();
        let mut exp = vec![0u8, 0, 0, 2, 0, 0, 0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0];
        exp.extend([1; 32]);

        assert_eq!(exp, gs_bytes_auth);
        assert_eq!(&[2; 32], gs.confidential());
    }
}
