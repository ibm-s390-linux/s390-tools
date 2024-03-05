// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use crate::{pem::Pem, uvsecret::guest_secret::MAX_SIZE_PLAIN_PAYLOAD, Result};

use byteorder::BigEndian;
use log::warn;
use pv_core::{
    request::Confidential,
    uv::{ListableSecretType, RetrievableSecret, RetrieveCmd},
};
use zerocopy::{FromBytes, U16};

/// An IBM Protected Key
///
/// A protected key, writeable as pem.
///
/// Will convert into PEM as:
/// ```PEM
///-----BEGIN IBM PROTECTED KEY-----
///kind: <name>
///
///<protected key in base64>
///-----END IBM PROTECTED KEY-----
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct IbmProtectedKey {
    kind: ListableSecretType,
    key: Confidential<Vec<u8>>,
}

impl IbmProtectedKey {
    /// Get the binary representation of the key.
    pub fn data(&self) -> &[u8] {
        self.key.value()
    }

    /// Converts a [`IbmProtectedKey`] into a vector.
    pub fn into_bytes(self) -> Confidential<Vec<u8>> {
        self.key
    }

    /// Get the data in PEM format.
    ///
    /// # Errors
    ///
    /// This function will return an error if the PEM conversion failed (very unlikely).
    pub fn to_pem(&self) -> Result<Pem> {
        Pem::new(
            "IBM PROTECTED KEY",
            format!("kind: {}", self.kind),
            self.key.value(),
        )
    }

    fn new<K>(kind: ListableSecretType, key: K) -> Self
    where
        K: Into<Confidential<Vec<u8>>>,
    {
        Self {
            kind,
            key: key.into(),
        }
    }
}

impl From<RetrieveCmd> for RetrievedSecret {
    fn from(value: RetrieveCmd) -> Self {
        let kind = value.meta_data().stype();
        let key = value.into_key();

        match kind {
            ListableSecretType::Retrievable(RetrievableSecret::PlainText) => {
                // Will not run into default, retrieve has a granularity of 16 bytes and 16 bytes is the
                // minimum size
                let len = U16::<BigEndian>::read_from_prefix(key.value())
                    .unwrap_or_default()
                    .get() as usize;

                // Test if the plain text secret has a size:
                // 1. len <= 8190
                // 2. first two bytes are max 15 less than buffer-size+2
                // 3. bytes after len + 2 are zero
                match len <= MAX_SIZE_PLAIN_PAYLOAD
                    && key.value().len() - (len + 2) < 15
                    && key.value()[len + 2..].iter().all(|c| *c == 0)
                {
                    false => Self::Plaintext(key),
                    true => Self::Plaintext(key.value()[2..len + 2].to_vec().into()),
                }
            }
            kind => {
                match kind {
                    ListableSecretType::Retrievable(_) => (),
                    _ => warn!("Retrieved an unretrievable Secret! Will continue; interpreting it as a protected key."),
                }
                Self::ProtectedKey(IbmProtectedKey::new(kind, key))
            }
        }
    }
}

/// A retrieved Secret.
#[derive(Debug, PartialEq, Eq)]
pub enum RetrievedSecret {
    /// A plaintext secret
    Plaintext(Confidential<Vec<u8>>),
    /// An [`IbmProtectedKey`]
    ProtectedKey(IbmProtectedKey),
}

impl RetrievedSecret {
    /// Create a new IBM PROTECTED KEY object
    pub fn from_cmd(cmd: RetrieveCmd) -> Self {
        cmd.into()
    }

    /// Get the binary representation of the key.
    pub fn data(&self) -> &[u8] {
        match self {
            RetrievedSecret::Plaintext(p) => p.value(),
            RetrievedSecret::ProtectedKey(p) => p.data(),
        }
    }

    /// Converts a [`IbmProtectedKey`] into a vector.
    pub fn into_bytes(self) -> Confidential<Vec<u8>> {
        match self {
            RetrievedSecret::Plaintext(p) => p,
            RetrievedSecret::ProtectedKey(p) => p.into_bytes(),
        }
    }
    /// Get the data in PEM format.
    ///
    /// # Errors
    ///
    /// This function will return an error if the PEM conversion failed (very unlikely).
    pub fn to_pem(&self) -> Result<Pem> {
        match self {
            RetrievedSecret::Plaintext(p) => Pem::new("PLAINTEXT SECRET", None, p.value()),
            RetrievedSecret::ProtectedKey(p) => p.to_pem(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use pv_core::uv::*;

    fn mk_retr(secret: &[u8]) -> RetrievedSecret {
        let entry = SecretEntry::new(
            0,
            ListableSecretType::Retrievable(RetrievableSecret::PlainText),
            SecretId::default(),
            secret.len() as u32,
        );
        let mut cmd = RetrieveCmd::from_entry(entry).unwrap();
        cmd.data().unwrap().copy_from_slice(secret);
        RetrievedSecret::from_cmd(cmd)
    }

    #[test]
    fn from_retr_cmd() {
        let secret = vec![0, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0, 0, 0, 0];
        let prot_key = mk_retr(&secret);
        let exp = RetrievedSecret::Plaintext(secret[2..12].to_vec().into());
        assert_eq!(prot_key, exp);
    }

    #[test]
    fn from_retr_inv_size() {
        let secret = vec![0x20; 32];
        let prot_key = mk_retr(&secret);
        let exp = RetrievedSecret::Plaintext(secret.into());
        assert_eq!(prot_key, exp);
    }

    #[test]
    fn from_retr_inv_no_zero_after_end() {
        let secret = vec![0, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 1, 0, 0, 0];
        let prot_key = mk_retr(&secret);
        let exp = RetrievedSecret::Plaintext(secret.into());
        assert_eq!(prot_key, exp);
    }

    #[test]
    fn from_retr_inv_to_much_padding() {
        let secret = vec![
            0, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        let prot_key = mk_retr(&secret);
        let exp = RetrievedSecret::Plaintext(secret.into());
        assert_eq!(prot_key, exp);
    }

    #[test]
    fn from_retr_0_size() {
        let secret = vec![0x00; 32];
        let prot_key = mk_retr(&secret);
        let exp = RetrievedSecret::Plaintext(secret.into());
        assert_eq!(prot_key, exp);
    }

    #[test]
    fn plain_text_pem() {
        let exp = "\
            -----BEGIN PLAINTEXT SECRET-----\n\
            ERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERER\n\
            -----END PLAINTEXT SECRET-----\n";
        let prot = RetrievedSecret::Plaintext(vec![17; 48].into());
        let pem = prot.to_pem().unwrap();
        let pem_str = pem.to_string();
        assert_eq!(pem_str, exp);
    }

    #[test]
    fn prot_key_pem() {
        let exp = "\
            -----BEGIN IBM PROTECTED KEY-----\n\
            kind: AES-128-KEY\n\n\
            ERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERER\n\
            -----END IBM PROTECTED KEY-----\n";
        let prot = IbmProtectedKey::new(
            ListableSecretType::Retrievable(RetrievableSecret::Aes(AesSizes::Bits128)),
            vec![17; 48],
        );
        let pem = prot.to_pem().unwrap();
        let pem_str = pem.to_string();
        assert_eq!(pem_str, exp);
    }
}
