// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use crate::{
    assert_size,
    uv::{AesSizes, AesXtsSizes, EcCurves, HmacShaSizes, ListCmd, RetrievableSecret},
    uvdevice::UvCmd,
    Error, Result,
};
use serde::{Deserialize, Serialize, Serializer};
use std::{
    cmp::min,
    ffi::CStr,
    fmt::{Debug, Display, LowerHex, UpperHex},
    io::{Cursor, Read, Seek, Write},
    mem::size_of,
    slice::Iter,
    vec::IntoIter,
};
use zerocopy::{BigEndian, ByteOrder};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, U16, U32};

/// The 32 byte long ID of an UV secret
///
/// (de)serializes itself in/from a hex-string
#[repr(C)]
#[derive(PartialEq, Eq, IntoBytes, FromBytes, Debug, Clone, Default, Immutable, KnownLayout)]
pub struct SecretId([u8; Self::ID_SIZE]);
assert_size!(SecretId, SecretId::ID_SIZE);

impl SecretId {
    /// Size in bytes of the [`SecretId`]
    pub const ID_SIZE: usize = 32;

    /// Create a [`SecretId`] from a buffer.
    pub fn from(buf: [u8; Self::ID_SIZE]) -> Self {
        buf.into()
    }

    /// Create a Id from a string
    ///
    /// Uses the first 31 bytes from `name` as id
    /// Does not hash anything. Byte 32 is the NUL char
    pub fn from_string(name: &str) -> Self {
        let len = min(name.len(), Self::ID_SIZE - 1);
        let mut res = Self::default();
        res.0[0..len].copy_from_slice(&name.as_bytes()[0..len]);
        res
    }

    /// Tries to represent the Id as printable-ASCII string
    pub fn as_ascii(&self) -> Option<&str> {
        if let Ok(t) = CStr::from_bytes_until_nul(&self.0) {
            if let Ok(t) = t.to_str() {
                if !t.is_empty()
                    && t.chars()
                        .all(|c| c.is_ascii_whitespace() | c.is_ascii_graphic())
                    && self.0[t.len()..].iter().all(|b| *b == 0)
                {
                    return Some(t);
                }
            }
        };
        None
    }
}

impl Serialize for SecretId {
    fn serialize<S>(&self, ser: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // calls LowerHex at one point
        ser.serialize_str(&format!("{self:#x}"))
    }
}

impl<'de> Deserialize<'de> for SecretId {
    fn deserialize<D>(de: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        de_gsid(de).map(|id| id.into())
    }
}

impl UpperHex for SecretId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if f.alternate() {
            write!(f, "0x")?;
        }
        for b in self.0 {
            write!(f, "{b:02X}")?;
        }
        Ok(())
    }
}

impl LowerHex for SecretId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if f.alternate() {
            write!(f, "0x")?;
        }
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl Display for SecretId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(s) = self.as_ascii() {
            write!(f, "{s} | ")?;
        }
        write!(f, "{self:#x}")
    }
}

impl From<[u8; Self::ID_SIZE]> for SecretId {
    fn from(value: [u8; Self::ID_SIZE]) -> Self {
        Self(value)
    }
}

impl AsRef<[u8]> for SecretId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A secret in a [`SecretList`]
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq, IntoBytes, FromBytes, Serialize, Immutable)]
pub struct SecretEntry {
    #[serde(serialize_with = "ser_u16")]
    index: U16<BigEndian>,
    #[serde(serialize_with = "ser_u16")]
    stype: U16<BigEndian>,
    #[serde(serialize_with = "ser_u32")]
    len: U32<BigEndian>,
    #[serde(skip)]
    res_8: u64,
    id: SecretId,
}
assert_size!(SecretEntry, SecretEntry::STRUCT_SIZE);

impl SecretEntry {
    const STRUCT_SIZE: usize = 0x30;

    /// Create a new entry for a [`SecretList`].
    ///
    /// The content of this entry will very likely not represent the status of the guest in the
    /// Ultravisor. Use of [`SecretList::decode`] in any non-test environments is encouraged.
    pub fn new(index: u16, stype: ListableSecretType, id: SecretId, secret_len: u32) -> Self {
        Self {
            index: index.into(),
            stype: U16::new(stype.into()),
            len: secret_len.into(),
            res_8: 0,
            id,
        }
    }

    /// Returns the index of this [`SecretEntry`].
    pub fn index(&self) -> u16 {
        self.index.get()
    }

    /// Returns the index of this [`SecretEntry`] in BE.
    pub(crate) fn index_be(&self) -> &U16<BigEndian> {
        &self.index
    }

    /// Returns the secret type of this [`SecretEntry`]
    pub fn stype(&self) -> ListableSecretType {
        self.stype.get().into()
    }

    /// Returns a reference to the id of this [`SecretEntry`].
    ///
    /// The slice is guaranteed to be 32 bytes long.
    /// ```rust
    /// # use s390_pv_core::uv::SecretEntry;
    /// # use zerocopy::FromZeros;
    /// # let secr = SecretEntry::new_zeroed();
    /// # assert_eq!(secr.id().len(), 32);
    /// ```
    pub fn id(&self) -> &[u8] {
        self.id.as_ref()
    }

    /// Get the id as [`SecretId`] reference
    pub(crate) fn secret_id(&self) -> &SecretId {
        &self.id
    }

    /// Returns the secret size of this [`SecretEntry`].
    pub fn secret_size(&self) -> u32 {
        self.len.get()
    }
}

impl Display for SecretEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let stype: ListableSecretType = self.stype.get().into();
        writeln!(f, "{} {}:", self.index, stype)?;
        write!(f, " {}", self.id)
    }
}

#[repr(C)]
#[derive(
    Debug, FromBytes, IntoBytes, Clone, PartialEq, Eq, Default, Serialize, Immutable, KnownLayout,
)]
struct SecretListHdr {
    #[serde(skip)]
    num_secrets_stored: U16<BigEndian>,
    #[serde(serialize_with = "ser_u16")]
    total_num_secrets: U16<BigEndian>,
    #[serde(skip)]
    next_secret_idx: U16<BigEndian>,
    #[serde(skip)]
    reserved_06: u16,
    #[serde(skip)]
    reserved_08: u64,
}

impl SecretListHdr {
    fn new(num_secrets_stored: u16, total_num_secrets: u16, next_secret_idx: u16) -> Self {
        Self {
            num_secrets_stored: num_secrets_stored.into(),
            total_num_secrets: total_num_secrets.into(),
            next_secret_idx: next_secret_idx.into(),
            reserved_06: 0,
            reserved_08: 0,
        }
    }
}
assert_size!(SecretListHdr, 16);

/// List of secrets used to parse the [`crate::uv::ListCmd`] result.
///
/// The list should ONLY be created from an UV-Call result using either:
/// - [`TryInto::try_into`] from [`ListCmd`]
/// - [`SecretList::decode`]
///
/// Any other ways can create invalid lists that do not represent the UV secret store.
/// The list must not hold more than [`u32::MAX`] elements
#[derive(Debug, PartialEq, Eq, Serialize, Default)]
pub struct SecretList {
    #[serde(flatten)]
    hdr: SecretListHdr,
    secrets: Vec<SecretEntry>,
}

impl<'a> IntoIterator for &'a SecretList {
    type IntoIter = Iter<'a, SecretEntry>;
    type Item = &'a SecretEntry;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl IntoIterator for SecretList {
    type IntoIter = IntoIter<Self::Item>;
    type Item = SecretEntry;

    fn into_iter(self) -> Self::IntoIter {
        self.secrets.into_iter()
    }
}

impl FromIterator<SecretEntry> for SecretList {
    fn from_iter<T: IntoIterator<Item = SecretEntry>>(iter: T) -> Self {
        let secrets: Vec<_> = iter.into_iter().collect();
        let total_num_secrets = secrets.len() as u16;
        Self::new(total_num_secrets, secrets)
    }
}

impl SecretList {
    /// Creates a new `SecretList`.
    ///
    /// The content of this list will very likely not represent the status of the guest in the
    /// Ultravisor. Use of [`SecretList::decode`] in any non-test environments is encuraged.
    pub fn new(total_num_secrets: u16, secrets: Vec<SecretEntry>) -> Self {
        Self::new_with_hdr(
            SecretListHdr::new(total_num_secrets, total_num_secrets, 0),
            secrets,
        )
    }

    fn new_with_hdr(hdr: SecretListHdr, secrets: Vec<SecretEntry>) -> Self {
        Self { hdr, secrets }
    }

    /// Returns an iterator over the slice.
    ///
    /// The iterator yields all secret entries from start to end.
    pub fn iter(&self) -> Iter<'_, SecretEntry> {
        self.secrets.iter()
    }

    /// Returns the length of this [`SecretList`].
    pub fn len(&self) -> usize {
        self.secrets.len()
    }

    /// Returns `true` if the [`SecretList`] contains no [`SecretEntry`].
    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }

    /// Reports the number of secrets stored in UV.
    ///
    /// This number may be not equal to the provided number of [`SecretEntry`]
    pub fn total_num_secrets(&self) -> usize {
        self.hdr.total_num_secrets.get() as usize
    }

    /// Find the first [`SecretEntry`] that has the provided [`SecretId`]
    pub fn find(&self, id: &SecretId) -> Option<SecretEntry> {
        self.iter().find(|e| e.id() == id.as_ref()).cloned()
    }

    /// Encodes the list in the same binary format the UV would do
    pub fn encode<T: Write>(&self, w: &mut T) -> Result<()> {
        let hdr = self.hdr.as_bytes();
        w.write_all(hdr)?;
        for secret in &self.secrets {
            w.write_all(secret.as_bytes())?;
        }
        w.flush().map_err(Error::Io)
    }

    /// Decodes the list from the binary format of the UV into this internal representation
    pub fn decode<R: Read + Seek>(r: &mut R) -> std::io::Result<Self> {
        let mut buf = [0u8; size_of::<SecretListHdr>()];
        r.read_exact(&mut buf)?;
        let hdr = SecretListHdr::ref_from_bytes(&buf).unwrap();

        let mut buf = [0u8; SecretEntry::STRUCT_SIZE];
        let mut v = Vec::with_capacity(hdr.num_secrets_stored.get() as usize);
        for _ in 0..hdr.num_secrets_stored.get() {
            r.read_exact(&mut buf)?;
            // cannot fail. buffer has the same size as the secret entry
            let secr = SecretEntry::read_from_bytes(buf.as_slice()).unwrap();
            v.push(secr);
        }
        Ok(Self {
            hdr: hdr.clone(),
            secrets: v,
        })
    }
}

impl TryFrom<ListCmd> for SecretList {
    type Error = Error;

    fn try_from(mut list: ListCmd) -> Result<Self> {
        Self::decode(&mut Cursor::new(list.data().unwrap())).map_err(Error::InvSecretList)
    }
}

impl Display for SecretList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Total number of secrets: {}", self.total_num_secrets())?;
        if !self.secrets.is_empty() {
            writeln!(f)?;
        }
        for s in &self.secrets {
            writeln!(f, "{s}")?;
        }
        Ok(())
    }
}

fn ser_u32<S: Serializer>(v: &U32<BigEndian>, ser: S) -> Result<S::Ok, S::Error> {
    ser.serialize_u32(v.get())
}

fn ser_u16<S: Serializer>(v: &U16<BigEndian>, ser: S) -> Result<S::Ok, S::Error> {
    ser.serialize_u16(v.get())
}

/// Secret types that can appear in a [`SecretList`]
#[non_exhaustive]
#[derive(PartialEq, Eq, Debug)]
pub enum ListableSecretType {
    /// Association Secret
    Association,
    /// Retrievable key
    Retrievable(RetrievableSecret),

    /// Invalid secret type, that should never appear in a list
    ///
    /// 0 is reserved
    /// 1 is Null secret, with no id and not list-able
    /// 21 is Update CCK secret, with no id and not list-able
    Invalid(u16),
    /// Unknown secret type
    Unknown(u16),
}

impl ListableSecretType {
    const RESERVED_0: u16 = 0x0000;
    /// UV secret-type id for a null secret
    pub const NULL: u16 = 0x0001;
    /// UV secret-type id for an association secret
    pub const ASSOCIATION: u16 = 0x0002;
    /// UV secret-type id for a plain text secret
    pub const PLAINTEXT: u16 = 0x0003;
    /// UV secret-type id for an aes-128-key secret
    pub const AES_128_KEY: u16 = 0x0004;
    /// UV secret-type id for an aes-192-key secret
    pub const AES_192_KEY: u16 = 0x0005;
    /// UV secret-type id for an aes-256-key secret
    pub const AES_256_KEY: u16 = 0x0006;
    /// UV secret-type id for an aes-xts-128-key secret
    pub const AES_128_XTS_KEY: u16 = 0x0007;
    /// UV secret-type id for an aes-xts-256-key secret
    pub const AES_256_XTS_KEY: u16 = 0x0008;
    /// UV secret-type id for an hmac-sha-256-key secret
    pub const HMAC_SHA_256_KEY: u16 = 0x0009;
    /// UV secret-type id for an hmac-sha-512-key secret
    pub const HMAC_SHA_512_KEY: u16 = 0x000a;
    // 0x000b - 0x0010 reserved
    /// UV secret-type id for an ecdsa-p256-private-key secret
    pub const ECDSA_P256_KEY: u16 = 0x0011;
    /// UV secret-type id for an ecdsa-p384-private-key secret
    pub const ECDSA_P384_KEY: u16 = 0x0012;
    /// UV secret-type id for an ecdsa-p521-private-key secret
    pub const ECDSA_P521_KEY: u16 = 0x0013;
    /// UV secret-type id for an ed25519-private-key secret
    pub const ECDSA_ED25519_KEY: u16 = 0x0014;
    /// UV secret-type id for an ed448-private-key secret
    pub const ECDSA_ED448_KEY: u16 = 0x0015;
    /// UV secret-type id for a new customer communication key
    pub const UPDATE_CCK: u16 = 0x0016;
}

impl Display for ListableSecretType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Association => write!(f, "Association"),
            Self::Invalid(n) => write!(f, "Invalid(0x{n:04x})"),
            Self::Unknown(n) => write!(f, "Unknown(0x{n:04x})"),
            Self::Retrievable(r) => write!(f, "{r}"),
        }
    }
}

impl<O: ByteOrder> From<U16<O>> for ListableSecretType {
    fn from(value: U16<O>) -> Self {
        value.get().into()
    }
}

impl From<u16> for ListableSecretType {
    fn from(value: u16) -> Self {
        match value {
            Self::RESERVED_0 => Self::Invalid(Self::RESERVED_0),
            Self::NULL => Self::Invalid(Self::NULL),
            Self::ASSOCIATION => Self::Association,
            Self::PLAINTEXT => Self::Retrievable(RetrievableSecret::PlainText),
            Self::AES_128_KEY => Self::Retrievable(RetrievableSecret::Aes(AesSizes::Bits128)),
            Self::AES_192_KEY => Self::Retrievable(RetrievableSecret::Aes(AesSizes::Bits192)),
            Self::AES_256_KEY => Self::Retrievable(RetrievableSecret::Aes(AesSizes::Bits256)),
            Self::AES_128_XTS_KEY => {
                Self::Retrievable(RetrievableSecret::AesXts(AesXtsSizes::Bits128))
            }
            Self::AES_256_XTS_KEY => {
                Self::Retrievable(RetrievableSecret::AesXts(AesXtsSizes::Bits256))
            }
            Self::HMAC_SHA_256_KEY => {
                Self::Retrievable(RetrievableSecret::HmacSha(HmacShaSizes::Sha256))
            }
            Self::HMAC_SHA_512_KEY => {
                Self::Retrievable(RetrievableSecret::HmacSha(HmacShaSizes::Sha512))
            }
            Self::ECDSA_P256_KEY => Self::Retrievable(RetrievableSecret::Ec(EcCurves::Secp256R1)),
            Self::ECDSA_P384_KEY => Self::Retrievable(RetrievableSecret::Ec(EcCurves::Secp384R1)),
            Self::ECDSA_P521_KEY => Self::Retrievable(RetrievableSecret::Ec(EcCurves::Secp521R1)),
            Self::ECDSA_ED25519_KEY => Self::Retrievable(RetrievableSecret::Ec(EcCurves::Ed25519)),
            Self::ECDSA_ED448_KEY => Self::Retrievable(RetrievableSecret::Ec(EcCurves::Ed448)),
            Self::UPDATE_CCK => Self::Invalid(Self::UPDATE_CCK),
            n => Self::Unknown(n),
        }
    }
}

impl<O: ByteOrder> From<ListableSecretType> for U16<O> {
    fn from(value: ListableSecretType) -> Self {
        Self::new(value.into())
    }
}

impl From<ListableSecretType> for u16 {
    fn from(value: ListableSecretType) -> Self {
        match value {
            ListableSecretType::Association => ListableSecretType::ASSOCIATION,
            ListableSecretType::Invalid(n) | ListableSecretType::Unknown(n) => n,
            ListableSecretType::Retrievable(r) => (&r).into(),
        }
    }
}

fn de_gsid<'de, D>(de: D) -> Result<[u8; 32], D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct FieldVisitor;

    impl serde::de::Visitor<'_> for FieldVisitor {
        type Value = [u8; SecretId::ID_SIZE];

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a `32 bytes (=64 character) long hexstring` prepended with 0x")
        }

        fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if s.len() != SecretId::ID_SIZE * 2 + "0x".len() {
                return Err(serde::de::Error::invalid_length(
                    s.len().saturating_sub("0x".len()),
                    &self,
                ));
            }
            let nb = s.strip_prefix("0x").ok_or_else(|| {
                serde::de::Error::invalid_value(serde::de::Unexpected::Str(s), &self)
            })?;
            crate::misc::decode_hex(nb)
                .map_err(|_| serde::de::Error::invalid_value(serde::de::Unexpected::Str(s), &self))?
                .try_into()
                .map_err(|_| serde::de::Error::invalid_value(serde::de::Unexpected::Str(s), &self))
        }
    }
    de.deserialize_identifier(FieldVisitor)
}

#[cfg(test)]
mod test {

    use std::io::{BufReader, BufWriter, Cursor};

    use serde_test::{assert_ser_tokens, assert_tokens, Token};
    use zerocopy::FromZeros;

    use super::*;

    #[test]
    fn dump_secret_entry() {
        const EXP: &[u8] = &[
            0x00, 0x01, 0x00, 0x02, // idx + type
            0x00, 0x00, 0x00, 0x20, // len
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // reserved
            // id
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let s = SecretEntry {
            index: 1.into(),
            stype: 2.into(),
            len: 32.into(),
            res_8: 0,
            id: SecretId::from([0; 32]),
        };

        assert_eq!(s.as_bytes(), EXP);
    }

    #[test]
    fn secret_list_dec() {
        let buf = [
            0x00u8, 0x01, // num secr stored
            0x01, 0x12, // total num secrets
            0x01, 0x01, // next valid idx
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // reserved
            // secret
            0x00, 0x01, 0x00, 0x02, // idx + type
            0x00, 0x00, 0x00, 0x20, // len
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // reserved
            // id
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let exp = SecretList::new_with_hdr(
            SecretListHdr::new(0x001, 0x112, 0x101),
            vec![SecretEntry {
                index: 1.into(),
                stype: 2.into(),
                len: 32.into(),
                res_8: 0,
                id: SecretId::from([0; 32]),
            }],
        );

        let mut br = BufReader::new(Cursor::new(buf));
        let sl = SecretList::decode(&mut br).unwrap();
        assert_eq!(sl, exp);
    }

    #[test]
    fn secret_list_enc() {
        const EXP: &[u8] = &[
            0x00, 0x01, // num secr stored
            0x01, 0x12, // total num secrets
            0x01, 0x01, // next valid idx
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // reserved
            // secret
            0x00, 0x01, 0x00, 0x02, // idx + type
            0x00, 0x00, 0x00, 0x20, // len
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // reserved
            // id
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let sl = SecretList::new_with_hdr(
            SecretListHdr::new(0x001, 0x112, 0x101),
            vec![SecretEntry {
                index: 1.into(),
                stype: 2.into(),
                len: 32.into(),
                res_8: 0,
                id: SecretId::from([0; 32]),
            }],
        );

        let mut buf = [0u8; 0x40];
        {
            let mut bw = BufWriter::new(&mut buf[..]);
            sl.encode(&mut bw).unwrap();
        }
        println!("list: {sl:?}");
        assert_eq!(buf, EXP);
    }

    #[test]
    fn secret_entry_ser() {
        let entry = SecretEntry::new_zeroed();

        assert_ser_tokens(
            &entry,
            &[
                Token::Struct {
                    name: "SecretEntry",
                    len: (4),
                },
                Token::String("index"),
                Token::U16(0),
                Token::String("stype"),
                Token::U16(0),
                Token::String("len"),
                Token::U32(0),
                Token::String("id"),
                Token::String("0x0000000000000000000000000000000000000000000000000000000000000000"),
                Token::StructEnd,
            ],
        )
    }

    #[test]
    fn secret_id_serde() {
        let id = SecretId::from([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ]);
        assert_tokens(
            &id,
            &[Token::String(
                "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )],
        )
    }

    #[test]
    fn secret_list_ser() {
        let list = SecretList::new_with_hdr(
            SecretListHdr::new(0x001, 0x112, 0x101),
            vec![SecretEntry {
                index: 1.into(),
                stype: 2.into(),
                len: 32.into(),
                res_8: 0,
                id: SecretId::from([0; 32]),
            }],
        );

        assert_ser_tokens(
            &list,
            &[
                Token::Map { len: None },
                Token::String("total_num_secrets"),
                Token::U16(0x112),
                Token::String("secrets"),
                Token::Seq { len: Some(1) },
                Token::Struct {
                    name: "SecretEntry",
                    len: (4),
                },
                Token::String("index"),
                Token::U16(1),
                Token::String("stype"),
                Token::U16(2),
                Token::String("len"),
                Token::U32(32),
                Token::String("id"),
                Token::String("0x0000000000000000000000000000000000000000000000000000000000000000"),
                Token::StructEnd,
                Token::SeqEnd,
                Token::MapEnd,
            ],
        )
    }

    #[test]
    fn secret_id_display() {
        let text = "Fancy secret ID";
        let id = SecretId::from_string(text);

        let exp =
            "Fancy secret ID | 0x46616e6379207365637265742049440000000000000000000000000000000000";
        assert_eq!(id.to_string(), exp);
    }

    #[test]
    fn secret_id_long_name() {
        let text = "the most fanciest secret ID you ever seen in the time the universe exists";
        let id = SecretId::from_string(text);
        let exp =
            "the most fanciest secret ID you | 0x746865206d6f73742066616e63696573742073656372657420494420796f7500";
        assert_eq!(id.to_string(), exp);
    }

    #[test]
    fn secret_id_no_ascii_name() {
        let text = [0; 32];
        let id = SecretId::from(text);

        let exp = "0x0000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(id.to_string(), exp);
    }

    #[test]
    fn secret_id_no_ascii_name2() {
        let text = [
            0x25, 0x55, 3, 4, 50, 0, 6, 0, 8, 0, 0, 0, 0, 0, 0, 0, 90, 0, 0xa, 0, 0, 0, 0, 0xf, 0,
            0, 0, 0, 0, 0, 0, 0,
        ];
        let id = SecretId::from(text);
        assert_eq!(id.as_ascii(), None);
    }

    #[test]
    fn secret_id_no_ascii_name3() {
        let text = [
            0x25, 0x55, 0, 4, 50, 0, 6, 0, 8, 0, 0, 0, 0, 0, 0, 0, 90, 0, 0xa, 0, 0, 0, 0, 0xf, 0,
            0, 0, 0, 0, 0, 0, 0,
        ];
        let id = SecretId::from(text);
        assert_eq!(id.as_ascii(), None);
    }

    #[test]
    fn secret_id_hex() {
        let id_str = "Nice Test 123";
        let id = SecretId::from_string(id_str);

        let s = format!("{id:#x}");
        assert_eq!(
            s,
            "0x4e69636520546573742031323300000000000000000000000000000000000000"
        );
        let s = format!("{id:x}");
        assert_eq!(
            s,
            "4e69636520546573742031323300000000000000000000000000000000000000"
        );
        let s = format!("{id:#X}");
        assert_eq!(
            s,
            "0x4E69636520546573742031323300000000000000000000000000000000000000"
        );

        let s = format!("{id:X}");
        assert_eq!(
            s,
            "4E69636520546573742031323300000000000000000000000000000000000000"
        );
    }
}
