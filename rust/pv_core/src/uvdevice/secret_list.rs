// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use crate::assert_size;
use crate::{misc::to_u16, uv::ListCmd, uvdevice::UvCmd, Error, Result};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use serde::{Deserialize, Serialize, Serializer};
use std::{
    fmt::Display,
    io::{Cursor, Read, Seek, Write},
    slice::Iter,
    vec::IntoIter,
};
use zerocopy::{AsBytes, FromBytes, FromZeroes, U16, U32};

/// The 32 byte long ID of an UV secret
///
/// (de)serializes itself in/from a hex-string
#[repr(C)]
#[derive(PartialEq, Eq, AsBytes, FromZeroes, FromBytes, Debug, Clone)]
pub struct SecretId([u8; Self::ID_SIZE]);
assert_size!(SecretId, SecretId::ID_SIZE);

impl SecretId {
    /// Size in bytes of the [`SecretId`]
    pub const ID_SIZE: usize = 32;

    /// Create a [`SecretId`] forom a buffer.
    pub fn from(buf: [u8; Self::ID_SIZE]) -> Self {
        buf.into()
    }
}

impl Serialize for SecretId {
    fn serialize<S>(&self, ser: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // calls Display at one point
        ser.serialize_str(&self.to_string())
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

impl Display for SecretId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = String::with_capacity(32 * 2 + 2);
        s.push_str("0x");
        let s = self.0.iter().fold(s, |acc, e| acc + &format!("{e:02x}"));
        write!(f, "{s}")
    }
}

impl From<[u8; SecretId::ID_SIZE]> for SecretId {
    fn from(value: [u8; SecretId::ID_SIZE]) -> Self {
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
#[derive(Debug, PartialEq, Eq, AsBytes, FromZeroes, FromBytes, Serialize)]
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
    /// Ultravisor. Use of [`SecretList::decode`] in any non-test environments is encuraged.
    pub fn new(index: u16, stype: ListableSecretType, id: SecretId, secret_len: u32) -> Self {
        Self {
            index: index.into(),
            stype: stype.into(),
            len: secret_len.into(),
            res_8: 0,
            id,
        }
    }

    /// Returns the index of this [`SecretEntry`].
    pub fn index(&self) -> u16 {
        self.index.get()
    }

    /// Returns the secret type of this [`SecretEntry`].
    pub fn stype(&self) -> ListableSecretType {
        self.stype.into()
    }

    /// Returns a reference to the id of this [`SecretEntry`].
    ///
    /// The slice is guaranteed to be 32 bytes long.
    /// ```rust
    /// # use s390_pv_core::uv::SecretEntry;
    /// # use zerocopy::FromZeroes;
    /// # let secr = SecretEntry::new_zeroed();
    /// # assert_eq!(secr.id().len(), 32);
    /// ```
    pub fn id(&self) -> &[u8] {
        self.id.as_ref()
    }
}

impl Display for SecretEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let stype: ListableSecretType = self.stype.into();
        writeln!(f, "{} {}:", self.index, stype)?;
        write!(f, "  ")?;
        for b in self.id.as_ref() {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// List of secrets used to parse the [`crate::uv::ListCmd`] result.
///
/// The list should not hold more than 0xffffffff elements
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct SecretList {
    total_num_secrets: usize,
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
    /// Creates a new SecretList.
    ///
    /// The content of this list will very likely not represent the status of the guest in the
    /// Ultravisor. Use of [`SecretList::decode`] in any non-test environments is encuraged.
    pub fn new(total_num_secrets: u16, secrets: Vec<SecretEntry>) -> Self {
        Self {
            total_num_secrets: total_num_secrets as usize,
            secrets,
        }
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
        self.total_num_secrets
    }

    /// Encodes the list in the same binary format the UV would do
    pub fn encode<T: Write>(&self, w: &mut T) -> Result<()> {
        let num_s = to_u16(self.secrets.len()).ok_or(Error::ManySecrets)?;
        w.write_u16::<BigEndian>(num_s)?;
        w.write_u16::<BigEndian>(
            self.total_num_secrets
                .try_into()
                .map_err(|_| Error::ManySecrets)?,
        )?;
        w.write_all(&[0u8; 12])?;
        for secret in &self.secrets {
            w.write_all(secret.as_bytes())?;
        }
        w.flush().map_err(Error::Io)
    }

    /// Decodes the list from the binary format of the UV into this internal representation
    pub fn decode<R: Read + Seek>(r: &mut R) -> std::io::Result<Self> {
        let num_s = r.read_u16::<BigEndian>()?;
        let total_num_secrets = r.read_u16::<BigEndian>()? as usize;
        let mut v: Vec<SecretEntry> = Vec::with_capacity(num_s as usize);
        r.seek(std::io::SeekFrom::Current(12))?; // skip reserved bytes
        let mut buf = [0u8; SecretEntry::STRUCT_SIZE];
        for _ in 0..num_s {
            r.read_exact(&mut buf)?;
            // cannot fail. buffer has the same size as the secret entry
            let secr = SecretEntry::read_from(buf.as_slice()).unwrap();
            v.push(secr);
        }
        Ok(Self {
            total_num_secrets,
            secrets: v,
        })
    }
}

impl TryFrom<ListCmd> for SecretList {
    type Error = Error;

    fn try_from(mut list: ListCmd) -> Result<SecretList> {
        SecretList::decode(&mut Cursor::new(list.data().unwrap())).map_err(Error::InvSecretList)
    }
}

impl Display for SecretList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Total number of secrets: {}", self.total_num_secrets)?;
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
    /// Invalid secret type, that should never appear in a list
    ///
    /// 0 is reserved
    /// 1 is Null secret, with no id and not listable
    Invalid(u16),
    /// Unknown secret type
    Unknown(u16),
}

impl ListableSecretType {
    /// UV type id for an association secret
    pub const ASSOCIATION: u16 = 0x0002;
    /// UV type id for a null secret
    pub const NULL: u16 = 0x0001;
    const RESERVED_0: u16 = 0x0000;
}

impl Display for ListableSecretType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Association => write!(f, "Association"),
            Self::Invalid(n) => write!(f, "Invalid({n})"),
            Self::Unknown(n) => write!(f, "Unknown({n})"),
        }
    }
}

impl From<U16<BigEndian>> for ListableSecretType {
    fn from(value: U16<BigEndian>) -> Self {
        match value.get() {
            Self::RESERVED_0 => Self::Invalid(Self::RESERVED_0),
            Self::NULL => Self::Invalid(Self::NULL),
            Self::ASSOCIATION => ListableSecretType::Association,
            n => Self::Unknown(n),
        }
    }
}

impl From<ListableSecretType> for U16<BigEndian> {
    fn from(value: ListableSecretType) -> Self {
        match value {
            ListableSecretType::Association => ListableSecretType::ASSOCIATION,
            ListableSecretType::Invalid(n) | ListableSecretType::Unknown(n) => n,
        }
        .into()
    }
}

fn de_gsid<'de, D>(de: D) -> Result<[u8; 32], D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct FieldVisitor;

    impl<'de> serde::de::Visitor<'de> for FieldVisitor {
        type Value = [u8; SecretId::ID_SIZE];

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a `32 bytes long hexstring` prepended with 0x")
        }

        fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if s.len() != SecretId::ID_SIZE * 2 + 2 {
                return Err(serde::de::Error::invalid_length(s.len(), &self));
            }
            let nb = s.strip_prefix("0x").ok_or_else(|| {
                serde::de::Error::invalid_value(serde::de::Unexpected::Str(s), &self)
            })?;
            crate::misc::parse_hex(nb)
                .try_into()
                .map_err(|_| serde::de::Error::invalid_value(serde::de::Unexpected::Str(s), &self))
        }
    }
    de.deserialize_identifier(FieldVisitor)
}

#[cfg(test)]
mod test {

    use serde_test::{assert_ser_tokens, assert_tokens, Token};

    use super::*;
    use std::io::{BufReader, BufWriter, Cursor};

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
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, // reserved
            // secret
            0x00, 0x01, 0x00, 0x02, // idx + type
            0x00, 0x00, 0x00, 0x20, // len
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // reserved
            // id
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let exp = SecretList {
            total_num_secrets: 0x112,
            secrets: vec![SecretEntry {
                index: 1.into(),
                stype: 2.into(),
                len: 32.into(),
                res_8: 0,
                id: SecretId::from([0; 32]),
            }],
        };

        let mut br = BufReader::new(Cursor::new(buf));
        let sl = SecretList::decode(&mut br).unwrap();
        assert_eq!(sl, exp);
    }

    #[test]
    fn secret_list_enc() {
        const EXP: &[u8] = &[
            0x00, 0x01, // num secr stored
            0x01, 0x12, // total num secrets
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, // reserved
            // secret
            0x00, 0x01, 0x00, 0x02, // idx + type
            0x00, 0x00, 0x00, 0x20, // len
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // reserved
            // id
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let sl = SecretList {
            total_num_secrets: 0x112,
            secrets: vec![SecretEntry {
                index: 1.into(),
                stype: 2.into(),
                len: 32.into(),
                res_8: 0,
                id: SecretId::from([0; 32]),
            }],
        };

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
}
