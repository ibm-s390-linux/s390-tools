// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use serde::{Serialize, Serializer};
use std::{
    fmt::Display,
    io::{Cursor, Read, Seek, Write},
    slice::Iter,
    vec::IntoIter,
};
use utils::assert_size;
use zerocopy::{AsBytes, FromBytes, FromZeroes, U16, U32};

use crate::{misc::to_u16, uv::ListCmd, uvdevice::UvCmd, Error, Result};

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
    #[serde(serialize_with = "ser_gsid")]
    id: [u8; SECRET_ID_SIZE],
}
assert_size!(SecretEntry, SecretEntry::STRUCT_SIZE);

impl SecretEntry {
    const STRUCT_SIZE: usize = 0x30;

    /// Create a new entry for a [`SecretList`].
    ///
    /// The content of this entry will very liekly not represent the status of the guest in the
    /// Ultravisor. Use of [`SecretList::decode`] in any non-test environments is encuraged.
    pub fn new(index: u16, stype: ListableSecretType, id: [u8; 32], secret_len: u32) -> Self {
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
    pub fn id(&self) -> &[u8] {
        &self.id
    }
}

impl Display for SecretEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let stype: ListableSecretType = self.stype.into();
        writeln!(f, "{} {}:", self.index, stype)?;
        write!(f, "  ")?;
        for b in self.id {
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
    type Item = &'a SecretEntry;
    type IntoIter = Iter<'a, SecretEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl IntoIterator for SecretList {
    type Item = SecretEntry;
    type IntoIter = IntoIter<Self::Item>;

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
    /// The content of this list will very liekly not represent the status of the guest in the
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
        r.seek(std::io::SeekFrom::Current(12))?; //skip reserved bytes
        let mut buf = [0u8; SecretEntry::STRUCT_SIZE];
        for _ in 0..num_s {
            r.read_exact(&mut buf)?;
            //cannot fail. buffer has the same size as the secret entry
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
#[derive(PartialEq, Eq)]
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
    const RESERVED_0: u16 = 0x0000;
    const NULL: u16 = 0x0001;
    const ASSOCIATION: u16 = 0x0002;
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

#[doc(hidden)]
pub const SECRET_ID_SIZE: usize = 32;

#[doc(hidden)]
pub fn ser_gsid<S>(id: &[u8; SECRET_ID_SIZE], ser: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut s = String::with_capacity(32 * 2 + 2);
    s.push_str("0x");
    let s = id.iter().fold(s, |acc, e| acc + &format!("{e:02x}"));
    ser.serialize_str(&s)
}

#[cfg(test)]
mod test {

    use super::*;
    use std::io::{BufReader, BufWriter, Cursor};

    #[test]
    fn dump_secret_entry() {
        const EXP: &[u8] = &[
            0x00, 0x01, 0x00, 0x02, //idx + type
            0x00, 0x00, 0x00, 0x20, //len
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
            id: [0; 32],
        };

        assert_eq!(s.as_bytes(), EXP);
    }

    #[test]
    fn secret_list_dec() {
        let buf = [
            0x00u8, 0x01, // num secr stored
            0x01, 0x12, // total num secrets
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //reserved
            // secret
            0x00, 0x01, 0x00, 0x02, //idx + type
            0x00, 0x00, 0x00, 0x20, //len
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
                id: [0; 32],
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
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //reserved
            // secret
            0x00, 0x01, 0x00, 0x02, //idx + type
            0x00, 0x00, 0x00, 0x20, //len
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
                id: [0; 32],
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
}
