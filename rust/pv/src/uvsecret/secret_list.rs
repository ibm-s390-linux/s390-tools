// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

use crate::{misc::to_u16, uv::ListCmd, uvdevice::UvCmd, Error, Result};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use serde::{Serialize, Serializer};
use std::usize;
use std::{
    fmt::Display,
    io::{Cursor, Read, Seek, Write},
};
use zerocopy::{AsBytes, FromBytes, U16, U32};

use super::ser_gsid;

/// List of secrets used to parse the [`crate::uv::ListCmd`] result
///
/// Requires the `uvsecret` feature.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct SecretList {
    total_num_secrets: u16,
    secrets: Vec<SecretEntry>,
}

impl SecretList {
    /// Encodes the list in the same binary format the UV would do
    pub fn encode<T: Write>(&self, w: &mut T) -> Result<()> {
        let num_s = to_u16(self.secrets.len()).ok_or(Error::ManySecrets)?;
        w.write_u16::<BigEndian>(num_s)?;
        w.write_u16::<BigEndian>(self.total_num_secrets)?;
        w.write_all(&[0u8; 12])?;
        for secret in &self.secrets {
            w.write_all(secret.as_bytes())?;
        }
        w.flush().map_err(Error::Io)
    }

    /// Decodes the list from the binary format of the UV into this internal representation
    pub fn decode<R: Read + Seek>(r: &mut R) -> std::io::Result<Self> {
        let num_s = r.read_u16::<BigEndian>()?;
        let total_num_secrets = r.read_u16::<BigEndian>()?;
        let mut v: Vec<SecretEntry> = Vec::with_capacity(num_s as usize);
        r.seek(std::io::SeekFrom::Current(12))?; //skip reserved bytes
        let mut buf = [0u8; SECRET_ENTRY_SIZE];
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

/// A secret in a [`SecretList`]
///
/// Fields are in big endian
#[repr(C)]
#[derive(Debug, PartialEq, Eq, AsBytes, FromBytes, Serialize)]
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
    id: [u8; 32],
}
const SECRET_ENTRY_SIZE: usize = 0x30;

fn stype_str(stype: u16) -> String {
    match stype {
        // should never match (not incl in list), but here for completeness
        1 => "Null".to_string(),
        2 => "Association".to_string(),
        n => format!("Unknown {n}"),
    }
}

impl Display for SecretEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{} {}:", self.index, stype_str(self.stype.get()))?;
        write!(f, "  ")?;
        for b in self.id {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::{BufReader, BufWriter, Cursor};

    #[test]
    fn secret_entry_size() {
        assert_eq!(::std::mem::size_of::<SecretEntry>(), SECRET_ENTRY_SIZE);
    }
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
