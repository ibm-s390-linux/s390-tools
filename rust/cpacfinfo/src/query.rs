// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use std::fs::File;
use std::io::Error;
use std::io::Read;
use std::io::Result as ioRes;
use std::ops::Index;
use std::result::Result;

use zerocopy::FromBytes;
use zerocopy::FromZeroes;

use crate::msa::InstructionKind;
use crate::msa::QueryAuthInfo;

/// Path to sysfs in which the query and qai informations are fetched from
const SYSFS_PATH: &str = "/sys/devices/system/cpu/cpacf/";

/// Every Instruction has a Query function to get information about what functions are available
pub const QUERY_FUNCTION_CODE: u8 = 0;

/// Number of bytes returned by this Query
pub const QUERY_PARAM_SIZE_IN_BYTES: usize = 16;

/// Starting with MSA 13 every Instruction has a Query Authentication Information function to get
/// information about the running firmware
pub const QAI_FUNCTION_CODE: u8 = 127;

/// Number of bytes returned by this Query Authentication Information
pub const QAI_PARAM_SIZE_IN_BYTES: usize = 256;

/// Query authentication information format identifier
const FORMAT_0: u8 = 0;

#[derive(FromBytes, FromZeroes)]
#[repr(C)]
struct QaiFmt0 {
    res00: [u8; 6],
    hash_length: u16,
    res08: [u8; 4],
    version: u32,
    hash: [u8; 64],
}

#[allow(clippy::large_enum_variant)]
pub enum Param {
    QueryParam([u8; QUERY_PARAM_SIZE_IN_BYTES]),
    QaiParam([u8; QAI_PARAM_SIZE_IN_BYTES]),
}

impl Index<u8> for Param {
    type Output = u8;

    fn index(&self, index: u8) -> &Self::Output {
        match self {
            Self::QueryParam(p) => &p[index as usize],
            Self::QaiParam(p) => &p[index as usize],
        }
    }
}

impl Param {
    pub fn len(&self) -> usize {
        match self {
            Self::QueryParam(_) => QUERY_PARAM_SIZE_IN_BYTES,
            Self::QaiParam(_) => QAI_PARAM_SIZE_IN_BYTES,
        }
    }

    /// check if a specific bit is 1 in param
    pub fn check_bit_in_param(&self, check_bit: usize) -> bool {
        // get correct byte of param
        let byte = check_bit / 8;

        // get correct byte of param
        if byte >= self.len() {
            return false;
        }

        // get correct bit of param
        let bit = 8 - ((check_bit % 8) + 1);

        // return if specified bit is set
        match self {
            Self::QueryParam(param) => (param[byte] & (1 << bit)) > 0,
            Self::QaiParam(param) => (param[byte] & (1 << bit)) > 0,
        }
    }

    /// set given bit in param to 0
    pub fn unset_bit_in_param(&mut self, flip_bit: u8) {
        // get correct byte of param
        let byte = flip_bit / 8;
        if byte as usize >= self.len() {
            return;
        }

        // get correct bit of param
        let bit = 8 - ((flip_bit % 8) + 1);

        // build template to logically AND against param byte
        // i.e. (flip_bit = 0) template = 1000 0000
        let mut template: u8 = 1 << bit;
        // flip all bits in template
        // i.e. (flip_bit = 0) template = 0111 1111
        template = !template;

        // set bit to 0 while not changing any other bit
        // i.e. (flip_bit = 0) 0111 1111 & xxxx xxxx = 0xxx xxxx
        match self {
            Self::QueryParam(c) => c[byte as usize] &= template,
            Self::QaiParam(c) => c[byte as usize] &= template,
        }
    }

    /// set all bytes of self to value
    #[cfg(test)]
    pub fn set_param_to(&mut self, value: u8) {
        match self {
            Self::QueryParam(ref mut content) => *content = [value; QUERY_PARAM_SIZE_IN_BYTES],
            Self::QaiParam(ref mut content) => *content = [value; QAI_PARAM_SIZE_IN_BYTES],
        }
    }

    // Outsourced for potential future formats to be easily added in this match statement
    pub fn parse_qai_based_on_format(
        &self,
        qai: &mut QueryAuthInfo,
    ) -> Result<bool, anyhow::Error> {
        match self {
            Self::QueryParam(_) => panic!("programming error"),
            Self::QaiParam(bin) => {
                // The third byte of the param block specifies which format to use to parse the rest
                qai.format = bin[3];

                // for new formats add a match case here along with a parsing function
                match qai.format {
                    FORMAT_0 => {
                        parse_qai_format_0(qai, bin);
                        Ok(true)
                    }
                    _ => Ok(false),
                }
            }
        }
    }
}

// check if SYSFS_PATH exists
pub fn check_sysfs() -> bool {
    match std::path::Path::new(SYSFS_PATH).exists() {
        true => true,
        false => {
            println!("Warning: There seems to be an insufficient kernel level running (sysfs interface {SYSFS_PATH} is missing)\nNo information can be fetched from sysfs, application exits early.");
            false
        }
    }
}

/// parsing the information supplied by sysfs into QueryAuthInfo struct
///
/// The following box shows the qai block with named fields each with a length in bytes.
/// The length of field IFCL Hash depends on IFCL Hash Length and is either 32 or 64 bytes long.
/// In case of a 32 bytes length the latter 32 bytes of the 64 bytes Hash are filled with zeros.
///
///     | BYTE          | BYTE          | BYTE          | BYTE          |
///     -----------------------------------------------------------------
///     | RESERVED (3)                                    FORMAT (1)    |
///     | RESERVED (2)                    IFCL HASH LENGTH (2)          |
///     | RESERVED (4)                                                  |
///     | IFCL VERSION (4)                                              |
///     | IFCL HASH (32 / 64)                                           |
///     | RESERVED (176)                                                |
///     -----------------------------------------------------------------
fn parse_qai_format_0(qai: &mut QueryAuthInfo, param: &[u8]) {
    // parse param to temporary struct to ease further conversion
    let tmp = QaiFmt0::read_from_prefix(param).expect("programming error");

    // parse from temporary struct
    qai.hash_len = tmp.hash_length;
    qai.version = tmp.version;

    // depending on the parsed hash length the hash is parsed
    qai.hash = vec![0; qai.hash_len as usize];
    qai.hash
        .as_mut_slice()
        .copy_from_slice(&tmp.hash[..qai.hash_len as usize]);
}

/// cpacfinfo does not execute the actual instruction with function code but uses information
/// provided by the sysfs
pub fn query(ins: &InstructionKind, fc: u8) -> Result<Param, Error> {
    // query dependent file names
    let auth_info;
    let mut param;
    match fc {
        QUERY_FUNCTION_CODE => {
            auth_info = "";
            param = Param::QueryParam([0; QUERY_PARAM_SIZE_IN_BYTES]);
        }
        QAI_FUNCTION_CODE => {
            auth_info = "_auth_info";
            param = Param::QaiParam([0; QAI_PARAM_SIZE_IN_BYTES]);
        }
        _ => panic!("programming error"),
    };

    // depending on which query is performed the bytes to be read from sysfs vary
    let bytes_to_be_read = param.len();

    // build filepath
    let filepath = format!(
        "{SYSFS_PATH}{}_query{auth_info}_raw",
        ins.to_string().to_lowercase()
    );

    // open file
    let mut f = match File::open(filepath) {
        ioRes::Ok(file) => file,
        Err(e) => return Err(e),
    };

    // read file
    let res = match param {
        Param::QueryParam(ref mut c) => read_file_to_buf(&mut f, c),
        Param::QaiParam(ref mut c) => read_file_to_buf(&mut f, c),
    };

    let bytes_read = match res {
        Ok(b) => b,
        Err(e) => return Err(e),
    };

    match bytes_read == bytes_to_be_read {
        true => Ok(param),
        false => Err(Error::new(std::io::ErrorKind::UnexpectedEof, "test")),
    }
}

fn read_file_to_buf(file: &mut File, buf: &mut [u8]) -> Result<usize, Error> {
    file.read(buf)
    /* match file.read(buf) {
        Result::Ok(bytes_read) => Ok(bytes_read),
        Err(e) => Err(e),
    } */
}

#[cfg(test)]
#[test]
fn test_param_funcs() {
    // initialize param with all ones
    let mut param = Param::QueryParam([0; QUERY_PARAM_SIZE_IN_BYTES]);
    const NUMBER_OF_BITS: usize = 8 * QUERY_PARAM_SIZE_IN_BYTES;

    for i in 0..NUMBER_OF_BITS {
        // reset param to all ones
        param.set_param_to(0xFF);
        assert!(param.check_bit_in_param(i));

        // set one bit to zero
        param.unset_bit_in_param(i as u8);

        // check if that bit is zero
        assert!(!param.check_bit_in_param(i));
    }
}
