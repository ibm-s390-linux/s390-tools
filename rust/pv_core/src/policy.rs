// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp.

use crate::misc::encode_hex;
use crate::utils::open_file;
use crate::{Error, Result};
use std::{
    fmt::{Display, Formatter, Result as Resfmt},
    fs::File,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    str::from_utf8,
};
use zerocopy::{FromBytes, Immutable, IntoBytes};

const HASH_LEN: usize = 32;
// UserDataType::Unsigned.max() returns 512
const USER_DATA_MAX_SIZE: usize = 512;

/// A reference to a policy file containing its SHA-256 hash and file path.
///
/// This structure is used in Early Boot Customization (EBC) to store
/// a reference to a policy file. It contains the SHA-256 hash of the policy
/// file content and the file path as a fixed-size byte array.
///
/// The total size is constrained by `USER_DATA_MAX_SIZE` (512 bytes), with
/// 32 bytes allocated for the hash and the remaining bytes for the file path.
#[derive(Debug, FromBytes, IntoBytes, Immutable, Copy, Clone)]
#[repr(C)]
pub struct PolicyReference {
    /// SHA-256 hash of the policy file content (32 bytes)
    pub hash: [u8; HASH_LEN],
    /// File path stored as a null-terminated byte array
    pub name: [u8; USER_DATA_MAX_SIZE - HASH_LEN],
}

impl PolicyReference {
    /// Creates a new `PolicyReference` from a file path.
    ///
    /// Opens the file, reads its content, and computes the SHA-256 hash.
    ///
    /// # Parameters
    ///
    /// * `src` - The path to the policy file
    /// * `sha256` - A function that computes the SHA-256 hash of the content
    ///
    /// # Returns
    ///
    /// Returns a `PolicyReference` containing the SHA-256 hash and the file path,
    /// or an error if the file cannot be opened or the hash computation fails.
    ///
    /// # Note
    ///
    /// The file path is truncated if it exceeds the available space in the `name` field.
    pub fn new<P, H>(src: P, sha256: H) -> Result<Self>
    where
        P: AsRef<Path>,
        H: Fn(File) -> Result<Vec<u8>>,
    {
        let mut ret = Self {
            hash: [0; HASH_LEN],
            name: [0; USER_DATA_MAX_SIZE - HASH_LEN],
        };

        let file = open_file(src.as_ref())?;
        ret.hash.copy_from_slice(sha256(file)?.as_bytes());
        let strbytes = src.as_ref().as_os_str().as_bytes();
        let nbytes = strbytes.len().min(ret.name.len());
        ret.name[..nbytes].copy_from_slice(&strbytes[..nbytes]);

        Ok(ret)
    }

    /// Converts the stored file path back to a `PathBuf`.
    ///
    /// # Returns
    ///
    /// Returns the file path as a `PathBuf`, or an error if the stored name
    /// is not valid UTF-8.
    ///
    /// # Errors
    ///
    /// * `Error::ParseError` - If the name contains invalid UTF-8
    pub fn to_path(&self) -> Result<PathBuf> {
        // Extract bytes until the first null byte (null-terminated string)
        let name_bytes: Vec<u8> = self
            .name
            .iter()
            .copied()
            .take_while(|&byte| byte != 0)
            .collect();

        let rust_string = String::from_utf8(name_bytes).map_err(|e| Error::ParseError {
            subject: "PolicyReference name".to_string(),
            content: format!("Invalid UTF-8 in name: {}", e),
        })?;

        Ok(Path::new(&rust_string).to_owned())
    }
}

impl Display for PolicyReference {
    fn fmt(&self, f: &mut Formatter) -> Resfmt {
        write!(
            f,
            "{} {}",
            encode_hex(self.hash),
            from_utf8(&self.name).expect("unable to convert name")
        )
    }
}
