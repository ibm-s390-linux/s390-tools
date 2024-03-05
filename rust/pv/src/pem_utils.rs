// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use crate::Result;
use crate::{openssl_extensions::BioMem, Error};
use openssl::error::ErrorStack;
use pv_core::request::Confidential;
use std::{
    ffi::{c_char, CString},
    fmt::Display,
};

mod ffi {
    use openssl_sys::BIO;
    use std::ffi::{c_char, c_int, c_long, c_uchar};
    extern "C" {
        pub fn PEM_write_bio(
            bio: *mut BIO,
            name: *const c_char,
            header: *const c_char,
            data: *const c_uchar,
            len: c_long,
        ) -> c_int;
    }
}

/// Thin wrapper around [`CString`] only containing ASCII chars.
#[derive(Debug)]
struct AsciiCString(CString);

impl AsciiCString {
    /// Convert from string
    ///
    /// # Returns
    /// Error if string is not ASCII or contains null chars
    pub(crate) fn from_str(s: &str) -> Result<Self> {
        match s.is_ascii() {
            true => Ok(Self(CString::new(s).map_err(|_| Error::NonAscii)?)),
            false => Err(Error::NonAscii),
        }
    }

    fn as_ptr(&self) -> *const c_char {
        self.0.as_ptr()
    }
}

/// Helper struct to construct the PEM format
#[derive(Debug)]
struct InnerPem<'d> {
    name: AsciiCString,
    header: Option<AsciiCString>,
    data: &'d [u8],
}

impl<'d> InnerPem<'d> {
    fn new(name: &str, header: Option<String>, data: &'d [u8]) -> Result<Self> {
        Ok(Self {
            name: AsciiCString::from_str(name)?,
            header: match header {
                Some(h) => Some(AsciiCString::from_str(&h)?),
                None => None,
            },
            data,
        })
    }

    /// Generate PEM representation of the data
    fn to_pem(&self) -> Result<Vec<u8>> {
        let bio = BioMem::new()?;
        let hdr_ptr = match self.header {
            // avoid moving variable -> use reference
            Some(ref h) => h.as_ptr(),
            None => std::ptr::null(),
        };

        // SAFETY:
        // All pointers point to valid C strings or memory regions
        let rc = unsafe {
            ffi::PEM_write_bio(
                bio.as_ptr(),
                self.name.as_ptr(),
                hdr_ptr,
                self.data.as_ptr(),
                self.data.len() as std::ffi::c_long,
            )
        };

        match rc {
            1 => Err(Error::InternalSsl("Could not write PEM", ErrorStack::get())),
            _ => Ok(bio.to_vec()),
        }
    }
}

/// Data in PEM format
///
/// Displays into a printable PEM structure.
/// Must be constructed from another structure in this library.
///
/// ```rust,ignore
/// let pem: Pem = ...;
/// println!("PEM {pem}");
/// ```
/// ```PEM
///-----BEGIN <name>-----
///<header>
///
///<Base64 formatted binary data>
///-----END <name>-----

#[derive(Debug)]
pub struct Pem {
    pem: Confidential<String>,
}

#[allow(unused)]
impl Pem {
    /// Create a new PEM structure.
    ///
    /// # Errors
    ///
    /// This function will return an error if name or header contain non-ASCII chars, or OpenSSL
    /// could not generate the PEM (very likely due to OOM).
    pub(crate) fn new<D, H>(name: &str, header: H, data: D) -> Result<Self>
    where
        D: AsRef<[u8]>,
        H: Into<Option<String>>,
    {
        let mut header = header.into();
        let header = match header {
            Some(h) if h.ends_with('\n') => Some(h),
            Some(h) if h.is_empty() => None,
            Some(mut h) => {
                h.push('\n');
                Some(h)
            }
            None => None,
        };

        let inner_pem = InnerPem::new(name, header, data.as_ref())?;

        // Create the PEM format eagerly so that to_string/display cannot fail because of ASCII or OpenSSL Errors
        // Both error should be very unlikely
        // OpenSSL should be able to create PEM if there is enough memory and produce a non-null
        // terminated ASCII-string
        // Unwrap succeeds it's all ASCII
        // Std lib implements all the conversations without a copy
        let pem = CString::new(inner_pem.to_pem()?)
            .map_err(|_| Error::NonAscii)?
            .into_string()
            .unwrap()
            .into();

        Ok(Self { pem })
    }

    /// Converts the PEM-data into a byte vector.
    ///
    /// This consumes the `PEM`.
    #[inline]
    #[must_use = "`self` will be dropped if the result is not used"]
    pub fn into_bytes(self) -> Confidential<Vec<u8>> {
        self.pem.into_inner().into_bytes().into()
    }
}

impl Display for Pem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.pem.value().fmt(f)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn no_data() {
        const EXP: &str =
            "-----BEGIN PEM test-----\ntest hdr value: 17\n\n-----END PEM test-----\n";
        let test_pem = Pem::new("PEM test", "test hdr value: 17".to_string(), []).unwrap();
        let pem_str = test_pem.to_string();
        assert_eq!(pem_str, EXP);
    }

    #[test]
    fn no_hdr() {
        const EXP: &str =
            "-----BEGIN PEM test-----\ndmVyeSBzZWNyZXQga2V5\n-----END PEM test-----\n";
        let test_pem = Pem::new("PEM test", None, "very secret key").unwrap();
        let pem_str = test_pem.to_string();
        assert_eq!(pem_str, EXP);
    }

    #[test]
    fn some_data() {
        const EXP: &str= "-----BEGIN PEM test-----\ntest hdr value: 17\n\ndmVyeSBzZWNyZXQga2V5\n-----END PEM test-----\n";
        let test_pem = Pem::new(
            "PEM test",
            "test hdr value: 17".to_string(),
            "very secret key",
        )
        .unwrap();
        let pem_str = test_pem.to_string();
        assert_eq!(pem_str, EXP);
    }

    #[test]
    fn data_linebreak() {
        const EXP: &str= "-----BEGIN PEM test-----\ntest hdr value: 17\n\ndmVyeSBzZWNyZXQga2V5\n-----END PEM test-----\n";
        let test_pem = Pem::new(
            "PEM test",
            "test hdr value: 17\n".to_string(),
            "very secret key",
        )
        .unwrap();
        let pem_str = test_pem.to_string();
        assert_eq!(pem_str, EXP);
    }
}
