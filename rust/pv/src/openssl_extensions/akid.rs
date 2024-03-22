// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

use std::fmt;

use foreign_types::{foreign_type, ForeignType, ForeignTypeRef};
use openssl::x509::{X509CrlRef, X509Ref};
use std::ffi::c_int;

mod ffi {
    extern "C" {
        pub fn X509_check_akid(
            issuer: *const openssl_sys::X509,
            akid: *const openssl_sys::AUTHORITY_KEYID,
        ) -> super::c_int;
    }
}

foreign_type! {
    type CType = openssl_sys::AUTHORITY_KEYID;
    fn drop = openssl_sys::AUTHORITY_KEYID_free;

    /// An `Authority Key Identifier`.
    pub struct Akid;
    /// Reference to `Akid`
    pub struct AkidRef;
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct AkidCheckResult(c_int);

impl fmt::Debug for AkidCheckResult {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("AkidCheckResult")
            .field("code", &self.0)
            .finish()
    }
}

impl AkidCheckResult {
    pub const OK: AkidCheckResult = AkidCheckResult(openssl_sys::X509_V_OK);

    /// Creates an `AkidCheckResult` from a raw error number.
    unsafe fn from_raw(err: c_int) -> AkidCheckResult {
        AkidCheckResult(err)
    }
}

impl AkidRef {
    /// Check if the `Akid` matches the issuer
    pub fn check(&self, issuer: &X509Ref) -> AkidCheckResult {
        unsafe {
            let res = ffi::X509_check_akid(issuer.as_ptr(), self.as_ptr());
            AkidCheckResult::from_raw(res)
        }
    }
}

pub trait AkidExtension {
    fn akid(&self) -> Option<Akid>;
}

impl AkidExtension for X509Ref {
    fn akid(&self) -> Option<Akid> {
        unsafe {
            let ptr = openssl_sys::X509_get_ext_d2i(
                self.as_ptr(),
                openssl_sys::NID_authority_key_identifier,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            if ptr.is_null() {
                None
            } else {
                Some(Akid::from_ptr(ptr as *mut _))
            }
        }
    }
}

impl AkidExtension for X509CrlRef {
    fn akid(&self) -> Option<Akid> {
        unsafe {
            let ptr = openssl_sys::X509_CRL_get_ext_d2i(
                self.as_ptr(),
                openssl_sys::NID_authority_key_identifier,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            if ptr.is_null() {
                None
            } else {
                Some(Akid::from_ptr(ptr as *mut _))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::test_utils::load_gen_cert;

    use super::*;

    #[test]
    fn akid() {
        let cert = load_gen_cert("ibm.crt");
        let ca = load_gen_cert("root_ca.crt");

        let akid = cert.akid().unwrap();
        let res = akid.check(&ca);
        assert_eq!(res, AkidCheckResult::OK);
    }
}
