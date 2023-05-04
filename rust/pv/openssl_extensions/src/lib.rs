// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

#![doc(hidden)]

/// Extensions to the rust-openssl crate, that are not upstream yet
/// Upstreaming mostly work in progress
pub mod akid;
pub mod crl;
mod stackable_crl;

/// Test if two CRLs are equal.
///
/// relates to X509_CRL_match
/// (Upstream is missing that functionality)
pub fn x509_crl_eq(a: &openssl::x509::X509CrlRef, b: &openssl::x509::X509CrlRef) -> bool {
    use foreign_types::ForeignTypeRef;
    let cmp = unsafe { openssl_sys::X509_CRL_match(a.as_ptr(), b.as_ptr()) };
    cmp == 0
}

#[allow(dead_code)]
mod test_utils {
    include!("../../src/test_utils.rs");
}
