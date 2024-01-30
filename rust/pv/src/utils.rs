// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023
use crate::{Error, Result};
use openssl::{
    pkey::{PKey, Private},
    x509::{X509Crl, X509},
};

/// Read all CRLs from the buffer and parse them into a vector.
///
/// # Errors
///
/// This function will return an error if the underlying OpenSSL implementation cannot parse `buf`
/// as `DER` or `PEM`.
pub fn read_crls(buf: &[u8]) -> Result<Vec<X509Crl>> {
    use openssl_extensions::crl::StackableX509Crl;
    X509Crl::from_der(buf)
        .map(|crl| vec![crl])
        .or_else(|_| StackableX509Crl::stack_from_pem(buf))
        .map_err(Error::Crypto)
}

/// Read all certificates from the buffer and parse them into a vector.
///
/// # Errors
///
/// This function will return an error if the underlying OpenSSL implementation cannot parse `buf`

pub fn read_certs(buf: &[u8]) -> Result<Vec<X509>> {
    X509::from_der(buf)
        .map(|crt| vec![crt])
        .or_else(|_| X509::stack_from_pem(buf))
        .map_err(Error::Crypto)
}

/// Read+parse the first key from the buffer.
///
/// # Errors
///
/// This function will return an error if the underlying OpenSSL implementation cannot parse `buf`
/// as `DER` or `PEM`.
pub fn read_private_key(buf: &[u8]) -> Result<PKey<Private>> {
    PKey::private_key_from_der(buf)
        .or_else(|_| PKey::private_key_from_pem(buf))
        .map_err(Error::Crypto)
}

#[cfg(test)]
mod tests {
    use crate::{get_test_asset, test_utils::*};

    #[test]
    fn read_crls() {
        let crl = get_cert_asset("ibm.crl");
        let crl_der = get_cert_asset("der.crl");
        let fail = get_cert_asset("ibm.crt");
        assert_eq!(super::read_crls(&crl).unwrap().len(), 1);
        assert_eq!(super::read_crls(&crl_der).unwrap().len(), 1);
        assert_eq!(super::read_crls(&fail).unwrap().len(), 0);
    }

    #[test]
    fn read_certs() {
        let crt = get_cert_asset("ibm.crt");
        let crt_der = get_cert_asset("der.crt");
        let fail = get_cert_asset("ibm.crl");
        assert_eq!(super::read_certs(&crt).unwrap().len(), 1);
        assert_eq!(super::read_certs(&crt_der).unwrap().len(), 1);
        assert_eq!(super::read_certs(&fail).unwrap().len(), 0);
    }

    #[test]
    fn read_private_key() {
        let key = get_test_asset!("keys/rsa3072key.pem");
        let key = super::read_private_key(key).unwrap();
        assert_eq!(key.rsa().unwrap().size(), 384);
    }

    #[test]
    fn read_private_key_fail() {
        let key = get_test_asset!("exp/secure_guest.hdr");
        let key = super::read_private_key(key);
        assert!(key.is_err());
    }
}
