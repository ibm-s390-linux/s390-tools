// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023
use crate::{Error, Result};
use openssl::{
    error::ErrorStack,
    x509::{X509Crl, X509},
};

/// Read all CRLs from the buffer and parse them into a vector.
///
/// # Errors
///
/// This function will return an error if the underlying OpenSSL implementation cannot parse `buf`
/// as `DER` or `PEM`.
pub fn read_crls<T: AsRef<[u8]>>(buf: T) -> Result<Vec<X509Crl>> {
    use crate::openssl_extensions::StackableX509Crl;
    X509Crl::from_der(buf.as_ref())
        .map(|crl| vec![crl])
        .or_else(|_| StackableX509Crl::stack_from_pem(buf.as_ref()))
        .map_err(Error::Crypto)
}

/// Read all certificates from the buffer and parse them into a vector.
///
/// # Errors
///
/// This function will return an error if the underlying OpenSSL implementation cannot parse `buf`
pub fn read_certs<T: AsRef<[u8]>>(buf: T) -> Result<Vec<X509>, ErrorStack> {
    X509::from_der(buf.as_ref())
        .map(|crt| vec![crt])
        .or_else(|_| X509::stack_from_pem(buf.as_ref()))
}

#[cfg(test)]
mod tests {
    use crate::test_utils::*;

    #[test]
    fn read_crls() {
        let crl = get_cert_asset("ibm.crl");
        let crl_der = get_cert_asset("der.crl");
        let fail = get_cert_asset("ibm.crt");
        assert_eq!(super::read_crls(crl).unwrap().len(), 1);
        assert_eq!(super::read_crls(crl_der).unwrap().len(), 1);
        assert_eq!(super::read_crls(fail).unwrap().len(), 0);
    }

    #[test]
    fn read_certs() {
        let crt = get_cert_asset("ibm.crt");
        let crt_der = get_cert_asset("der.crt");
        let fail = get_cert_asset("ibm.crl");
        assert_eq!(super::read_certs(crt).unwrap().len(), 1);
        assert_eq!(super::read_certs(crt_der).unwrap().len(), 1);
        assert_eq!(super::read_certs(fail).unwrap().len(), 0);
    }
}
