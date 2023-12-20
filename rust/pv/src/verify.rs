// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

use core::slice;
use log::debug;
use openssl::stack::Stack;
use openssl::x509::store::X509Store;
use openssl::x509::{CrlStatus, X509Ref, X509StoreContext, X509};
use openssl_extensions::crl::StackableX509Crl;
use openssl_extensions::crl::X509StoreContextExtension;

use crate::error::bail_hkd_verify;
use crate::misc::{read_certs, read_file};
use crate::Result;

mod helper;
mod test;

/// A HkdVerifier verifies that a host-key document(HKD) can be trusted.
///
/// If the verification fails the HKD should not be used to create requests.
pub trait HkdVerifier {
    /// Checks if the given host-key document can be trusted.
    ///
    /// #Errors
    ///
    /// This function will return an error if the Hostkey cannot be trusted.
    /// Refer to the concrete Error type for the specific reason.
    fn verify(&self, hkd: &X509Ref) -> Result<()>;
}

/// A "verifier" that does not verify and accepts all given host-keys as valid.
pub struct NoVerifyHkd;
impl HkdVerifier for NoVerifyHkd {
    fn verify(&self, _hkd: &X509Ref) -> Result<()> {
        Ok(())
    }
}

/// A Verifier that checks the host-key document against a chain of trust.
pub struct CertVerifier {
    store: X509Store,
    ibm_z_sign_key: X509,
    offline: bool,
}

impl std::fmt::Debug for CertVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CertVerifier")
    }
}

impl HkdVerifier for CertVerifier {
    /// This function verifies a host-key
    /// document. To do so multiple steps are required:
    ///
    /// 1. issuer(host_key) == subject(ibm_z_sign_key)
    /// 2. Signature verification
    /// 3. @hkd must not be expired
    /// 4. @hkd must not be revoked
    fn verify(&self, hkd: &X509Ref) -> Result<()> {
        helper::verify_hkd_options(hkd, &self.ibm_z_sign_key)?;

        // verify that the hkd was signed with the key of the IBM signing key
        if !hkd.verify(self.ibm_z_sign_key.public_key()?.as_ref())? {
            bail_hkd_verify!(Signature);
        }

        // Find matching crl for sign key in the store or download them
        let crls = self.hkd_crls(hkd)?;

        // Verify that the CLRs are still valid
        let mut verified_crls = Vec::with_capacity(crls.len());
        for crl in &crls {
            if helper::verify_crl(crl, &self.ibm_z_sign_key).is_some() {
                verified_crls.push(crl.to_owned());
            }
        }

        // Test if hkd was revoked (min1 required)
        if verified_crls.is_empty() {
            bail_hkd_verify!(NoCrl);
        }
        for crl in &verified_crls {
            match crl.get_by_cert(&hkd.to_owned()) {
                CrlStatus::NotRevoked => (),
                _ => bail_hkd_verify!(HdkRevoked),
            }
        }
        debug!("HKD: verified");
        Ok(())
    }
}

impl CertVerifier {
    ///Download the CLRs that a HKD refers to.
    pub fn hkd_crls(&self, hkd: &X509Ref) -> Result<Stack<StackableX509Crl>> {
        let mut ctx = X509StoreContext::new()?;
        // Unfortunately we cannot use a dedicated function here and have to use a closure (E0434)
        // Otherwise, we cannot refer to self
        let mut crls = ctx.init_opt(&self.store, None, None, |ctx| {
            let subject = self.ibm_z_sign_key.subject_name();
            match ctx.crls(subject) {
                Ok(crls) => Ok(crls),
                _ => {
                    // reorder the name and try again
                    let broken_subj = helper::reorder_x509_names(subject)?;
                    ctx.crls(&broken_subj).or_else(helper::stack_err_hlp)
                }
            }
        })?;

        if !self.offline {
            // Try to download a CRL if defined in the HKD
            if let Some(crl) = helper::download_first_crl_from_x509(hkd)? {
                crl.into_iter().try_for_each(|c| crls.push(c.into()))?;
            }
        }
        Ok(crls)
    }
}

impl CertVerifier {
    /// Create a `CertVerifier`.
    ///
    /// * `cert_paths` - Paths to Cerificates for the chain of trust
    /// * `crl_paths` - Paths to certificate revocation lists for the chain of trust
    /// * `root_ca_path` - Path to the root of trust
    /// * `offline` - if set to true the verification process will not try to download CRLs from the
    /// internet.
    /// # Errors
    ///
    /// This function will return an error if the chain of trust could not be established.
    pub fn new(
        cert_paths: &[String],
        crl_paths: &[String],
        root_ca_path: &Option<String>,
        offline: bool,
    ) -> Result<Self> {
        let mut store = helper::store_setup(root_ca_path, crl_paths, cert_paths)?;
        let mut untr_certs = Vec::with_capacity(cert_paths.len());
        for path in cert_paths {
            let mut crt = read_certs(&read_file(path, "certificate")?)?;
            if !offline {
                helper::download_crls_into_store(&mut store, &crt)?;
            }
            untr_certs.append(&mut crt);
        }

        // remove the IBM signing certificate from chain.
        // We have to verify them separately as they are not marked as intermediate certs
        let (ibm_z_sign_key, chain) = helper::extract_ibm_sign_key(untr_certs)?;

        let store = store.build();
        helper::verify_chain(&store, &chain, slice::from_ref(&ibm_z_sign_key))?;

        Ok(Self {
            store,
            ibm_z_sign_key,
            offline,
        })
    }
}
