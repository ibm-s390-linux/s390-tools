// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

use crate::openssl_extensions::{StackableX509Crl, X509StoreContextExtension, X509StoreExtension};
use core::slice;
use log::{debug, trace};
use openssl::error::ErrorStack;
use openssl::stack::Stack;
use openssl::x509::store::X509Store;
use openssl::x509::{CrlStatus, X509NameRef, X509Ref, X509StoreContext, X509StoreContextRef, X509};
use std::path::Path;

#[cfg(not(test))]
use helper::download_first_crl_from_x509;
#[cfg(test)]
use test::download_first_crl_from_x509;

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
    /// # Errors
    ///
    /// This function will return an error if the host-key document cannot be
    /// trusted. Refer to the concrete Error type for the specific reason.
    fn verify(&self, hkd: &X509Ref) -> Result<()>;
}

/// A verifier that does not verify and accepts all given host-keys as valid.
#[derive(Debug)]
pub struct NoVerifyHkd;
impl HkdVerifier for NoVerifyHkd {
    fn verify(&self, _hkd: &X509Ref) -> Result<()> {
        Ok(())
    }
}

/// A verifier that checks the host-key document against a chain of trust.
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

        // verify that the HKD was signed with the key of the IBM signing key
        if !hkd.verify(self.ibm_z_sign_key.public_key()?.as_ref())? {
            bail_hkd_verify!(Signature);
        }

        // Find matching CRL for sign key in the store or download them
        let crls = self.hkd_crls(hkd)?;

        // Verify that the CRLs are still valid
        let mut verified_crls = Vec::with_capacity(crls.len());
        for crl in &crls {
            if helper::verify_crl(crl, &self.ibm_z_sign_key).is_some() {
                verified_crls.push(crl.to_owned());
            }
        }

        // Test if HKD was revoked (min1 required)
        if verified_crls.is_empty() {
            bail_hkd_verify!(NoCrl);
        }
        for crl in verified_crls {
            match crl.get_by_serial(hkd.serial_number()) {
                CrlStatus::NotRevoked => (),
                _ => bail_hkd_verify!(HkdRevoked),
            }
        }
        debug!("HKD: verified");
        Ok(())
    }
}

impl CertVerifier {
    fn quirk_crls(
        ctx: &mut X509StoreContextRef,
        subject: &X509NameRef,
    ) -> Result<Stack<StackableX509Crl>, ErrorStack> {
        match ctx.crls(subject) {
            Ok(ret) if !ret.is_empty() => return Ok(ret),
            _ => (),
        }

        // Armonk/Poughkeepsie fixup
        trace!("quirk_crls: Try Locality");
        if let Some(locality_subject) = helper::armonk_locality_fixup(subject) {
            match ctx.crls(&locality_subject) {
                Ok(ret) if !ret.is_empty() => return Ok(ret),
                _ => (),
            }

            // reorder
            trace!("quirk_crls: Try Locality+Reorder");
            if let Ok(locality_ordered_subject) = helper::reorder_x509_names(&locality_subject) {
                match ctx.crls(&locality_ordered_subject) {
                    Ok(ret) if !ret.is_empty() => return Ok(ret),
                    _ => (),
                }
            }
        }

        // reorder unchanged locality subject
        trace!("quirk_crls: Try Reorder");
        if let Ok(ordered_subject) = helper::reorder_x509_names(subject) {
            match ctx.crls(&ordered_subject) {
                Ok(ret) if !ret.is_empty() => return Ok(ret),
                _ => (),
            }
        }
        // nothing found, return empty stack
        Stack::new()
    }

    /// Download the CRLs that a HKD refers to.
    pub fn hkd_crls(&self, hkd: &X509Ref) -> Result<Stack<StackableX509Crl>> {
        let mut ctx = X509StoreContext::new()?;
        // Unfortunately we cannot use a dedicated function here and have to use a closure (E0434)
        // Otherwise, we cannot refer to self
        // Search for local CRLs
        let mut crls = ctx.init_opt(&self.store, None, None, |ctx| {
            let subject = self.ibm_z_sign_key.subject_name();
            Self::quirk_crls(ctx, subject)
        })?;

        if !self.offline {
            // Try to download a CRL if defined in the HKD
            if let Some(crl) = download_first_crl_from_x509(hkd)? {
                crl.into_iter().try_for_each(|c| crls.push(c.into()))?;
            }
        }
        Ok(crls)
    }
}

impl CertVerifier {
    /// Create a `CertVerifier`.
    ///
    /// * `cert_paths` - Paths to certificates for the chain of trust
    /// * `crl_paths` - Paths to certificate revocation lists for the chain of trust
    /// * `root_ca_path` - Path to the root of trust
    /// * `offline` - if set to true the verification process will not try to download CRLs from the
    /// internet.
    ///
    /// # Errors
    ///
    /// This function will return an error if the chain of trust could not be established.
    pub fn new<P, Q, R>(
        cert_paths: &[P],
        crl_paths: &[Q],
        root_ca_path: Option<R>,
        offline: bool,
    ) -> Result<Self>
    where
        P: AsRef<Path>,
        Q: AsRef<Path>,
        R: AsRef<Path>,
    {
        let mut store = helper::store_setup(root_ca_path, crl_paths, cert_paths)?;
        let mut untr_certs = Vec::with_capacity(cert_paths.len());
        for path in cert_paths {
            let mut crt = read_certs(&read_file(path, "certificate")?)?;
            if !offline {
                for c in &crt {
                    if let Some(crl) = download_first_crl_from_x509(c)? {
                        crl.iter().try_for_each(|c| store.add_crl(c))?;
                    }
                }
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
