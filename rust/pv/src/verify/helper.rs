// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

use crate::error::bail_hkd_verify;
use crate::openssl_extensions::{AkidCheckResult, AkidExtension};
use crate::HkdVerifyErrorType::*;
use crate::{Error, Result};
use log::debug;
use openssl::{
    asn1::{Asn1Time, Asn1TimeRef},
    error::ErrorStack,
    nid::Nid,
    ssl::SslFiletype,
    stack::Stack,
    x509::{
        store::{File, X509Lookup, X509StoreBuilder, X509StoreRef},
        verify::{X509VerifyFlags, X509VerifyParam},
        X509CrlRef, X509Name, X509NameRef, X509PurposeId, X509Ref, X509StoreContext,
        X509StoreContextRef, X509VerifyResult, X509,
    },
};
use std::path::Path;
use std::str::from_utf8;
use std::{cmp::Ordering, ffi::c_int};

/// Minimum security level for the keys/certificates used to establish a chain of
/// trust (see https://www.openssl.org/docs/man1.1.1/man3/X509_VERIFY_PARAM_set_auth_level.html
/// for details).
const SECURITY_LEVEL: usize = 2;
const SECURITY_BITS_ARRAY: [u32; 6] = [0, 80, 112, 128, 192, 256];
const SECURITY_BITS: u32 = SECURITY_BITS_ARRAY[SECURITY_LEVEL];
const SECURITY_CHAIN_MAX_LEN: c_int = 2;

/// Verifies that the HKD
/// * has enough security bits
/// * is inside its validity period
/// * the Authority Key ID matches the Signing Key ID of the  [`sign_key`]
pub fn verify_hkd_options(hkd: &X509Ref, sign_key: &X509Ref) -> Result<()> {
    let hk_pkey = hkd.public_key()?;
    let security_bits = hk_pkey.security_bits();

    if SECURITY_BITS > 0 && SECURITY_BITS > security_bits {
        return Err(Error::HkdVerify(SecurityBits(security_bits, SECURITY_BITS)));
    }
    // TODO rust-openssl fix X509::not.after/before() impl to return Option& not panic on nullptr
    // from C? try_... rust-openssl
    // verify that the HKD is still valid
    check_validity_period(hkd.not_before(), hkd.not_after())?;

    // verify that the AKID of the hkd matches the SKID of the issuer
    if let Some(akid) = hkd.akid() {
        if akid.check(sign_key) != AkidCheckResult::OK {
            bail_hkd_verify!(Akid);
        }
    }
    Ok(())
}

pub fn verify_crl(crl: &X509CrlRef, issuer: &X509Ref) -> Option<()> {
    let last = crl.last_update();
    let next = crl.next_update()?;

    check_validity_period(last, next).ok()?;
    if let Some(akid) = crl.akid() {
        if akid.check(issuer) != AkidCheckResult::OK {
            return None;
        }
    }
    match crl.verify(issuer.public_key().ok()?.as_ref()).ok()? {
        true => Some(()),
        false => None,
    }
}

/// Setup the x509Store such that it can be used it for verifying certificates
pub fn store_setup<P: AsRef<Path>, Q: AsRef<Path>, R: AsRef<Path>>(
    root_ca_path: Option<P>,
    crl_paths: &[Q],
    cert_w_crl_paths: &[R],
) -> Result<X509StoreBuilder> {
    let mut x509store = X509StoreBuilder::new()?;

    match root_ca_path {
        None => x509store.set_default_paths()?,
        Some(p) => load_root_ca(p, &mut x509store)?,
    }

    for crl in crl_paths {
        load_crl_to_store(&mut x509store, crl, true).map_err(|source| Error::X509Load {
            path: crl.as_ref().into(),
            ty: Error::CRL,
            source,
        })?;
    }

    for crl in cert_w_crl_paths {
        load_crl_to_store(&mut x509store, crl, false).map_err(|source| Error::X509Load {
            path: crl.as_ref().into(),
            ty: Error::CRL,
            source,
        })?;
    }
    let mut param = X509VerifyParam::new()?;
    let flags = X509VerifyFlags::X509_STRICT
        | X509VerifyFlags::CRL_CHECK
        | X509VerifyFlags::CRL_CHECK_ALL
        | X509VerifyFlags::TRUSTED_FIRST
        | X509VerifyFlags::CHECK_SS_SIGNATURE
        | X509VerifyFlags::POLICY_CHECK;

    param.set_depth(SECURITY_CHAIN_MAX_LEN);
    param.set_auth_level(SECURITY_LEVEL as i32);
    param.set_purpose(X509PurposeId::ANY)?;
    param.set_flags(flags)?;
    x509store.set_param(&param)?;

    Ok(x509store)
}

/// Verify that the given IBM signing keys can be trusted
/// -> check the chain: IBMsignKey<-InterCA(s)<-RootCA
pub fn verify_chain(
    store: &X509StoreRef,
    untrusted_certs: &Stack<X509>,
    sign_keys: &[X509],
) -> Result<()> {
    fn verify_fun(ctx: &mut X509StoreContextRef) -> std::result::Result<bool, ErrorStack> {
        // verify certificate
        let res = ctx.verify_cert()?;
        if !res {
            debug!("Failed to verify the singing key with the chain of trust");
            return Ok(res);
        }
        // verify that the chain is as expected
        let chain = match ctx.chain() {
            Some(c) => c,
            None => {
                debug!("No verification chain in verify-context. (openssl BUG)");
                ctx.set_error(X509VerifyResult::APPLICATION_VERIFICATION);
                return Ok(false);
            }
        };
        if chain.len() < SECURITY_CHAIN_MAX_LEN as usize {
            debug!("Verification expects one root and at least one intermediate certificate",);
            ctx.set_error(X509VerifyResult::APPLICATION_VERIFICATION);
            Ok(false)
        } else {
            Ok(true)
        }
    }

    let mut store_ctx = X509StoreContext::new()?;

    for sign_key in sign_keys {
        // (rust)OpenSSL should not error out on `X509_verify_cert`\
        // (Internal (probably unrecoverable) error like OOM)
        if !store_ctx
            .init(store, sign_key, untrusted_certs, verify_fun)
            .map_err(|e| Error::InternalSsl("The IBM Z signing key could not be verified.", e))?
        {
            return Err(Error::HkdVerify(IbmSignInvalid(
                store_ctx.error(),
                store_ctx.error_depth(),
            )));
        }
    }
    Ok(())
}

/// Consumes and splits the given vector into a single IBM Z signing key and other certificates
///
/// Error if not exactly one IBM Z signing key available
pub fn extract_ibm_sign_key(certs: Vec<X509>) -> Result<(X509, Stack<X509>)> {
    let ibm_z_sign_key = get_ibm_z_sign_key(&certs)?;

    let mut chain = Stack::<X509>::new()?;
    for x in certs.into_iter().filter(|x| !is_ibm_signing_cert(x)) {
        chain.push(x)?;
    }
    Ok((ibm_z_sign_key, chain))
}

// Name Entry values of an IBM Z key signing cert
// Asn1StringRef::as_slice aka ASN1_STRING_get0_data gives a string without \0 delimiter
const IBM_Z_COMMON_NAME: &[u8; 43usize] = b"International Business Machines Corporation";
const IBM_Z_COUNTRY_NAME: &[u8; 2usize] = b"US";
const IBM_Z_LOCALITY_NAME_POUGHKEEPSIE: &[u8; 12usize] = b"Poughkeepsie";
const IBM_Z_LOCALITY_NAME_ARMONK: &[u8; 6usize] = b"Armonk";
const IBM_Z_ORGANIZATIONAL_UNIT_NAME_SUFFIX: &str = "Key Signing Service";
const IBM_Z_ORGANIZATION_NAME: &[u8; 43usize] = b"International Business Machines Corporation";
const IBM_Z_STATE: &[u8; 8usize] = b"New York";
const IMB_Z_ENTRY_COUNT: usize = 6;
fn name_data_eq(entries: &X509NameRef, nid: Nid, rhs: &[u8]) -> bool {
    let mut it = entries.entries_by_nid(nid);
    match it.next() {
        None => false,
        Some(entry) => entry.data().as_slice() == rhs,
    }
}

fn is_ibm_signing_cert(cert: &X509) -> bool {
    let subj = cert.subject_name();

    if subj.entries().count() != IMB_Z_ENTRY_COUNT
        || !name_data_eq(subj, Nid::COUNTRYNAME, IBM_Z_COUNTRY_NAME)
        || !name_data_eq(subj, Nid::STATEORPROVINCENAME, IBM_Z_STATE)
        || !(name_data_eq(subj, Nid::LOCALITYNAME, IBM_Z_LOCALITY_NAME_POUGHKEEPSIE)
            || name_data_eq(subj, Nid::LOCALITYNAME, IBM_Z_LOCALITY_NAME_ARMONK))
        || !name_data_eq(subj, Nid::ORGANIZATIONNAME, IBM_Z_ORGANIZATION_NAME)
        || !name_data_eq(subj, Nid::COMMONNAME, IBM_Z_COMMON_NAME)
    {
        return false;
    }

    return match subj.entries_by_nid(Nid::ORGANIZATIONALUNITNAME).next() {
        None => false,
        Some(entry) => match entry.data().as_utf8() {
            Err(_) => false,
            Ok(s) => s
                .as_bytes()
                .ends_with(IBM_Z_ORGANIZATIONAL_UNIT_NAME_SUFFIX.as_bytes()),
        },
    };
}

fn get_ibm_z_sign_key(certs: &[X509]) -> Result<X509> {
    let mut ibm_sign_keys = certs.iter().filter(|x| is_ibm_signing_cert(x)).cloned();
    match ibm_sign_keys.next() {
        None => bail_hkd_verify!(NoIbmSignKey),
        Some(k) => match ibm_sign_keys.next() {
            None => Ok(k),
            Some(_) => bail_hkd_verify!(ManyIbmSignKeys),
        },
    }
}

fn load_root_ca<P: AsRef<Path>>(path: P, x509_store: &mut X509StoreBuilder) -> Result<()> {
    let lu = x509_store.add_lookup(X509Lookup::<File>::file())?;

    // Try to load cert as PEM file
    match lu.load_cert_file(&path, SslFiletype::PEM) {
        Ok(_) => lu
            .load_crl_file(&path, SslFiletype::PEM)
            .map(|_| ())
            .or(Ok(())),
        // Not a PEM file? try ASN1
        Err(_) => lu
            .load_cert_file(&path, SslFiletype::ASN1)
            .map(|_| ())
            .map_err(|source| Error::X509Load {
                path: path.as_ref().into(),
                ty: Error::CERT,
                source,
            }),
    }
}

fn load_crl_to_store<P: AsRef<Path>>(
    x509_store: &mut X509StoreBuilder,
    path: P,
    err_out_empty_crl: bool,
) -> std::result::Result<(), ErrorStack> {
    let lu = x509_store.add_lookup(X509Lookup::<File>::file())?;
    // Try to load cert as PEM file
    if lu.load_crl_file(&path, SslFiletype::PEM).is_err() {
        // Not a PEM file? try read as ASN1
        let res = lu.load_crl_file(path, SslFiletype::ASN1);
        if err_out_empty_crl {
            res?;
        }
    }
    Ok(())
}

/// Run through the forest of the distribution points and find them
pub fn x509_dist_points(cert: &X509Ref) -> Vec<String> {
    let mut res = Vec::<String>::with_capacity(1);
    let dps = match cert.crl_distribution_points() {
        Some(d) => d,
        None => return res,
    };
    for dp in dps {
        let dp_nm = match dp.distpoint() {
            Some(nm) => nm,
            None => continue,
        };
        let dp_gns = match dp_nm.fullname() {
            Some(gns) => gns,
            None => continue,
        };
        for dp_gn in dp_gns {
            match dp_gn.uri() {
                Some(uri) => res.push(uri.to_string()),
                None => continue,
            };
        }
    }
    res
}

/// Searches for CRL Distribution points and downloads the CRL. Stops after the first successful
/// download.
///
/// Error if something bad(=unexpected) happens (not bad: CRL not available at link, unexpected
/// format) Other issues are mapped to Ok(None)
#[cfg(not(test))]
pub fn download_first_crl_from_x509(cert: &X509Ref) -> Result<Option<Vec<openssl::x509::X509Crl>>> {
    use crate::utils::read_crls;
    use curl::easy::{Easy2, Handler, WriteError};
    use std::time::Duration;
    const CRL_TIMEOUT_MAX: Duration = Duration::from_secs(3);
    struct Buf(Vec<u8>);

    impl Handler for Buf {
        fn write(&mut self, data: &[u8]) -> std::result::Result<usize, WriteError> {
            self.0.extend_from_slice(data);
            Ok(data.len())
        }
    }

    for dist_point in x509_dist_points(cert) {
        // A typical certificate is about 1200 bytes long
        let mut handle = Easy2::new(Buf(Vec::with_capacity(1500)));
        handle.url(&dist_point)?;
        handle.get(true)?;
        handle.follow_location(true)?;
        handle.timeout(CRL_TIMEOUT_MAX)?;
        handle.useragent("s390-tools-pv-crl")?;

        if handle.perform().is_err() {
            continue;
        }
        match read_crls(&handle.get_ref().0) {
            Err(_) => continue,
            Ok(crl) => return Ok(Some(crl)),
        }
    }
    Ok(None)
}

fn check_validity_period(not_before: &Asn1TimeRef, not_after: &Asn1TimeRef) -> Result<()> {
    let now = Asn1Time::days_from_now(0)?;
    if let Ordering::Less = now.compare(not_before)? {
        bail_hkd_verify!(BeforeValidity);
    }
    match now.compare(not_after)? {
        Ordering::Less => Ok(()),
        _ => bail_hkd_verify!(AfterValidity),
    }
}

const NIDS_CORRECT_ORDER: [Nid; 6] = [
    Nid::COUNTRYNAME,
    Nid::ORGANIZATIONNAME,
    Nid::ORGANIZATIONALUNITNAME,
    Nid::LOCALITYNAME,
    Nid::STATEORPROVINCENAME,
    Nid::COMMONNAME,
];
/// Workaround to fix the mismatch between issuer name of the
/// IBM Z signing CRLs and the IBM Z signing key subject name.
pub fn reorder_x509_names(subject: &X509NameRef) -> std::result::Result<X509Name, ErrorStack> {
    let mut correct_subj = X509Name::builder()?;
    for nid in NIDS_CORRECT_ORDER {
        if let Some(name) = subject.entries_by_nid(nid).next() {
            correct_subj.append_entry(name)?;
        }
    }
    Ok(correct_subj.build())
}

/// Workaround for potential locality mismatches between CRLs and Certs
/// # Return
/// fixed subject or none if locality was not Armonk or any OpenSSL error
pub fn armonk_locality_fixup(subject: &X509NameRef) -> Option<X509Name> {
    if !name_data_eq(subject, Nid::LOCALITYNAME, IBM_Z_LOCALITY_NAME_ARMONK) {
        return None;
    }

    let mut ret = X509Name::builder().ok()?;
    for entry in subject.entries() {
        match entry.object().nid() {
            nid @ Nid::LOCALITYNAME => ret
                .append_entry_by_nid(nid, from_utf8(IBM_Z_LOCALITY_NAME_POUGHKEEPSIE).ok()?)
                .ok()?,
            _ => {
                ret.append_entry(entry).ok()?;
            }
        }
    }
    Some(ret.build())
}

#[cfg(test)]
/// tests for some private functions
mod test {

    use super::*;
    use crate::test_utils::*;
    use std::time::{Duration, SystemTime};

    fn sys_to_asn1_time(syst: SystemTime) -> Asn1Time {
        let secs = syst
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Asn1Time::from_unix(secs as i64).unwrap()
    }

    #[test]
    fn check_validity_period() {
        let day = Duration::from_secs(60 * 60 * 24);
        let yesterday = sys_to_asn1_time(SystemTime::now() - day);
        let tomorrow = sys_to_asn1_time(SystemTime::now() + day);

        assert!(super::check_validity_period(&yesterday, &tomorrow).is_ok());
        assert!(matches!(
            super::check_validity_period(&tomorrow, &tomorrow),
            Err(Error::HkdVerify(BeforeValidity))
        ));
        assert!(matches!(
            super::check_validity_period(&yesterday, &yesterday),
            Err(Error::HkdVerify(AfterValidity))
        ));
    }

    #[test]
    fn is_ibm_z_sign_key() {
        let ibm_crt = load_gen_cert("ibm.crt");
        let no_ibm_crt = load_gen_cert("inter_ca.crt");
        let ibm_wrong_subj = load_gen_cert("ibm_wrong_subject.crt");

        assert!(is_ibm_signing_cert(&ibm_crt));
        assert!(!is_ibm_signing_cert(&no_ibm_crt));
        assert!(!is_ibm_signing_cert(&ibm_wrong_subj));
    }

    #[test]
    fn get_ibm_z_sign_key() {
        let ibm_crt = load_gen_cert("ibm.crt");
        let ibm_wrong_subj = load_gen_cert("ibm_wrong_subject.crt");
        let no_sign_crt = load_gen_cert("inter_ca.crt");

        assert!(super::get_ibm_z_sign_key(&[ibm_crt.clone()]).is_ok());
        assert!(matches!(
            super::get_ibm_z_sign_key(&[ibm_crt.clone(), ibm_crt.clone()]),
            Err(Error::HkdVerify(ManyIbmSignKeys))
        ));
        assert!(matches!(
            super::get_ibm_z_sign_key(&[ibm_wrong_subj]),
            Err(Error::HkdVerify(NoIbmSignKey))
        ));
        assert!(matches!(
            super::get_ibm_z_sign_key(&[no_sign_crt.clone()]),
            Err(Error::HkdVerify(NoIbmSignKey))
        ));
        assert!(super::get_ibm_z_sign_key(&[ibm_crt, no_sign_crt]).is_ok(),);
    }
}
