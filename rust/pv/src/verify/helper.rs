// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

use std::cmp::Ordering;
use std::ffi::c_int;
use std::path::Path;
use std::str::from_utf8;
use std::time::Duration;

use log::{debug, error, warn};
use openssl::asn1::{Asn1Time, Asn1TimeRef};
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::ssl::SslFiletype;
use openssl::stack::{Stack, StackRef};
use openssl::x509::store::{File, X509Lookup, X509StoreBuilder, X509StoreRef};
use openssl::x509::verify::{X509VerifyFlags, X509VerifyParam};
use openssl::x509::{
    X509CrlRef, X509Name, X509NameRef, X509PurposeId, X509Ref, X509StoreContext,
    X509StoreContextRef, X509VerifyResult, X509,
};
#[cfg(not(test))]
pub(crate) use prod_client::download_first_crl_from_x509;
#[cfg(test)]
pub(crate) use tests::download_first_crl_from_x509;

use crate::error::bail_hkd_verify;
use crate::openssl_extensions::{AkidCheckResult, AkidExtension};
use crate::HkdVerifyErrorType::*;
use crate::{Error, Result};

/// Minimum security level for the keys/certificates used to establish a chain of
/// trust (see <https://www.openssl.org/docs/man1.1.1/man3/X509_VERIFY_PARAM_set_auth_level.html>
/// for details).
const SECURITY_LEVEL: usize = 2;
const SECURITY_BITS_ARRAY: [u32; 6] = [0, 80, 112, 128, 192, 256];
const SECURITY_BITS: u32 = SECURITY_BITS_ARRAY[SECURITY_LEVEL];
const SECURITY_CHAIN_MAX_LEN: c_int = 2;

/// Maximum number of HTTP(S) redirections allowed when downloading CRLs.
///
/// This limit prevents infinite redirect loops and potential denial-of-service
/// attacks through redirect chains. When downloading a CRL from a distribution
/// point, if the number of redirects exceeds this limit, the download fails
/// with [`HkdVerifyErrorType::TooManyRedirectionsCrlDownload`].
///
/// # Security
///
/// Each redirect URL is validated to ensure it uses HTTP or HTTPS protocol only,
/// preventing protocol downgrade attacks or redirects to unsafe protocols.
///
/// # Value
///
/// Set to 10 redirections, which should be sufficient for legitimate CDN setups
/// while preventing abuse.
const CRL_MAX_REDIRECTIONS: usize = 10;

/// Maximum timeout duration for CRL (Certificate Revocation List) downloads.
///
/// This timeout applies to individual CRL download operations to prevent
/// indefinite blocking when fetching revocation information from remote servers.
///
/// # Value
///
/// Set to 10 seconds, which provides a reasonable balance between:
/// - Allowing sufficient time for legitimate CRL downloads over slow networks
/// - Preventing excessive delays in certificate verification workflows
/// - Protecting against unresponsive or malicious CRL distribution points
const CRL_TIMEOUT_MAX: Duration = Duration::from_secs(10);

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

pub enum StoreSetupMode {
    WithCrlCheck,
    WithoutCrlCheck,
}

/// Setup the x509Store such that it can be used it for verifying certificates
pub fn store_setup<P: AsRef<Path>, Q: AsRef<Path>, R: AsRef<Path>>(
    root_ca_path: Option<P>,
    crl_paths: &[Q],
    cert_w_crl_paths: &[R],
    mode: StoreSetupMode,
) -> Result<X509StoreBuilder> {
    let mut x509store_builder = X509StoreBuilder::new()?;

    match root_ca_path {
        None => x509store_builder.set_default_paths()?,
        Some(p) => load_root_ca(p, &mut x509store_builder)?,
    }

    for crl in crl_paths {
        load_crl_to_store(&mut x509store_builder, crl, true).map_err(|source| Error::X509Load {
            path: crl.as_ref().into(),
            ty: Error::CRL,
            source,
        })?;
    }

    for crl in cert_w_crl_paths {
        load_crl_to_store(&mut x509store_builder, crl, false).map_err(|source| {
            Error::X509Load {
                path: crl.as_ref().into(),
                ty: Error::CRL,
                source,
            }
        })?;
    }
    let mut param = X509VerifyParam::new()?;
    let mut flags = X509VerifyFlags::X509_STRICT
        | X509VerifyFlags::TRUSTED_FIRST
        | X509VerifyFlags::CHECK_SS_SIGNATURE
        | X509VerifyFlags::POLICY_CHECK;
    match mode {
        StoreSetupMode::WithCrlCheck => {
            flags |= X509VerifyFlags::CRL_CHECK | X509VerifyFlags::CRL_CHECK_ALL
        }
        StoreSetupMode::WithoutCrlCheck => {
            // nothing to do
        }
    }

    param.set_depth(SECURITY_CHAIN_MAX_LEN);
    param.set_auth_level(SECURITY_LEVEL as i32);
    param.set_purpose(X509PurposeId::ANY)?;
    param.set_flags(flags)?;
    x509store_builder.set_param(&param)?;

    Ok(x509store_builder)
}

/// Root CA verification mode
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootCaVerification {
    /// Enforce specific root CA organization name requirement
    RootCaOrganizationPinning(&'static str),
    /// Skip root CA verification (when custom root CA is provided)
    SkipPinning,
}

fn x509_subject_orgs(cert: &X509Ref) -> Vec<String> {
    cert.subject_name()
        .entries_by_nid(Nid::ORGANIZATIONNAME)
        .filter_map(|entry| entry.data().as_utf8().ok())
        .map(|s| s.to_string())
        .collect()
}

/// Checks if the certificate subject matches the expected organization name
///
/// # Arguments
/// * `cert` - The certificate chain to verify
/// * `expected_org` - The expected organization name to match
///
/// # Returns
/// * `true` if the certificate organization name equals the expected string
/// * `false` otherwise
fn check_x509_org_name(cert: &X509Ref, expected_org: &str) -> bool {
    x509_subject_orgs(cert).iter().any(|s| s == expected_org)
}

/// Verify that the given IBM signing keys can be trusted
/// -> check the chain: `IBMsignKey`<-InterCA(s)<-`RootCA`
///
/// # Arguments
/// * `store` - The X509 store containing trusted certificates
/// * `untrusted_certs` - Stack of untrusted certificates to build the chain
/// * `sign_keys` - IBM Z signing keys to verify
/// * `root_ca_verification` - Root CA verification mode
pub fn verify_chain(
    store: &X509StoreRef,
    untrusted_certs: &StackRef<X509>,
    sign_keys: &[&X509Ref],
    root_ca_verification: &RootCaVerification,
) -> Result<()> {
    fn verify_fun(
        ctx: &mut X509StoreContextRef,
        root_ca_verification: &RootCaVerification,
    ) -> std::result::Result<bool, ErrorStack> {
        // verify certificate
        let res = ctx.verify_cert()?;
        if !res {
            error!("error: Failed to verify the signing key with the chain of trust");
            return Ok(res);
        }
        // verify that the chain is as expected
        let chain = match ctx.chain() {
            Some(c) => c,
            None => {
                error!("error: No verification chain in verify-context. (openssl BUG)");
                ctx.set_error(X509VerifyResult::APPLICATION_VERIFICATION);
                return Ok(false);
            }
        };
        if chain.len() < SECURITY_CHAIN_MAX_LEN as usize {
            error!(
                "error: Verification expects one root and at least one intermediate certificate",
            );
            ctx.set_error(X509VerifyResult::APPLICATION_VERIFICATION);
            return Ok(false);
        }

        if let RootCaVerification::RootCaOrganizationPinning(expected_org) = root_ca_verification {
            // The root CA is the last certificate in the chain
            let root_ca = match chain.get(chain.len() - 1) {
                Some(cert) => cert,
                None => {
                    ctx.set_error(X509VerifyResult::APPLICATION_VERIFICATION);
                    return Ok(false);
                }
            };

            if !check_x509_org_name(root_ca, expected_org) {
                error!(
                    "error: Root CA pinning failed as organization mismatch
       expected: {}
       found:    {}

       To trust a different root CA, use '--root-ca <FILE>'.",
                    expected_org,
                    x509_subject_orgs(root_ca).join(", "),
                );
                ctx.set_error(X509VerifyResult::APPLICATION_VERIFICATION);
                return Ok(false);
            }
        }

        Ok(true)
    }

    let mut store_ctx = X509StoreContext::new()?;

    for sign_key in sign_keys {
        // (rust)OpenSSL should not error out on `X509_verify_cert`\
        // (Internal (probably unrecoverable) error like OOM)
        if !store_ctx
            .init(store, sign_key, untrusted_certs, |ctx| {
                verify_fun(ctx, root_ca_verification)
            })
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

    match subj.entries_by_nid(Nid::ORGANIZATIONALUNITNAME).next() {
        None => false,
        Some(entry) => match entry.data().as_utf8() {
            Err(_) => false,
            Ok(s) => s
                .as_bytes()
                .ends_with(IBM_Z_ORGANIZATIONAL_UNIT_NAME_SUFFIX.as_bytes()),
        },
    }
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

/// Validates that a URL uses HTTP or HTTPS protocol
///
/// # Arguments
/// * `url` - The URL to validate
///
/// # Returns
/// * `Ok(())` if protocol is HTTP or HTTPS
/// * `Err(Error::HkdVerify(InvalidCrlProtocol))` otherwise
///
/// # Security
/// This function enforces protocol restrictions to prevent CRL downloads from
/// potentially unsafe protocols like FTP, file://, or custom schemes.
fn validate_crl_url_protocol(url: &str) -> Result<()> {
    let url_lower = url.to_lowercase();
    if url_lower.starts_with("http://") || url_lower.starts_with("https://") {
        Ok(())
    } else {
        bail_hkd_verify!(InvalidCrlProtocol)
    }
}

/// Trait for HTTP client operations to enable testing
trait HttpClient {
    fn url(&mut self, url: &str) -> Result<()>;
    fn timeout(&mut self, timeout: Duration) -> Result<()>;
    fn useragent(&mut self, agent: &str) -> Result<()>;
    fn perform(&mut self) -> Result<()>;
    fn get(&mut self, enable: bool) -> Result<()>;
    fn follow_location(&mut self, enable: bool) -> Result<()>;
    fn redirect_url(&self) -> Result<Option<String>>;
    fn get_ref(&self) -> &[u8];
    fn max_filesize(&mut self, size: u64) -> Result<()>;
    /// Clears the response buffer so stale data from a previous distribution
    /// point or failed redirect chain does not bleed into the next attempt.
    fn clear(&mut self);
}

/// Production HTTP client implementation
#[cfg(not(test))]
mod prod_client {

    use curl::easy::{Easy2, Handler, WriteError};

    use super::*;

    /// Production HTTP client using curl
    pub(super) struct CurlHttpClient<H: Handler> {
        handle: Easy2<H>,
    }

    pub(crate) struct Buf(Vec<u8>);

    impl Handler for Buf {
        fn write(&mut self, data: &[u8]) -> std::result::Result<usize, WriteError> {
            self.0.extend_from_slice(data);
            Ok(data.len())
        }
    }

    impl CurlHttpClient<Buf> {
        pub(super) fn new(capacity: usize) -> Self {
            Self {
                handle: Easy2::new(Buf(Vec::with_capacity(capacity))),
            }
        }
    }

    impl HttpClient for CurlHttpClient<Buf> {
        fn get_ref(&self) -> &[u8] {
            &self.handle.get_ref().0
        }

        fn clear(&mut self) {
            self.handle.get_mut().0.clear();
        }

        fn perform(&mut self) -> Result<()> {
            match self.handle.perform() {
                Ok(()) => Ok(()),
                Err(err) if err.is_filesize_exceeded() => {
                    Err(Error::HkdVerify(CrlDownloadTooLarge(CRL_FILE_SIZE_MAX)))
                }
                Err(err) => Err(err.into()),
            }
        }

        fn get(&mut self, enable: bool) -> Result<(), Error> {
            self.handle.get(enable)?;
            Ok(())
        }

        fn follow_location(&mut self, enable: bool) -> Result<()> {
            self.handle.follow_location(enable)?;
            Ok(())
        }

        fn timeout(&mut self, timeout: Duration) -> Result<()> {
            self.handle.timeout(timeout)?;
            Ok(())
        }

        fn url(&mut self, url: &str) -> Result<()> {
            self.handle.url(url)?;
            Ok(())
        }

        fn useragent(&mut self, agent: &str) -> Result<()> {
            self.handle.useragent(agent)?;
            Ok(())
        }

        fn redirect_url(&self) -> Result<Option<String>> {
            Ok(self.handle.redirect_url()?.map(|s| s.to_string()))
        }

        fn max_filesize(&mut self, size: u64) -> Result<()> {
            self.handle.max_filesize(size)?;
            Ok(())
        }
    }

    /// Searches for CRL Distribution points and downloads the CRL. Stops after the first successful
    /// download.
    ///
    /// # Security
    ///
    /// This function enforces the following security restrictions:
    /// 1. **Protocol Restriction**: Only HTTP and HTTPS protocols are allowed for
    ///    CRL downloads. This prevents potential security issues with other protocols
    ///    like FTP, file://, or custom schemes.
    /// 2. **Redirect Protocol Restriction**: Redirects are only allowed to HTTP/HTTPS destinations,
    ///    preventing protocol downgrade attacks.
    ///
    /// Error if something bad(=unexpected) happens
    /// CRL not available at all URIs and unexpected format at all URIs are mapped to Ok(None)
    pub(crate) fn download_first_crl_from_x509(
        cert: &X509Ref,
    ) -> Result<Option<Vec<openssl::x509::X509Crl>>> {
        // A typical CRL is about 1200 bytes long
        download_first_crl_from_x509_impl(cert, CurlHttpClient::new(1200))
    }
}

const CRL_FILE_SIZE_MAX: u64 = 10 * 1024 * 1024; // 10 MiB

/// Searches for CRL Distribution points and downloads the CRL. Stops after the first successful
/// download.
///
/// Error if something bad(=unexpected) happens
/// CRL not available at all URIs and unexpected format at all URIs are mapped to Ok(None)
/// Internal implementation that accepts an HttpClient
fn download_first_crl_from_x509_impl<H: HttpClient>(
    cert: &X509Ref,
    mut client: H,
) -> Result<Option<Vec<openssl::x509::X509Crl>>> {
    use crate::utils::read_crls;

    'outer: for dist_point_url in x509_dist_points(cert) {
        // Validate protocol BEFORE attempting download
        if validate_crl_url_protocol(&dist_point_url).is_err() {
            warn!("Invalid CRL URL protocol, skipping: {}", dist_point_url);
            continue;
        }

        // Clear any stale data from a previous distribution point or
        // redirect chain before starting a new attempt.
        client.clear();

        client.url(&dist_point_url)?;
        client.get(true)?;
        // Disable automatic redirects - we handle them manually to validate the
        // protocol of each redirect URL and to limit the amount of
        // redirections.
        client.follow_location(false)?;
        client.timeout(CRL_TIMEOUT_MAX)?;
        client.max_filesize(CRL_FILE_SIZE_MAX)?;
        client.useragent("s390-tools-pv-crl")?;

        for i in 0..=CRL_MAX_REDIRECTIONS {
            // Clear any stale data by the previous perform() in this redirect
            // chain before issuing the next request.
            if i > 0 {
                client.clear();
            }
            if let Err(err) = client.perform() {
                debug!("Failed to download CRL: {}", err);
                continue 'outer;
            }

            if let Some(url) = client.redirect_url()? {
                if i == CRL_MAX_REDIRECTIONS {
                    bail_hkd_verify!(TooManyRedirectionsCrlDownload);
                }
                if validate_crl_url_protocol(&url).is_err() {
                    continue 'outer;
                }
                debug!("Redirection to: {url}");
                client.url(&url)?;
            } else {
                // No redirection, therefore let's stop and read the data
                break;
            }
        }

        match read_crls(client.get_ref()) {
            Err(_) => continue,
            Ok(crl) if crl.is_empty() => continue,
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
mod tests {
    use std::time::{Duration, SystemTime};

    use super::*;
    use crate::test_utils::*;

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

        assert!(super::get_ibm_z_sign_key(std::slice::from_ref(&ibm_crt)).is_ok());
        assert!(matches!(
            super::get_ibm_z_sign_key(&[ibm_crt.clone(), ibm_crt.clone()]),
            Err(Error::HkdVerify(ManyIbmSignKeys))
        ));
        assert!(matches!(
            super::get_ibm_z_sign_key(std::slice::from_ref(&ibm_wrong_subj)),
            Err(Error::HkdVerify(NoIbmSignKey))
        ));
        assert!(matches!(
            super::get_ibm_z_sign_key(std::slice::from_ref(&no_sign_crt)),
            Err(Error::HkdVerify(NoIbmSignKey))
        ));
        assert!(super::get_ibm_z_sign_key(&[ibm_crt, no_sign_crt]).is_ok(),);
    }

    use std::collections::HashMap;

    use openssl::bn::{BigNum, MsbOption};
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::{X509Builder, X509Crl, X509Extension, X509NameBuilder};

    use crate::test_utils::get_cert_asset_path;

    /// Mock HTTP response for testing
    pub struct MockResponse {
        pub data: Vec<u8>,
        pub redirect_to: Option<String>,
        pub should_fail: bool,
    }

    /// Mock HTTP client for testing
    pub struct MockHttpClient {
        url: String,
        responses: HashMap<String, MockResponse>,
        perform_count: usize,
        max_filesize: Option<u64>,
        /// Accumulated response body, mirroring the real CurlHttpClient behaviour.
        buf: Vec<u8>,
    }

    impl MockHttpClient {
        pub fn new(responses: HashMap<String, MockResponse>) -> Self {
            Self {
                url: String::new(),
                responses,
                perform_count: 0,
                max_filesize: None,
                buf: Vec::new(),
            }
        }
    }

    impl HttpClient for MockHttpClient {
        fn url(&mut self, url: &str) -> Result<()> {
            self.url = url.to_string();
            Ok(())
        }

        fn get(&mut self, _enable: bool) -> Result<()> {
            Ok(())
        }

        fn follow_location(&mut self, enable: bool) -> Result<()> {
            // The Rust curl crate does not support to limit the protocols,
            // therefore expect that our workaround is used.
            assert!(
                !enable,
                "Unexpected curl crate redirection instead of pv redirection used "
            );
            Ok(())
        }

        fn timeout(&mut self, _timeout: Duration) -> Result<()> {
            Ok(())
        }

        fn useragent(&mut self, _agent: &str) -> Result<()> {
            Ok(())
        }

        fn perform(&mut self) -> Result<()> {
            self.perform_count += 1;
            if let Some(response) = self.responses.get(&self.url) {
                if self
                    .max_filesize
                    .is_some_and(|max_filesize| response.data.len() as u64 > max_filesize)
                {
                    return Err(Error::HkdVerify(CrlDownloadTooLarge(CRL_FILE_SIZE_MAX)));
                }
                if response.should_fail {
                    bail_hkd_verify!(CrlDownloadFailed);
                }
                self.buf.extend_from_slice(&response.data);
                Ok(())
            } else {
                bail_hkd_verify!(CrlDownloadFailed);
            }
        }

        fn redirect_url(&self) -> Result<Option<String>> {
            if let Some(response) = self.responses.get(&self.url) {
                Ok(response.redirect_to.clone())
            } else {
                Ok(None)
            }
        }

        fn get_ref(&self) -> &[u8] {
            &self.buf
        }

        fn max_filesize(&mut self, size: u64) -> Result<()> {
            self.max_filesize = Some(size);
            Ok(())
        }

        fn clear(&mut self) {
            self.buf.clear();
        }
    }

    /// Helper to create mock response with data
    fn mock_response(data: Vec<u8>) -> MockResponse {
        MockResponse {
            data,
            redirect_to: None,
            should_fail: false,
        }
    }

    /// Helper to create mock redirect response. `body` is the response body
    /// sent along with the redirect (e.g. an HTML "Moved Permanently" page);
    /// pass `&[]` for none.
    fn mock_redirect(redirect_to: &str, body: &[u8]) -> MockResponse {
        MockResponse {
            data: body.to_vec(),
            redirect_to: Some(redirect_to.to_string()),
            should_fail: false,
        }
    }

    /// Helper to create mock failure response
    fn mock_failure() -> MockResponse {
        MockResponse {
            data: vec![],
            redirect_to: None,
            should_fail: true,
        }
    }

    /// Helper to create test certificate with CRL distribution points
    fn create_cert_with_crl_dps(crl_uris: &[&str]) -> X509 {
        // Generate a key pair
        let rsa = Rsa::generate(2048).unwrap();
        let key_pair = PKey::from_rsa(rsa).unwrap();

        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();

        // Set serial number
        let serial = {
            let mut num = BigNum::new().unwrap();
            num.rand(159, MsbOption::MAYBE_ZERO, false).unwrap();
            num.to_asn1_integer().unwrap()
        };
        builder.set_serial_number(&serial).unwrap();

        // Set subject name
        let mut name_builder = X509NameBuilder::new().unwrap();
        name_builder.append_entry_by_text("C", "US").unwrap();
        name_builder
            .append_entry_by_text("O", "Test Organization")
            .unwrap();
        name_builder
            .append_entry_by_text("CN", "Test Certificate")
            .unwrap();
        let name = name_builder.build();

        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key_pair).unwrap();

        // Set validity
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();

        // Add CRL Distribution Points if provided
        if !crl_uris.is_empty() {
            // Create a single extension with all URIs
            let crl_dp_value = crl_uris
                .iter()
                .map(|uri| format!("URI:{}", uri))
                .collect::<Vec<_>>()
                .join(",");
            #[allow(deprecated)]
            let crl_ext =
                X509Extension::new_nid(None, None, Nid::CRL_DISTRIBUTION_POINTS, &crl_dp_value)
                    .unwrap();
            builder.append_extension(crl_ext).unwrap();
        }

        // Sign the certificate
        builder.sign(&key_pair, MessageDigest::sha256()).unwrap();

        builder.build()
    }

    /// Helper to test with mock client
    fn download_with_mock(
        cert: &X509Ref,
        responses: HashMap<String, MockResponse>,
    ) -> Result<Option<Vec<X509Crl>>> {
        download_first_crl_from_x509_impl(cert, MockHttpClient::new(responses))
    }

    // Mock function
    pub(crate) fn download_first_crl_from_x509(cert: &X509Ref) -> Result<Option<Vec<X509Crl>>> {
        use std::collections::HashMap;

        let dist_points = x509_dist_points(cert);

        // Build mock responses for each distribution point
        let mut responses = HashMap::new();
        for dist_point in dist_points {
            // Treat distribution point as filename, remove the "http://" prefix
            let dist_point_path = dist_point
                .strip_prefix("http://")
                .unwrap_or(&dist_point)
                .to_string();
            let path = get_cert_asset_path(&dist_point_path);

            if let Ok(crl_data) = std::fs::read(&path) {
                responses.insert(dist_point, mock_response(crl_data));
            }
            // If file doesn't exist, skip this distribution point
        }

        download_with_mock(cert, responses)
    }

    mod protocol_validation {
        use super::*;

        #[test]
        fn validate_protocol_http() {
            assert!(validate_crl_url_protocol("http://example.com/test.crl").is_ok());
        }

        #[test]
        fn validate_protocol_https() {
            assert!(validate_crl_url_protocol("https://example.com/test.crl").is_ok());
        }

        #[test]
        fn validate_protocol_ftp_rejected() {
            assert!(matches!(
                validate_crl_url_protocol("ftp://example.com/test.crl"),
                Err(Error::HkdVerify(InvalidCrlProtocol))
            ));
        }

        #[test]
        fn validate_protocol_file_rejected() {
            assert!(matches!(
                validate_crl_url_protocol("file:///tmp/test.crl"),
                Err(Error::HkdVerify(InvalidCrlProtocol))
            ));
        }

        #[test]
        fn validate_protocol_custom_rejected() {
            assert!(matches!(
                validate_crl_url_protocol("custom://example.com/test.crl"),
                Err(Error::HkdVerify(InvalidCrlProtocol))
            ));
        }

        #[test]
        fn validate_protocol_case_insensitive() {
            assert!(validate_crl_url_protocol("HTTP://example.com/test.crl").is_ok());
            assert!(validate_crl_url_protocol("HTTPS://example.com/test.crl").is_ok());
            assert!(validate_crl_url_protocol("HtTpS://example.com/test.crl").is_ok());
        }
    }

    mod distribution_points {
        use super::*;

        #[test]
        fn extract_single_distribution_point() {
            let cert = create_cert_with_crl_dps(&["http://example.com/test.crl"]);
            let dps = x509_dist_points(&cert);
            assert_eq!(dps.len(), 1);
            assert_eq!(dps[0], "http://example.com/test.crl");
        }

        #[test]
        fn extract_multiple_distribution_points() {
            let cert = create_cert_with_crl_dps(&[
                "http://primary.example.com/test.crl",
                "http://backup.example.com/test.crl",
            ]);
            let dps = x509_dist_points(&cert);
            assert_eq!(dps.len(), 2);
            assert_eq!(dps[0], "http://primary.example.com/test.crl");
            assert_eq!(dps[1], "http://backup.example.com/test.crl");
        }

        #[test]
        fn extract_no_distribution_points() {
            let cert = create_cert_with_crl_dps(&[]);
            let dps = x509_dist_points(&cert);
            assert!(dps.is_empty());
        }
    }

    mod download_success {
        use super::*;

        #[test]
        fn download_success_single_dp() {
            let cert = create_cert_with_crl_dps(&["http://example.com/test.crl"]);
            let crl_data = std::fs::read(get_cert_asset_path("inter_ca.crl")).unwrap();

            let mut responses = HashMap::new();
            responses.insert(
                "http://example.com/test.crl".to_string(),
                mock_response(crl_data),
            );

            let result = download_with_mock(&cert, responses);
            assert!(result.is_ok());
            let crls = result.unwrap();
            assert!(crls.is_some());
            assert_eq!(crls.unwrap().len(), 1);
        }

        #[test]
        fn download_no_crl_available() {
            let cert = create_cert_with_crl_dps(&["http://example.com/test.crl"]);

            let mut responses = HashMap::new();
            responses.insert("http://example.com/test.crl".to_string(), mock_failure());

            let result = download_with_mock(&cert, responses);
            assert!(result.is_ok());
            assert!(result.unwrap().is_none());
        }

        #[test]
        fn download_first_dp_succeeds() {
            let cert = create_cert_with_crl_dps(&[
                "http://primary.example.com/test.crl",
                "http://backup.example.com/test.crl",
            ]);
            let crl_data = std::fs::read(get_cert_asset_path("inter_ca.crl")).unwrap();

            let mut responses = HashMap::new();
            responses.insert(
                "http://primary.example.com/test.crl".to_string(),
                mock_response(crl_data),
            );

            let result = download_with_mock(&cert, responses);
            assert!(result.is_ok());
            assert!(result.unwrap().is_some());
        }

        #[test]
        fn download_fallback_to_second_dp() {
            let cert = create_cert_with_crl_dps(&[
                "http://primary.example.com/test.crl",
                "http://backup.example.com/test.crl",
            ]);
            let crl_data = std::fs::read(get_cert_asset_path("inter_ca.crl")).unwrap();

            let mut responses = HashMap::new();
            responses.insert(
                "http://primary.example.com/test.crl".to_string(),
                mock_failure(),
            );
            responses.insert(
                "http://backup.example.com/test.crl".to_string(),
                mock_response(crl_data),
            );

            let result = download_with_mock(&cert, responses);
            assert!(result.is_ok());
            assert!(result.unwrap().is_some());
        }

        #[test]
        fn download_skip_invalid_protocol() {
            let cert = create_cert_with_crl_dps(&[
                "ftp://example.com/test.crl",
                "http://example.com/test.crl",
            ]);
            let crl_data = std::fs::read(get_cert_asset_path("inter_ca.crl")).unwrap();

            let mut responses = HashMap::new();
            responses.insert(
                "http://example.com/test.crl".to_string(),
                mock_response(crl_data),
            );

            let result = download_with_mock(&cert, responses);
            assert!(result.is_ok());
            assert!(result.unwrap().is_some());
        }

        #[test]
        fn download_invalid_crl_data() {
            let cert = create_cert_with_crl_dps(&["http://example.com/test.crl"]);

            let mut responses = HashMap::new();
            responses.insert(
                "http://example.com/test.crl".to_string(),
                mock_response(vec![0x00, 0x01, 0x02, 0x03]),
            );

            let result = download_with_mock(&cert, responses);
            assert!(result.is_ok());
            assert!(result.unwrap().is_none());
        }

        #[test]
        fn download_empty_response() {
            let cert = create_cert_with_crl_dps(&["http://example.com/test.crl"]);

            let mut responses = HashMap::new();
            responses.insert(
                "http://example.com/test.crl".to_string(),
                mock_response(vec![]),
            );

            let result = download_with_mock(&cert, responses);
            assert!(result.is_ok());
            assert!(result.unwrap().is_none());
        }
    }

    mod redirect_handling {
        use super::*;

        #[test]
        fn redirect_single_valid() {
            let cert = create_cert_with_crl_dps(&["http://example.com/test.crl"]);
            let crl_data = std::fs::read(get_cert_asset_path("inter_ca.crl")).unwrap();

            let mut responses = HashMap::new();
            responses.insert(
                "http://example.com/test.crl".to_string(),
                mock_redirect("http://cdn.example.com/test.crl", &[]),
            );
            responses.insert(
                "http://cdn.example.com/test.crl".to_string(),
                mock_response(crl_data),
            );

            let result = download_with_mock(&cert, responses);
            assert!(result.is_ok());
            assert!(result.unwrap().is_some());
        }

        /// A redirect response whose body contains non-CRL bytes must not corrupt
        /// the buffer: the intermediate body must be cleared before the next
        /// perform() so that read_crls() only sees the final CRL bytes.
        #[test]
        fn redirect_with_body_does_not_corrupt_crl() {
            let cert = create_cert_with_crl_dps(&["http://example.com/test.crl"]);
            let crl_data = std::fs::read(get_cert_asset_path("inter_ca.crl")).unwrap();

            // Simulate a 301 response whose body is an HTML page.
            let html_body = b"<html><body>Moved Permanently</body></html>";

            let mut responses = HashMap::new();
            responses.insert(
                "http://example.com/test.crl".to_string(),
                mock_redirect("http://cdn.example.com/test.crl", html_body),
            );
            responses.insert(
                "http://cdn.example.com/test.crl".to_string(),
                mock_response(crl_data),
            );

            let result = download_with_mock(&cert, responses);
            assert!(
                result.is_ok(),
                "CRL download should succeed despite redirect body"
            );
            assert!(
                result.unwrap().is_some(),
                "CRL should be parsed correctly after redirect with body"
            );
        }

        #[test]
        fn redirect_to_invalid_protocol() {
            let cert = create_cert_with_crl_dps(&[
                "http://example.com/test.crl",
                "http://backup.example.com/test.crl",
            ]);
            let crl_data = std::fs::read(get_cert_asset_path("inter_ca.crl")).unwrap();

            let mut responses = HashMap::new();
            responses.insert(
                "http://example.com/test.crl".to_string(),
                mock_redirect("ftp://example.com/test.crl", &[]),
            );
            responses.insert(
                "http://backup.example.com/test.crl".to_string(),
                mock_response(crl_data),
            );

            let result = download_with_mock(&cert, responses);
            assert!(result.is_ok());
            assert!(result.unwrap().is_some());
        }

        /// Exactly CRL_MAX_REDIRECTIONS (10) hops must succeed.
        #[test]
        fn redirect_at_limit_succeeds() {
            let cert = create_cert_with_crl_dps(&["http://example.com/test.crl"]);
            let crl_data = std::fs::read(get_cert_asset_path("inter_ca.crl")).unwrap();

            let mut responses = HashMap::new();
            responses.insert(
                "http://example.com/test.crl".to_string(),
                mock_redirect("http://redirect1.example.com/test.crl", &[]),
            );
            responses.insert(
                "http://redirect1.example.com/test.crl".to_string(),
                mock_redirect("http://redirect2.example.com/test.crl", &[]),
            );
            responses.insert(
                "http://redirect2.example.com/test.crl".to_string(),
                mock_redirect("http://redirect3.example.com/test.crl", &[]),
            );
            responses.insert(
                "http://redirect3.example.com/test.crl".to_string(),
                mock_redirect("http://redirect4.example.com/test.crl", &[]),
            );
            responses.insert(
                "http://redirect4.example.com/test.crl".to_string(),
                mock_redirect("http://redirect5.example.com/test.crl", &[]),
            );
            responses.insert(
                "http://redirect5.example.com/test.crl".to_string(),
                mock_redirect("http://redirect6.example.com/test.crl", &[]),
            );
            responses.insert(
                "http://redirect6.example.com/test.crl".to_string(),
                mock_redirect("http://redirect7.example.com/test.crl", &[]),
            );
            responses.insert(
                "http://redirect7.example.com/test.crl".to_string(),
                mock_redirect("http://redirect8.example.com/test.crl", &[]),
            );
            responses.insert(
                "http://redirect8.example.com/test.crl".to_string(),
                mock_redirect("http://redirect9.example.com/test.crl", &[]),
            );
            responses.insert(
                "http://redirect9.example.com/test.crl".to_string(),
                mock_redirect("http://redirect10.example.com/test.crl", &[]),
            );
            responses.insert(
                "http://redirect10.example.com/test.crl".to_string(),
                mock_response(crl_data),
            );

            let result = download_with_mock(&cert, responses);
            assert!(result.is_ok());
            assert!(result.unwrap().is_some());
        }

        /// CRL_MAX_REDIRECTIONS + 1 (11) hops must fail.
        #[test]
        fn redirect_too_many() {
            let cert = create_cert_with_crl_dps(&["http://example.com/test.crl"]);

            let mut responses = HashMap::new();
            responses.insert(
                "http://example.com/test.crl".to_string(),
                mock_redirect("http://redirect1.example.com/test.crl", &[]),
            );
            responses.insert(
                "http://redirect1.example.com/test.crl".to_string(),
                mock_redirect("http://redirect2.example.com/test.crl", &[]),
            );
            responses.insert(
                "http://redirect2.example.com/test.crl".to_string(),
                mock_redirect("http://redirect3.example.com/test.crl", &[]),
            );
            responses.insert(
                "http://redirect3.example.com/test.crl".to_string(),
                mock_redirect("http://redirect4.example.com/test.crl", &[]),
            );
            responses.insert(
                "http://redirect4.example.com/test.crl".to_string(),
                mock_redirect("http://redirect5.example.com/test.crl", &[]),
            );
            responses.insert(
                "http://redirect5.example.com/test.crl".to_string(),
                mock_redirect("http://redirect6.example.com/test.crl", &[]),
            );
            responses.insert(
                "http://redirect6.example.com/test.crl".to_string(),
                mock_redirect("http://redirect7.example.com/test.crl", &[]),
            );
            responses.insert(
                "http://redirect7.example.com/test.crl".to_string(),
                mock_redirect("http://redirect8.example.com/test.crl", &[]),
            );
            responses.insert(
                "http://redirect8.example.com/test.crl".to_string(),
                mock_redirect("http://redirect9.example.com/test.crl", &[]),
            );
            responses.insert(
                "http://redirect9.example.com/test.crl".to_string(),
                mock_redirect("http://redirect10.example.com/test.crl", &[]),
            );
            responses.insert(
                "http://redirect10.example.com/test.crl".to_string(),
                mock_redirect("http://redirect11.example.com/test.crl", &[]),
            );

            let result = download_with_mock(&cert, responses);
            assert!(matches!(
                result,
                Err(Error::HkdVerify(TooManyRedirectionsCrlDownload))
            ));
        }

        #[test]
        fn redirect_chain_valid() {
            let cert = create_cert_with_crl_dps(&["http://example.com/test.crl"]);
            let crl_data = std::fs::read(get_cert_asset_path("inter_ca.crl")).unwrap();

            let mut responses = HashMap::new();
            responses.insert(
                "http://example.com/test.crl".to_string(),
                mock_redirect("http://redirect1.example.com/test.crl", &[]),
            );
            responses.insert(
                "http://redirect1.example.com/test.crl".to_string(),
                mock_redirect("http://redirect2.example.com/test.crl", &[]),
            );
            responses.insert(
                "http://redirect2.example.com/test.crl".to_string(),
                mock_response(crl_data),
            );

            let result = download_with_mock(&cert, responses);
            assert!(result.is_ok());
            assert!(result.unwrap().is_some());
        }

        #[test]
        fn redirect_endless_loop() {
            let cert = create_cert_with_crl_dps(&["http://example.com/test.crl"]);

            let mut responses = HashMap::new();
            // Create a circular redirect: A -> B -> A
            responses.insert(
                "http://example.com/test.crl".to_string(),
                mock_redirect("http://redirect.example.com/test.crl", &[]),
            );
            responses.insert(
                "http://redirect.example.com/test.crl".to_string(),
                mock_redirect("http://example.com/test.crl", &[]),
            );

            let result = download_with_mock(&cert, responses);
            assert!(matches!(
                result,
                Err(Error::HkdVerify(TooManyRedirectionsCrlDownload))
            ));
        }
    }

    mod max_filesize {
        use super::*;
        use crate::test_utils::get_cert_asset_path;

        #[test]
        fn download_just_over_max_filesize() {
            testing_logger::setup();

            let cert = create_cert_with_crl_dps(&["http://example.com/test.crl"]);

            // Create data just over the 10 MiB limit
            let over_limit_data = vec![0u8; 10 * 1024 * 1024 + 1];

            let mut responses = HashMap::new();
            responses.insert(
                "http://example.com/test.crl".to_string(),
                mock_response(over_limit_data),
            );

            let result = download_with_mock(&cert, responses);
            // When file size exceeds limit, the download fails and function tries next URL
            // Since there's only one URL, it returns Ok(None) after exhausting all options
            assert!(result.is_ok());
            assert!(result.unwrap().is_none());

            // Verify that error was logged about file size exceeding limit
            testing_logger::validate(|captured_logs| {
                assert!(
                    captured_logs
                        .iter()
                        .any(|log| { log.body.contains("CRL download exceeds maximum file size") }),
                    "Expected log message about CRL file size exceeding maximum limit"
                );
            });
        }

        #[test]
        fn download_fallback_after_size_exceeded() {
            let cert = create_cert_with_crl_dps(&[
                "http://primary.example.com/test.crl",
                "http://backup.example.com/test.crl",
            ]);
            let crl_data = std::fs::read(get_cert_asset_path("inter_ca.crl")).unwrap();

            let mut responses = HashMap::new();
            // First URL has file that's too large
            responses.insert(
                "http://primary.example.com/test.crl".to_string(),
                mock_response(vec![0u8; (CRL_FILE_SIZE_MAX + 1).try_into().unwrap()]),
            );
            // Second URL has valid CRL
            responses.insert(
                "http://backup.example.com/test.crl".to_string(),
                mock_response(crl_data),
            );

            let result = download_with_mock(&cert, responses);
            // Should fall back to second URL and succeed
            assert!(result.is_ok());
            assert!(result.unwrap().is_some());
        }
    }

    mod organization_name_validation {
        use openssl::bn::{BigNum, MsbOption};
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::{X509Builder, X509NameBuilder};

        use super::*;

        /// Helper to create a certificate with custom organization names
        fn create_cert_with_orgs(org_names: &[&str]) -> X509 {
            let rsa = Rsa::generate(2048).unwrap();
            let key_pair = PKey::from_rsa(rsa).unwrap();

            let mut builder = X509Builder::new().unwrap();
            builder.set_version(2).unwrap();

            let serial = {
                let mut num = BigNum::new().unwrap();
                num.rand(159, MsbOption::MAYBE_ZERO, false).unwrap();
                num.to_asn1_integer().unwrap()
            };
            builder.set_serial_number(&serial).unwrap();

            let mut name_builder = X509NameBuilder::new().unwrap();
            name_builder.append_entry_by_text("C", "US").unwrap();

            // Add all organization names
            for org in org_names {
                name_builder.append_entry_by_text("O", org).unwrap();
            }

            name_builder
                .append_entry_by_text("CN", "Test Certificate")
                .unwrap();
            let name = name_builder.build();

            builder.set_subject_name(&name).unwrap();
            builder.set_issuer_name(&name).unwrap();
            builder.set_pubkey(&key_pair).unwrap();

            builder
                .set_not_before(&Asn1Time::days_from_now(0).unwrap())
                .unwrap();
            builder
                .set_not_after(&Asn1Time::days_from_now(365).unwrap())
                .unwrap();

            builder.sign(&key_pair, MessageDigest::sha256()).unwrap();
            builder.build()
        }

        #[test]
        fn organization_name_edge_cases() {
            // Test X.509 length limits: minimum (1 char) and maximum (64 chars)
            let min_org = "A";
            let max_org = "B".repeat(64);
            let special_org = "Test & Co.";
            let unicode_org = "日本電気株式会社";

            let cert = create_cert_with_orgs(&[min_org, &max_org, special_org, unicode_org]);

            assert!(check_x509_org_name(&cert, min_org));
            assert!(check_x509_org_name(&cert, &max_org));
            assert!(check_x509_org_name(&cert, special_org));
            assert!(check_x509_org_name(&cert, unicode_org));

            assert!(!check_x509_org_name(&cert, "AB"));
            assert!(!check_x509_org_name(&cert, &"B".repeat(63)));
            assert!(!check_x509_org_name(&cert, "Test"));
            assert!(!check_x509_org_name(&cert, ""));
        }

        #[test]
        fn multiple_organization_values() {
            let cert = create_cert_with_orgs(&["IBM", "Red Hat"]);

            assert!(check_x509_org_name(&cert, "IBM"));
            assert!(check_x509_org_name(&cert, "Red Hat"));

            assert!(!check_x509_org_name(&cert, "Microsoft"));
        }

        #[test]
        fn organization_name_exact_matching() {
            // Test case sensitivity and whitespace handling
            let cert = create_cert_with_orgs(&["IBM Corporation", "IBM  Corp"]);

            assert!(check_x509_org_name(&cert, "IBM Corporation"));
            assert!(!check_x509_org_name(&cert, "ibm corporation"));
            assert!(!check_x509_org_name(&cert, "IBM CORPORATION"));

            assert!(check_x509_org_name(&cert, "IBM  Corp"));
            assert!(!check_x509_org_name(&cert, "IBM Corp"));
        }
    }

    mod custom_root_ca_validation {
        use openssl::x509::verify::{X509VerifyFlags, X509VerifyParam};
        use openssl::x509::X509Crl;

        use super::*;
        use crate::verify::X509StoreExtension;

        #[test]
        fn custom_root_ca_does_not_bypass_chain_validation() {
            // This test verifies that providing a custom root CA (--root-ca flag)
            // only skips organization pinning, but does NOT bypass other validation

            let root_ca = load_gen_cert("root_ca.crt");
            let fake_inter = load_gen_cert("fake_inter_ca.crt");
            let ibm_cert = load_gen_cert("ibm.crt");

            let mut store_builder = X509StoreBuilder::new().unwrap();
            store_builder.add_cert(root_ca).unwrap();

            let crl =
                X509Crl::from_pem(&std::fs::read(get_cert_asset_path("inter_ca.crl")).unwrap())
                    .unwrap();
            store_builder.add_crl(&crl).unwrap();
            let mut param = X509VerifyParam::new().unwrap();
            param.set_flags(X509VerifyFlags::CRL_CHECK).unwrap();
            store_builder.set_param(&param).unwrap();

            let store = store_builder.build();

            // Create untrusted chain with FAKE intermediate (invalid chain)
            let mut untrusted = Stack::<X509>::new().unwrap();
            untrusted.push(fake_inter).unwrap();

            let result = verify_chain(
                &store,
                &untrusted,
                &[&ibm_cert],
                &RootCaVerification::SkipPinning,
            );

            assert!(
                result.is_err(),
                "Custom root CA should not bypass chain validation"
            );
        }

        #[test]
        fn custom_root_ca_skips_organization_pinning() {
            // This test verifies that SkipPinning mode allows any root CA organization

            let root_ca = load_gen_cert("root_ca.crt");
            let inter_ca = load_gen_cert("inter_ca.crt");
            let ibm_cert = load_gen_cert("ibm.crt");

            let mut store_builder = X509StoreBuilder::new().unwrap();
            store_builder.add_cert(root_ca).unwrap();

            let crl =
                X509Crl::from_pem(&std::fs::read(get_cert_asset_path("inter_ca.crl")).unwrap())
                    .unwrap();
            store_builder.add_crl(&crl).unwrap();
            let mut param = X509VerifyParam::new().unwrap();
            param.set_flags(X509VerifyFlags::CRL_CHECK).unwrap();
            store_builder.set_param(&param).unwrap();

            let store = store_builder.build();

            let mut untrusted = Stack::<X509>::new().unwrap();
            untrusted.push(inter_ca).unwrap();

            let result = verify_chain(
                &store,
                &untrusted,
                &[&ibm_cert],
                &RootCaVerification::SkipPinning,
            );

            assert!(
                result.is_ok(),
                "Valid chain should succeed with SkipPinning"
            );
        }

        #[test]
        fn organization_pinning_enforces_expected_org() {
            // This test verifies that organization pinning rejects wrong organizations

            let root_ca = load_gen_cert("root_ca.crt");
            let inter_ca = load_gen_cert("inter_ca.crt");
            let ibm_cert = load_gen_cert("ibm.crt");

            let mut store_builder = X509StoreBuilder::new().unwrap();
            store_builder.add_cert(root_ca.clone()).unwrap();

            let crl =
                X509Crl::from_pem(&std::fs::read(get_cert_asset_path("inter_ca.crl")).unwrap())
                    .unwrap();
            store_builder.add_crl(&crl).unwrap();
            let mut param = X509VerifyParam::new().unwrap();
            param.set_flags(X509VerifyFlags::CRL_CHECK).unwrap();
            store_builder.set_param(&param).unwrap();

            let store = store_builder.build();

            let mut untrusted = Stack::<X509>::new().unwrap();
            untrusted.push(inter_ca).unwrap();

            // With wrong organization pinning, should fail
            let wrong_org = "Wrong Organization Name";
            let result = verify_chain(
                &store,
                &untrusted,
                &[&ibm_cert.clone()],
                &RootCaVerification::RootCaOrganizationPinning(wrong_org),
            );

            assert!(result.is_err(), "Should fail with wrong organization");

            // With correct organization pinning, should succeed
            let result = verify_chain(
                &store,
                &untrusted,
                &[&ibm_cert],
                &RootCaVerification::RootCaOrganizationPinning(
                    "International Business Machines Corporation",
                ),
            );

            assert!(result.is_ok(), "Should succeed with correct organization");
        }
    }
}
