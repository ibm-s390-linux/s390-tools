// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

/// Result type for this crate
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Error cases for this crate
#[allow(missing_docs)]
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("Invalid SE header provided")]
    InvBootHdr,

    #[error("Host-key verification failed: {0}")]
    HkdVerify(HkdVerifyErrorType),

    #[error("No host-key provided")]
    NoHostkey,

    #[error("Too many host-keys provided")]
    ManyHostkeys,

    #[error("Cannot load {ty}  from {path}")]
    X509Load {
        path: String,
        ty: &'static str,
        source: openssl::error::ErrorStack,
    },

    #[error("Internal (unexpected) error: {0}, caused by {1}")]
    InternalSsl(&'static str, #[source] openssl::error::ErrorStack),

    #[error("Signing is only supported for EC and RSA keys")]
    UnsupportedSigningKey,

    #[error("Verifying signatures is only supported for EC and RSA keys")]
    UnsupportedVerificationKey,

    // errors from other crates
    #[error(transparent)]
    PvCore(#[from] pv_core::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Crypto(#[from] openssl::error::ErrorStack),
    #[error(transparent)]
    Curl(#[from] curl::Error),
}

// used in macros
#[doc(hidden)]
impl Error {
    pub const CRL: &'static str = "CRL";
    pub const CERT: &'static str = "certificate";
}

/// Error cases for verifying host-key documents
///
#[allow(missing_docs)]
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HkdVerifyErrorType {
    #[error("Signature verification failed")]
    Signature,
    #[error("No valid CRL found")]
    NoCrl,
    #[error("Host-key document is revoked.")]
    HdkRevoked,
    #[error("Not enough bits of security. ({0}, {1} expected)")]
    SecurityBits(u32, u32),
    #[error("Authority Key Id mismatch")]
    Akid,
    #[error("CRL has no validity period")]
    NoValidityPeriod,
    #[error("Specify one IBM Z signing key")]
    NoIbmSignKey,
    #[error("Specify only one IBM Z signing key")]
    ManyIbmSignKeys,
    #[error("Before validity period")]
    BeforeValidity,
    #[error("After validity period")]
    AfterValidity,
    #[error("Issuer mismatch")]
    IssuerMismatch,
    #[error("No CRL distribution points found")]
    NoCrlDP,
    #[error("The IBM Z signing key could not be verified. Error occurred at level {1}")]
    IbmSignInvalid(#[source] openssl::x509::X509VerifyResult, u32),
}

macro_rules! bail_hkd_verify {
    ($var: tt) => {
        return Err($crate::Error::HkdVerify($crate::HkdVerifyErrorType::$var))
    };
}
pub(crate) use bail_hkd_verify;
