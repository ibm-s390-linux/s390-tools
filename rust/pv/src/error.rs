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
    #[cfg_attr(debug_assertions, error("Ultravisor: '{msg}' ({rc:#06x},{rrc:#06x})"))]
    #[cfg_attr(not(debug_assertions), error("Ultravisor: '{msg}' ({rc:#06x})"))]
    Uv {
        rc: u16,
        rrc: u16,
        msg: &'static str,
    },

    #[error("Invalid SE header provided")]
    #[cfg(feature = "request")]
    InvBootHdr,

    #[error("{0}")]
    Specification(String),

    #[error("Cannot {ty} {ctx} at `{path}`")]
    FileIo {
        ty: FileIoErrorType,
        ctx: String,
        path: String,
        source: std::io::Error,
    },
    #[error("Cannot {ty} `{path}`")]
    FileAccess {
        ty: FileAccessErrorType,
        path: String,
        source: std::io::Error,
    },

    #[error("Host-key verification failed: {0}")]
    #[cfg(feature = "request")]
    HkdVerify(HkdVerifyErrorType),

    #[error("No host-key provided")]
    #[cfg(feature = "request")]
    NoHostkey,

    #[error("To many host-keys provided")]
    #[cfg(feature = "request")]
    ManyHostkeys,

    #[error("Cannot load {ty}  from {path}")]
    #[cfg(feature = "request")]
    X509Load {
        path: String,
        ty: &'static str,
        source: openssl::error::ErrorStack,
    },

    #[error("Internal (unexpected) error: {0}, caused by {1}")]
    #[cfg(feature = "request")]
    InternalSsl(&'static str, #[source] openssl::error::ErrorStack),

    #[error("No Config UID found: {0}")]
    NoCuid(String),
    // errors from request types
    #[cfg(feature = "uvsecret")]
    #[error("Customer Communication Key must be 32 bytes long")]
    CckSize,

    #[cfg(feature = "uvsecret")]
    #[error("Cannot encode secrets (Too many secrets)")]
    ManySecrets,

    #[cfg(feature = "uvsecret")]
    #[error("Cannot decode secret list")]
    InvSecretList(#[source] std::io::Error),

    #[cfg(feature = "uvsecret")]
    #[error("Input does not contain an Add Secret Request")]
    NoAsrcb,

    // errors from other crates
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    #[cfg(feature = "request")]
    Crypto(#[from] openssl::error::ErrorStack),
    #[error(transparent)]
    ParseInt(#[from] std::num::ParseIntError),
    #[cfg(feature = "request")]
    #[error(transparent)]
    Curl(#[from] curl::Error),
}

// used in macros
#[doc(hidden)]
impl Error {
    pub const CRL: &str = "CRL";
    pub const CERT: &str = "certificate";
}

/// Error cases for I/O operations
#[allow(missing_docs)]
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum FileIoErrorType {
    #[error("read")]
    Read,
    #[error("write")]
    Write,
}

/// Error cases for accessing files
#[allow(missing_docs)]
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum FileAccessErrorType {
    #[error("open")]
    Open,
    #[error("create")]
    Create,
}

/// Error cases for verifying host-key documents
///
#[doc = crate::requires_feat!(request)]
#[allow(missing_docs)]
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
#[non_exhaustive]
#[cfg(feature = "request")]
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

macro_rules! path_to_str {
    ($path: expr) => {
        $path.as_ref().to_str().unwrap_or("no UTF-8 path")
    };
}
pub(crate) use path_to_str;

macro_rules! file_error {
    ($ty: tt, $ctx: expr, $path:expr, $src: expr) => {
        $crate::Error::FileIo {
            ty: $crate::FileIoErrorType::$ty,
            ctx: $ctx.to_string(),
            path: $path.to_string(),
            source: $src,
        }
    };
}
pub(crate) use file_error;

#[cfg(feature = "request")]
macro_rules! bail_hkd_verify {
    ($var: tt) => {
        return Err($crate::Error::HkdVerify($crate::HkdVerifyErrorType::$var))
    };
}
#[cfg(feature = "request")]
pub(crate) use bail_hkd_verify;

macro_rules! bail_spec {
    ($str: expr) => {
        return Err($crate::Error::Specification($str.to_string()))
    };
}
pub(crate) use bail_spec;
