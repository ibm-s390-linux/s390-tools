// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023, 2024

use std::path::PathBuf;

use crate::secret::UserDataType;

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
        path: PathBuf,
        ty: &'static str,
        source: openssl::error::ErrorStack,
    },

    #[error("Internal (unexpected) error: {0}, caused by {1}")]
    InternalSsl(&'static str, #[source] openssl::error::ErrorStack),

    #[error("Signing is only supported for EC and RSA keys")]
    UnsupportedSigningKey,

    #[error("Verifying signatures is only supported for EC and RSA keys")]
    UnsupportedVerificationKey,

    #[error("Provided binary request is too small")]
    BinRequestSmall,

    #[error("No Configuration UID found: {0}")]
    NoCuid(String),

    // errors from request types
    #[error("Customer Communication Key must be 32 bytes long")]
    CckSize,

    #[error("Decryption failed. Probably due to a GCM tag mismatch.")]
    GcmTagMismatch,

    #[error("Invalid {0} user-data for signing provided. Max {} bytes allowed", .0.max())]
    AsrcbInvSgnUserData(UserDataType),

    #[error("Unsupported user data signing key provided. Only EC(secp521r1) and RSA(2048 & 3072 bit) are supported")]
    BinAsrcbUnsupportedUserDataSgnKey,

    #[error("No user-key for verification provided and user-data is signed")]
    BinAsrcbNoUserDataSgnKey,

    #[error("Input does not contain an add-secret request version 1")]
    BinAsrcbInvVersion,

    #[error("Provided user-data key type ({key}) does not match with the user-data ({kind})")]
    AsrcbUserDataKeyMismatch { key: String, kind: UserDataType },

    #[error(
        "The user-defined request signature could not be verified with the provided certificate"
    )]
    AsrcbUserDataSgnFail,

    #[error("The provided Host Key Document in '{hkd}' is not in PEM or DER format")]
    HkdNotPemOrDer {
        hkd: String,
        source: openssl::error::ErrorStack,
    },

    #[error("The provided host key document in {0} contains no certificate!")]
    NoHkdInFile(String),

    #[error("Invalid input size ({0}) for boot hdr")]
    InvBootHdrSize(usize),

    #[error("Input does not contain an attestation request")]
    NoArcb,

    #[error("The attestation request has an unknown version (.0)")]
    BinArcbInvVersion(u32),

    #[error(
        "The attestation request encrypted sice is to0 small (.0). Request probably tampered with."
    )]
    BinArcbSeaSmall(u32),

    #[error("The input is missing the Configuration UID entry. It is probably not an attestation response")]
    AttExCuidMissing,

    #[error(
        "Attestation flags indicating that the additional data contains {0}, but no data was provided."
    )]
    AddDataMissing(&'static str),

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
    pub const CERT: &'static str = "certificate";
    pub const CRL: &'static str = "CRL";
}

/// Error cases for verifying host-key documents
#[allow(missing_docs)]
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HkdVerifyErrorType {
    #[error("Signature verification failed")]
    Signature,
    #[error("No valid CRL found")]
    NoCrl,
    #[error("Host-key document is revoked.")]
    HkdRevoked,
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
