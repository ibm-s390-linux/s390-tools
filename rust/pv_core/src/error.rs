// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023, 2024

use std::path::PathBuf;

use crate::uv::SecretId;

/// Result type for this crate
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Error cases for this crate
#[allow(missing_docs)]
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("Ultravisor: '{msg}' ({rc:#06x},{rrc:#06x})")]
    Uv {
        rc: u16,
        rrc: u16,
        msg: &'static str,
    },

    #[error("{0}")]
    Specification(String),

    #[error("Cannot {ty} {ctx} at `{path}`")]
    FileIo {
        ty: FileIoErrorType,
        ctx: String,
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("Cannot {ty} `{path}`")]
    FileAccess {
        ty: FileAccessErrorType,
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("Cannot rename '{src}' to '{dst}'")]
    FileAccessRename {
        src: String,
        dst: String,
        source: std::io::Error,
    },

    #[error("Cannot encode secrets (Too many secrets)")]
    ManySecrets,

    #[error("Cannot decode secret list")]
    InvSecretList(#[source] std::io::Error),

    #[error("Input does not contain an add-secret request")]
    NoAsrcb,

    #[error("Input add-secret request is larger than 8k")]
    AscrbLarge,

    #[error("Input contains unsupported user-data type: {0:#06x}")]
    UnsupportedUserData(u16),

    #[error("The input has not the correct format: {field} is too large. Maximal size {max_size}")]
    AttDataSizeLarge { field: &'static str, max_size: u32 },

    #[error("The input has not the correct format: {field} is too small. Minimal size {min_size}")]
    AttDataSizeSmall { field: &'static str, min_size: u32 },

    #[error("The attestation request has an unknown algorithm type (.0)")]
    BinArcbInvAlgorithm(u32),

    #[error("The attestation request does not specify a measurement size or measurement data.")]
    BinArcbNoMeasurement,

    #[error(
        "The secret with the ID {id} cannot be retrieved. The requested size is too large ({size})"
    )]
    InvalidRetrievableSecretType { id: SecretId, size: usize },

    #[error("Unknown bind state '{0}'.")]
    UnknownBindState(String),

    #[error("Unknown association state '{0}'.")]
    UnknownAssocState(String),

    #[error(
        "APQN({card:02x},{domain:04x}) is associated with {actual} but it should be {desired}."
    )]
    WrongAssocState {
        card: u32,
        domain: u32,
        desired: u16,
        actual: u16,
    },

    #[error("Timeout on {0}.")]
    Timeout(String),

    #[error(
        "CCA card {0:02x} cannot be used with Secure Execution, as this combination is unsupported"
    )]
    CcaSeIncompatible(u32),

    #[error("APQN({card:02x}{domain:04x}) is offline.")]
    ApOffline { card: u32, domain: u32 },

    #[error("Failure parsing {subject} '{content}'.")]
    ParseError { subject: String, content: String },

    // errors from other crates
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    ParseInt(#[from] std::num::ParseIntError),

    #[error("Cannot decode hex string: Size {0} is not a multiple of two")]
    InvHexStringSize(usize),

    #[error("Cannot decode hex string")]
    InvHexStringChar { source: std::num::ParseIntError },

    #[error("Expected size {expected}, actual {actual}")]
    LengthMismatch { expected: usize, actual: usize },
}

/// Error cases for I/O operations
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum FileIoErrorType {
    #[error("read")]
    Read,
    #[error("write")]
    Write,
}

/// Error cases for accessing files
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum FileAccessErrorType {
    #[error("open")]
    Open,
    #[error("create")]
    Create,
}
