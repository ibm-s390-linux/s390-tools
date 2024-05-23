// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023, 2024

use std::path::PathBuf;

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

    // errors from other crates
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    ParseInt(#[from] std::num::ParseIntError),
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
