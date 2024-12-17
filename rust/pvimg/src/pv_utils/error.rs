// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

pub use pv::Error as PvError;
pub use pv::PvCoreError;
use utils::{impl_exitcodetrait, ExitCodeTrait};

/// Result type for this crate
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Error cases for this crate
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("First image component was already prepared")]
    FirstComponentAlreadyPrepared,

    #[error(
        "Stage3b is already added so there is no possibility to add another secured component"
    )]
    ImgAlreadyFinalized,

    #[error("Invalid target key hash")]
    InvalidTargetKeyHash,

    #[error("Invalid UV key hashes")]
    InvalidUvKeyHashes,

    #[error("Invalid Secure Execution header")]
    InvalidSeHdr,

    #[error("Secure Execution header size {given} is larger than the maximum of {maximum} bytes")]
    InvalidSeHdrTooLarge { given: usize, maximum: usize },

    #[error("Invalid component metadata.")]
    InvalidComponentMetadata,

    #[error("Invalid alignment {alignment} as it's larger than the chunk size {chunk_size}.")]
    InvalidAlignment { alignment: u64, chunk_size: usize },

    #[error("Invalid interval: Start {start} is larger than {stop}")]
    InvalidInterval { start: u64, stop: u64 },

    #[error(
        "The given tweak size {given} is smaller than the expected tweak size, which is {expected}"
    )]
    InvalidTweakSize { given: usize, expected: usize },

    #[error("Invalid customer communication key (CCK)")]
    InvalidCCK { source: Box<Error> },

    #[error("Invalid stage3a")]
    InvalidStage3a,

    #[error("Invalid stage3b")]
    InvalidStage3b,

    #[error("Interval overlaps: {0}")]
    IntervalOverlap(String),

    #[error("Image already finalized")]
    ImageAlreadyFinalized,

    #[error("Provided kernel cmdline is too large: {size} > {max_size}")]
    KernelCmdlineTooLarge { size: usize, max_size: usize },

    #[error("Cannot convert to short PSW")]
    TryToShortPSWError,

    #[error("Address {addr:#0x} is not aligned to {alignment:#0x}")]
    UnalignedAddress { addr: u64, alignment: u64 },

    #[error("Support for query UV host key hashes is not available")]
    UnavailableQueryUvKeyHashesSupport { source: PvCoreError },

    #[error("ELF file found, but only raw binary kernels are supported.")]
    UnexpectedElfFile,

    #[error("Unexpected arithmetic overflow")]
    UnexpectedOverflow,

    #[error("Unexpected key type. Given {given}, expected {expected}")]
    UnexpectedKeyType { given: String, expected: String },

    #[error("Unsupported message digest")]
    UnsupportMessageDigest,

    #[error("Unexpected arithmetic underflow")]
    UnexpectedUnderflow,

    #[error(
        "Address {addr:#0x} is smaller than the next possible address, which is {next_addr:#0x}"
    )]
    NonMonotonicallyIncreasing { addr: u64, next_addr: u64 },

    #[error("No host key document provided")]
    NoHostkey,

    #[error("No s390x Linux kernel provided")]
    NoS390Kernel,

    #[error("Expert mode is not enabled")]
    NonExpertMode,

    #[error("Tweaks can be specified in expert mode only")]
    NonExpertModeTweakGiven,

    #[error("No plaintext control flag")]
    NoPlainTextControlFlag,

    #[error("No secret control flag")]
    NoSecretControlFlag,

    #[error("No Secure Execution header found.")]
    NoSeHdrFound,

    #[error("Address {addr} is already used")]
    NoUnusedAddr { addr: u64 },

    #[error("Prepared component is too large for the given location: {output_size} >  {max_output_size}")]
    PreparedComponentTooLarge {
        output_size: usize,
        max_output_size: usize,
    },

    // Errors from other crates
    #[error(transparent)]
    Deku(#[from] deku::DekuError),

    #[error(transparent)]
    Crypto(#[from] openssl::error::ErrorStack),

    #[error(transparent)]
    Pv(#[from] PvError),

    #[error(transparent)]
    PvCore(#[from] PvCoreError),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    TryFromIntError(#[from] std::num::TryFromIntError),
}

impl_exitcodetrait!(
    #[repr(u8)]
    #[derive(Debug)]
    pub enum OwnExitCode {
        /// Program finished successfully
        ///
        /// The command was executed successfully.
        Success = 0,

        /// Generic error
        ///
        /// Something went wrong during the operation. Refer to the error
        /// message.
        GenericError = 1,

        /// Usage error
        ///
        /// The command was used incorrectly, for example: unsupported command
        /// line flag, or wrong number of arguments.
        UsageError = 2, // same exit code as used by `Clap` crate
    }
);

impl From<OwnExitCode> for std::process::ExitCode {
    fn from(value: OwnExitCode) -> Self {
        Self::from(value as u8)
    }
}
