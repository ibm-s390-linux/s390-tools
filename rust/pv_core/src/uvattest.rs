// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use crate::{request::MagicValue, Error};
use byteorder::{BigEndian, ByteOrder};
use zerocopy::U32;

/// The magic value used to identify an attestation request
///
/// The magic value is ASCII:
/// ```rust
/// # use s390_pv_core::attest::AttestationMagic;
/// # use s390_pv_core::request::MagicValue;
/// # fn main() {
/// # let magic = &
/// [0u8; 8]
/// # ;
/// # assert!(AttestationMagic::starts_with_magic(magic));
/// # }
/// ```
#[derive(Debug)]
pub struct AttestationMagic;
impl MagicValue<8> for AttestationMagic {
    const MAGIC: [u8; 8] = [0; 8];
}

/// Identifier for the used measurement algorithm
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationMeasAlg {
    /// Use HMAC with SHA512 as measurement algorithm
    HmacSha512 = 1,
}

impl AttestationMeasAlg {
    /// Report the expected size for a given measurement algorithm
    pub const fn exp_size(&self) -> u32 {
        match self {
            AttestationMeasAlg::HmacSha512 => 64,
        }
    }
}

impl<E: ByteOrder> TryFrom<U32<E>> for AttestationMeasAlg {
    type Error = Error;

    fn try_from(value: U32<E>) -> Result<Self, Self::Error> {
        if value.get() == AttestationMeasAlg::HmacSha512 as u32 {
            Ok(Self::HmacSha512)
        } else {
            Err(Error::BinArcbInvAlgorithm(value.get()))
        }
    }
}

impl From<AttestationMeasAlg> for U32<BigEndian> {
    fn from(value: AttestationMeasAlg) -> Self {
        (value as u32).into()
    }
}
