// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

//! Control flags for Secure Execution (SE) headers.
//!
//! This module provides types and traits for managing control flags used in
//! IBM Secure Execution headers. It supports two types of flags:
//! - Plaintext Control Flags (PCF)
//! - Secret Control Flags (SCF)
//!
//! # Examples
//!
//! ```
//! use pvimg::uvdata::{ControlFlagTrait, ControlFlagsTrait, PcfV1, PlaintextControlFlagsV1};
//!
//! // Create flags with specific settings
//! let flags = PlaintextControlFlagsV1::from_flags([
//!     PcfV1::AllowDumping.enabled(),
//!     PcfV1::PckmoAes.enabled(),
//! ]);
//!
//! // Check if a flag is set
//! assert!(flags.is_set(PcfV1::AllowDumping));
//! ```

use std::{fmt::Display, marker::PhantomData, mem::size_of};

use pv::misc::{Flags, Msb0Flags64};

/// Trait for individual control flag types.
///
/// This trait defines the interface for control flag enums, providing methods
/// to get the flag's bit position and create enabled/disabled flag data.
/// Implementors must be enum types with `#[repr(u8)]` to ensure proper bit positioning.
pub trait ControlFlagTrait: std::fmt::Debug + std::hash::Hash + Copy + Eq + Ord {
    /// Returns the bit position (0-63) for this flag in MSB0 ordering.
    ///
    /// # Safety
    ///
    /// This method assumes the implementing type is `#[repr(u8)]` and performs
    /// an unsafe cast to extract the discriminant value.
    fn discriminant(&self) -> u8 {
        assert!(size_of::<Self>() == size_of::<u8>());
        unsafe { *(self as *const Self as *const u8) }
    }

    /// Creates flag data with this flag in the enabled state.
    fn enabled(self) -> FlagData<Self> {
        FlagData::new(self, FlagState::Enabled)
    }

    /// Creates flag data with this flag in the disabled state.
    fn disabled(self) -> FlagData<Self> {
        FlagData::new(self, FlagState::Disabled)
    }

    /// Creates a vector of flag data with all specified flags enabled.
    ///
    /// # Arguments
    ///
    /// * `flags` - A collection of flags to enable
    fn all_enabled<F: AsRef<[Self]>>(flags: F) -> Vec<FlagData<Self>> {
        flags
            .as_ref()
            .iter()
            .map(|flag| (*flag).enabled())
            .collect()
    }

    /// Creates a vector of flag data with all specified flags disabled.
    ///
    /// # Arguments
    ///
    /// * `flags` - A collection of flags to disable
    fn all_disabled<F: AsRef<[Self]>>(flags: F) -> Vec<FlagData<Self>> {
        flags
            .as_ref()
            .iter()
            .map(|flag| (*flag).disabled())
            .collect()
    }
}

/// Internal state of a control flag (enabled or disabled).
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
enum FlagState {
    /// Flag is enabled (bit set to 1)
    Enabled,
    /// Flag is disabled (bit set to 0)
    Disabled,
}

/// Represents a control flag with its associated state.
///
/// This structure pairs a flag with its enabled/disabled state, used when
/// constructing or modifying `ControlFlags` instances.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct FlagData<T: ControlFlagTrait> {
    value: T,
    state: FlagState,
}

impl<T: ControlFlagTrait> FlagData<T> {
    const fn new(value: T, state: FlagState) -> Self {
        Self { value, state }
    }
}

/// Trait for managing control flags in Secure Execution headers.
///
/// This trait provides methods for parsing, checking, and validating
/// control flags used in Secure Execution headers.
pub trait ControlFlagsTrait: Display {
    /// The underlying control flag type
    type T: ControlFlagTrait;

    /// Creates a new instance from a collection of flag data
    fn from_flags<F: AsRef<[FlagData<Self::T>]>>(flags: F) -> Self;

    /// Parses and applies flag data to this instance
    fn parse_flags<F: AsRef<[FlagData<Self::T>]>>(&mut self, flags: F);

    /// Checks if a specific flag is set
    fn is_set(&self, flag: Self::T) -> bool;

    /// Checks if a specific flag is not set
    fn is_unset(&self, flag: Self::T) -> bool {
        !self.is_set(flag)
    }

    /// Validates that there are no duplicate flags in the collection
    fn no_duplicates<F: AsRef<[FlagData<Self::T>]>>(flags: F) -> bool {
        let mut flags_sorted = flags.as_ref().to_vec();
        flags_sorted.sort_by_key(|data| data.value);
        flags_sorted.dedup_by_key(|data| data.value);

        flags_sorted.len() == flags.as_ref().len()
    }

    /// Checks if all specified flags are set.
    ///
    /// # Arguments
    ///
    /// * `flags` - A collection of flags to check
    ///
    /// # Returns
    ///
    /// `true` if all flags are set, `false` otherwise
    fn all_set<F: AsRef<[Self::T]>>(&self, flags: F) -> bool {
        flags.as_ref().iter().all(|flag| self.is_set(*flag))
    }

    /// Checks if all specified flags are unset.
    ///
    /// # Arguments
    ///
    /// * `flags` - A collection of flags to check
    ///
    /// # Returns
    ///
    /// `true` if all flags are unset, `false` otherwise
    fn all_unset<F: AsRef<[Self::T]>>(&self, flags: F) -> bool {
        flags.as_ref().iter().all(|flag| self.is_unset(*flag))
    }
}

/// Bitflags container for Secure Execution control flags.
///
/// This structure wraps a 64-bit value with MSB0 (Most Significant Bit first)
/// ordering, as used by IBM Secure Execution. Each bit position corresponds to
/// a specific control flag defined by the generic type parameter `T`.
///
/// # Type Parameters
///
/// * `T` - The control flag enum type (e.g., [`PcfV1`] or [`ScfV1`])
///
/// # Examples
///
/// ```rust,ignore
/// use flags::{ControlFlagTrait, ControlFlags, PcfV1};
///
/// // Create from u64
/// let flags: ControlFlags<PcfV1> = 0x0000000020000000_u64.into();
///
/// // Convert back to u64
/// let value: u64 = flags.into();
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlFlags<T: ControlFlagTrait> {
    flags: Msb0Flags64,
    t: PhantomData<T>,
}

impl<T: ControlFlagTrait> ControlFlags<T> {
    /// Creates a new instance with all flags disabled.
    fn new() -> Self {
        Self {
            flags: 0x0.into(),
            t: PhantomData {},
        }
    }
}

impl<T: ControlFlagTrait> From<u64> for ControlFlags<T> {
    fn from(value: u64) -> Self {
        Self {
            flags: value.into(),
            t: PhantomData,
        }
    }
}

impl<T: ControlFlagTrait> From<&ControlFlags<T>> for u64 {
    fn from(value: &ControlFlags<T>) -> Self {
        value.flags.into()
    }
}

impl<T: ControlFlagTrait> From<ControlFlags<T>> for u64 {
    fn from(value: ControlFlags<T>) -> Self {
        value.flags.into()
    }
}

impl<T: ControlFlagTrait> ControlFlagsTrait for ControlFlags<T> {
    type T = T;

    fn from_flags<F: AsRef<[FlagData<T>]>>(flags: F) -> Self {
        let mut ret = Self::new();
        ret.parse_flags(flags);
        ret
    }

    fn parse_flags<F: AsRef<[FlagData<T>]>>(&mut self, flags: F) {
        flags.as_ref().iter().for_each(|v| match v.state {
            FlagState::Enabled => self.flags.set_bit(v.value.discriminant()),
            FlagState::Disabled => self.flags.unset_bit(v.value.discriminant()),
        });
    }

    fn is_set(&self, flag: T) -> bool {
        self.flags.is_set(flag.discriminant())
    }
}

impl<T: ControlFlagTrait> Display for ControlFlags<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value: u64 = self.flags.into();
        write!(f, "{value:#018x}")
    }
}

/// Plaintext Control Flags for Secure Execution header version 1.
///
/// These flags control various aspects of Protected Virtualization (PV) guest
/// behavior and capabilities. Each variant represents a specific bit position
/// in the 64-bit control flags field (MSB0 ordering).
///
/// # Bit Positions
///
/// The numeric values represent bit positions in MSB0 ordering (bit 0 is the
/// most significant bit). For example, `AllowDumping = 34` means bit 34 from
/// the left (MSB).
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum PcfV1 {
    /// Enables Protected Virtualization guest dump support.
    ///
    /// When set, allows dumping of the PV guest for debugging purposes.
    AllowDumping = 34,

    /// Disables component encryption during image unpacking.
    ///
    /// When set, components are not decrypted during the SE image unpack process.
    NoComponentEncryption = 35,

    /// Enables DEA/TDEA PCKMO encryption functions.
    ///
    /// Allows the guest to use Data Encryption Algorithm (DEA) and Triple DEA
    /// with the Perform Cryptographic Key Management Operation (PCKMO) instruction.
    PckmoDeaTdea = 56,

    /// Enables AES PCKMO encryption functions.
    ///
    /// Allows the guest to use Advanced Encryption Standard (AES) with PCKMO.
    PckmoAes = 57,

    /// Enables ECC PCKMO encryption functions.
    ///
    /// Allows the guest to use Elliptic Curve Cryptography (ECC) with PCKMO.
    PckmoEcc = 58,

    /// Enables HMAC PCKMO encryption functions.
    ///
    /// Allows the guest to use Hash-based Message Authentication Code (HMAC) with PCKMO.
    PckmoHmac = 59,

    /// Enables backup target keys support.
    ///
    /// When set, allows the use of backup target keys for key management operations.
    BackupTargetKeys = 62,
}

/// Type alias for plaintext control flags version 1.
///
/// This is the primary type used for managing plaintext control flags in
/// SE header version 1.
pub type PlaintextControlFlagsV1 = ControlFlags<PcfV1>;
impl PlaintextControlFlagsV1 {
    /// Array of all PCKMO-related flags (excluding HMAC).
    ///
    /// This constant provides convenient access to the three main PCKMO flags
    /// that are typically enabled together.
    pub const PCKMO: [PcfV1; 3] = [PcfV1::PckmoAes, PcfV1::PckmoDeaTdea, PcfV1::PckmoEcc];
}

impl Default for PlaintextControlFlagsV1 {
    /// Creates default plaintext control flags with PCKMO support enabled.
    fn default() -> Self {
        Self::from_flags(PcfV1::all_enabled(PlaintextControlFlagsV1::PCKMO))
    }
}

impl Display for PcfV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::AllowDumping => "allow dumping",
                Self::NoComponentEncryption => "no component encryption",
                Self::PckmoDeaTdea => "DEA and TDEA PCMKO",
                Self::PckmoAes => "AES",
                Self::PckmoEcc => "ECC PCKMO",
                Self::PckmoHmac => "HMAC PCKMO",
                Self::BackupTargetKeys => "backup target keys",
            }
        )
    }
}

impl ControlFlagTrait for PcfV1 {}

/// Secret Control Flags for Secure Execution header version 1.
///
/// These flags control various aspects of Protected Virtualization (PV) guest
/// behavior and capabilities. Each variant represents a specific bit position
/// in the 64-bit control flags field (MSB0 ordering).
///
/// # Bit Positions
///
/// The numeric values represent bit positions in MSB0 ordering (bit 0 is the
/// most significant bit). For example, `CckExtensionSecretEnforcement = 1` means bit 1 from
/// the left (MSB).
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum ScfV1 {
    /// Enforces extension secret requirement for add-secret requests.
    ///
    /// When set, all add-secret requests must provide an extension secret.
    /// This adds an additional layer of security to secret management.
    CckExtensionSecretEnforcement = 1,

    /// Allows Customer Communication Key (CCK) updates.
    ///
    /// When set, permits updating the CCK after initial configuration.
    CckUpdateAllowed = 2,
}

/// Type alias for secret control flags version 1.
///
/// This is the primary type used for managing secret control flags in
/// SE header version 1.
pub type SecretControlFlagsV1 = ControlFlags<ScfV1>;

impl ControlFlagTrait for ScfV1 {}

impl Default for SecretControlFlagsV1 {
    /// Creates default secret control flags.
    fn default() -> Self {
        Self::from_flags(ScfV1::all_enabled([]))
    }
}

#[allow(clippy::shadow_unrelated)]
#[cfg(test)]
mod test {

    use super::{ControlFlagTrait, ControlFlagsTrait, PcfV1, PlaintextControlFlagsV1};

    #[test]
    fn test_from_flags() {
        let flags = PlaintextControlFlagsV1::from_flags(&[]);
        assert_eq!(u64::from(flags), 0_u64);

        let flags = PlaintextControlFlagsV1::from_flags([PcfV1::AllowDumping.enabled()]);
        assert_eq!(u64::from(&flags), 536870912);
        assert!(flags.is_set(PcfV1::AllowDumping));

        let flags = PlaintextControlFlagsV1::from_flags([
            PcfV1::AllowDumping.enabled(),
            PcfV1::AllowDumping.disabled(),
        ]);
        assert_eq!(u64::from(flags), 0);

        let flags = PlaintextControlFlagsV1::from_flags([
            PcfV1::AllowDumping.disabled(),
            PcfV1::AllowDumping.enabled(),
        ]);
        assert_eq!(u64::from(&flags), 536870912);

        let flags = PlaintextControlFlagsV1::from_flags([
            PcfV1::AllowDumping.enabled(),
            PcfV1::BackupTargetKeys.enabled(),
        ]);
        assert_eq!(u64::from(&flags), 536870914);
    }

    #[test]
    fn test_all_set_unset() {
        let flags = PlaintextControlFlagsV1::from_flags([
            PcfV1::AllowDumping.enabled(),
            PcfV1::BackupTargetKeys.enabled(),
        ]);
        assert!(flags.all_set([PcfV1::AllowDumping, PcfV1::BackupTargetKeys]));
        assert!(!flags.all_set([PcfV1::NoComponentEncryption, PcfV1::BackupTargetKeys]));
        assert!(!flags.all_unset([PcfV1::NoComponentEncryption, PcfV1::BackupTargetKeys]));
        assert!(flags.all_unset([PcfV1::NoComponentEncryption, PcfV1::PckmoHmac]));
    }

    #[test]
    fn test_display() {
        let flags = PlaintextControlFlagsV1::from_flags([PcfV1::NoComponentEncryption.enabled()]);
        assert_eq!("0x0000000010000000", format!("{flags}"));

        let flags = PlaintextControlFlagsV1::from_flags([
            PcfV1::AllowDumping.enabled(),
            PcfV1::BackupTargetKeys.enabled(),
            PcfV1::NoComponentEncryption.enabled(),
            PcfV1::PckmoAes.enabled(),
            PcfV1::PckmoDeaTdea.enabled(),
            PcfV1::PckmoEcc.enabled(),
            PcfV1::PckmoHmac.enabled(),
        ]);
        assert_eq!("0x00000000300000f2", format!("{flags}"));
    }

    #[test]
    fn test_no_duplicates() {
        let flags: Vec<_> = [
            PcfV1::all_disabled([PcfV1::PckmoAes, PcfV1::PckmoDeaTdea, PcfV1::PckmoEcc]),
            PcfV1::all_enabled([PcfV1::PckmoAes, PcfV1::PckmoDeaTdea, PcfV1::PckmoEcc]),
        ]
        .into_iter()
        .flatten()
        .collect();
        assert!(!PlaintextControlFlagsV1::no_duplicates(flags));

        let flags: Vec<_> = [
            PcfV1::all_disabled([PcfV1::PckmoAes]),
            PcfV1::all_enabled([PcfV1::PckmoDeaTdea, PcfV1::PckmoEcc]),
        ]
        .into_iter()
        .flatten()
        .collect();
        assert!(PlaintextControlFlagsV1::no_duplicates(flags));

        let flags: Vec<_> =
            std::iter::once(PcfV1::all_disabled([PcfV1::PckmoAes, PcfV1::PckmoAes]))
                .flatten()
                .collect();
        assert!(!PlaintextControlFlagsV1::no_duplicates(flags));
    }
}
