// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use std::{fmt::Display, marker::PhantomData, mem::size_of};

use pv::misc::{Flags, Msb0Flags64};

pub trait ControlFlagTrait: std::fmt::Debug + std::hash::Hash + Copy + Eq + Ord {
    fn discriminant(&self) -> u8 {
        assert!(size_of::<Self>() == size_of::<u8>());
        unsafe { *(self as *const Self as *const u8) }
    }

    fn enabled(self) -> FlagData<Self> {
        FlagData::new(self, FlagState::Enabled)
    }

    fn disabled(self) -> FlagData<Self> {
        FlagData::new(self, FlagState::Disabled)
    }

    fn all_enabled<F: AsRef<[Self]>>(flags: F) -> Vec<FlagData<Self>> {
        flags
            .as_ref()
            .iter()
            .map(|flag| (*flag).enabled())
            .collect()
    }

    fn all_disabled<F: AsRef<[Self]>>(flags: F) -> Vec<FlagData<Self>> {
        flags
            .as_ref()
            .iter()
            .map(|flag| (*flag).disabled())
            .collect()
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
enum FlagState {
    Enabled,
    Disabled,
}

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

pub trait ControlFlagsTrait: Display {
    type T: ControlFlagTrait;

    fn from_flags<F: AsRef<[FlagData<Self::T>]>>(flags: F) -> Self;
    fn parse_flags<F: AsRef<[FlagData<Self::T>]>>(&mut self, flags: F);
    fn is_set(&self, flag: Self::T) -> bool;
    fn is_unset(&self, flag: Self::T) -> bool {
        !self.is_set(flag)
    }

    fn no_duplicates<F: AsRef<[FlagData<Self::T>]>>(flags: F) -> bool {
        let mut flags_sorted = flags.as_ref().to_vec();
        flags_sorted.sort_by_key(|data| data.value);
        flags_sorted.dedup_by_key(|data| data.value);

        flags_sorted.len() == flags.as_ref().len()
    }

    fn all_set<F: AsRef<[Self::T]>>(&self, flags: F) -> bool {
        flags.as_ref().iter().all(|flag| self.is_set(*flag))
    }

    fn all_unset<F: AsRef<[Self::T]>>(&self, flags: F) -> bool {
        flags.as_ref().iter().all(|flag| self.is_unset(*flag))
    }
}

/// Bitflags as used by the Secure Execution in MSB0 ordering
///
/// Wraps an u64 to set/get individual bits
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlFlags<T: ControlFlagTrait> {
    flags: Msb0Flags64,
    t: PhantomData<T>,
}

impl<T: ControlFlagTrait> ControlFlags<T> {
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
        write!(f, "{:#018x}", value)
    }
}

#[repr(u8)]
#[non_exhaustive]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum PcfV1 {
    /// PV guest dump support.
    AllowDumping = 34,
    /// The components are not decrypted during the image unpack.
    NoComponentEncryption = 35,
    /// DEA/TDEA PCKMO encryption function are allowed.
    PckmoDeaTdea = 56,
    /// AES PCKMO encryption function are allowed.
    PckmoAes = 57,
    /// ECC PCKMO encryption function are allowed.
    PckmoEcc = 58,
    /// HMAC PCKMO encryption function are allowed.
    PckmoHmac = 59,
    /// Backup target keys can be used.
    BackupTargetKeys = 62,
}
pub type PlaintextControlFlagsV1 = ControlFlags<PcfV1>;
impl PlaintextControlFlagsV1 {
    pub const PCKMO: [PcfV1; 3] = [PcfV1::PckmoAes, PcfV1::PckmoDeaTdea, PcfV1::PckmoEcc];
}

impl Default for PlaintextControlFlagsV1 {
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

#[repr(u8)]
#[non_exhaustive]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum ScfV1 {
    /// All add-secret requests must provide an extension secret
    CckExtensionSecretEnforcement = 1,
}
pub type SecretControlFlagsV1 = ControlFlags<ScfV1>;
impl ControlFlagTrait for ScfV1 {}

impl Default for SecretControlFlagsV1 {
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
        assert_eq!("0x0000000010000000", format!("{}", flags));

        let flags = PlaintextControlFlagsV1::from_flags([
            PcfV1::AllowDumping.enabled(),
            PcfV1::BackupTargetKeys.enabled(),
            PcfV1::NoComponentEncryption.enabled(),
            PcfV1::PckmoAes.enabled(),
            PcfV1::PckmoDeaTdea.enabled(),
            PcfV1::PckmoEcc.enabled(),
            PcfV1::PckmoHmac.enabled(),
        ]);
        assert_eq!("0x00000000300000f2", format!("{}", flags));
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
