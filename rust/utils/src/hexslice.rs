// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use serde::Serialize;
use std::fmt::{Display, Formatter};

/// Displays/Serializes an u8-slice into a Hex-string
///
/// Thin wrapper around an u8-slice.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct HexSlice<'a>(&'a [u8]);

impl<'a> HexSlice<'a> {
    /// Creates a [`HexSlice`] from the given value.
    pub fn from<T>(s: &'a T) -> Self
    where
        T: ?Sized + AsRef<[u8]> + 'a,
    {
        s.into()
    }
}

impl<'a, T> From<&'a T> for HexSlice<'a>
where
    T: ?Sized + AsRef<[u8]> + 'a,
{
    fn from(value: &'a T) -> Self {
        Self(value.as_ref())
    }
}

impl Serialize for HexSlice<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!("{self:#}"))
    }
}

impl Display for HexSlice<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if f.alternate() && !f.sign_minus() {
            write!(f, "0x")?;
        }
        for byte in self.0 {
            if f.sign_minus() && f.alternate() {
                write!(f, "0x")?;
            }
            write!(f, "{byte:0>2x}")?;
            if f.sign_minus() {
                write!(f, " ")?;
            }
        }
        Ok(())
    }
}

impl AsRef<[u8]> for HexSlice<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn display_minus() {
        let hex = HexSlice::from(&[0; 8]);
        let exp = "00 00 00 00 00 00 00 00 ";

        assert_eq!(exp, format!("{hex:-}"));
    }

    #[test]
    fn display() {
        let hex = HexSlice::from(&[0; 8]);
        let exp = "0000000000000000";

        assert_eq!(exp, format!("{hex}"));
    }

    #[test]
    fn display_alternate() {
        let hex = HexSlice::from(&[0; 8]);
        let exp = "0x0000000000000000";

        assert_eq!(exp, format!("{hex:#}"));
    }

    #[test]
    fn display_minus_alternate() {
        let hex = HexSlice::from(&[0; 8]);
        let exp = "0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 ";

        assert_eq!(exp, format!("{hex:-#}"));
    }
}
