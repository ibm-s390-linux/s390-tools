// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use deku::{ctx::Endian, DekuRead, DekuWrite};
use pv::request::Zeroize;
use serde::Serialize;

use super::serializing::ser_lower_hex;
use crate::pv_utils::error::Error;

pub const PSW32_ADDR_MASK: u64 = 0x000000007fffffff;
pub const PSW_MASK_BA: u64 = 0x0000000080000000;
pub const PSW_MASK_EA: u64 = 0x0000000100000000;
pub const PSW_MASK_BIT_12: u64 = 0x08000000000000;

#[derive(Default, Debug, Clone, PartialEq, Eq, DekuRead, DekuWrite, Serialize)]
#[deku(endian = "endian", ctx = "endian: Endian", ctx_default = "Endian::Big")]
pub struct PSW {
    #[serde(serialize_with = "ser_lower_hex")]
    pub mask: u64,
    #[serde(serialize_with = "ser_lower_hex")]
    pub addr: u64,
}

impl Zeroize for PSW {
    fn zeroize(&mut self) {
        self.mask.zeroize();
        self.addr.zeroize();
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, DekuRead, DekuWrite, Serialize)]
#[deku(endian = "endian", ctx = "endian: Endian", ctx_default = "Endian::Big")]
pub struct ShortPsw(u64);

impl From<ShortPsw> for PSW {
    fn from(value: ShortPsw) -> Self {
        let mask = value.0 & !PSW32_ADDR_MASK & !PSW_MASK_BIT_12;
        let addr = value.0 & PSW32_ADDR_MASK;
        Self { mask, addr }
    }
}

impl TryFrom<PSW> for ShortPsw {
    type Error = Error;

    fn try_from(value: PSW) -> Result<Self, Self::Error> {
        // test if PSW mask can be converted
        if value.mask & PSW32_ADDR_MASK != 0 {
            return Err(Error::TryToShortPSWError);
        }

        // test for bit 12
        if value.mask & PSW_MASK_BIT_12 != 0 {
            return Err(Error::TryToShortPSWError);
        }

        // test if PSW addr can be converted
        if value.addr & !PSW32_ADDR_MASK != 0 {
            return Err(Error::TryToShortPSWError);
        }

        let mut short_psw = value.mask;
        // Set bit 12 to 1
        short_psw |= PSW_MASK_BIT_12;
        short_psw |= value.addr;
        Ok(Self(short_psw))
    }
}

#[cfg(test)]
mod tests {
    use super::{ShortPsw, PSW};
    use crate::pv_utils::{error::Result, psw::PSW_MASK_BIT_12};

    #[test]
    fn test_from_psw_to_short_psw_ok() {
        let psw = PSW {
            mask: 0x180000000,
            addr: 0x11000,
        };

        let short_psw_res: Result<ShortPsw> = psw.try_into();
        assert!(short_psw_res.is_ok());
        let short_psw = short_psw_res.unwrap();

        assert_eq!(short_psw, ShortPsw(0x8000180011000));
    }

    #[test]
    fn test_from_psw_to_short_psw_mask_bit12_is_set() {
        let psw = PSW {
            mask: PSW_MASK_BIT_12,
            addr: 0x11000,
        };

        let short_psw_res: Result<ShortPsw> = psw.try_into();
        assert!(short_psw_res.is_err());
    }

    #[test]
    fn test_from_psw_to_short_psw_mask_too_large() {
        let psw = PSW {
            mask: 0x8000180011000,
            addr: 0x11000,
        };

        let short_psw_res: Result<ShortPsw> = psw.try_into();
        assert!(short_psw_res.is_err());
    }

    #[test]
    fn test_from_psw_to_short_psw_addr_too_large() {
        let psw = PSW {
            mask: 0x180000000,
            addr: 0x8000180011000,
        };

        let short_psw_res: Result<ShortPsw> = psw.try_into();
        assert!(short_psw_res.is_err());
    }

    #[test]
    fn test_from_psw_to_short_psw_and_vice_versa() {
        let psw = PSW {
            mask: 0x180000000,
            addr: 0x11000,
        };

        let short_psw_res: Result<ShortPsw> = psw.clone().try_into();
        assert!(short_psw_res.is_ok());
        let short_psw = short_psw_res.unwrap();

        let new_psw: PSW = short_psw.into();
        assert_eq!(new_psw, psw);
    }
}
