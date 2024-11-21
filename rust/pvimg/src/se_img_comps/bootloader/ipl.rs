// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

// Based on the output of rust-bindgen 0.69.1
#![allow(nonstandard_style, unused)]

use deku::{ctx::Endian, prelude::*};
use pvimg::{error::Result, misc::bytesize};

pub const IPL_FLAG_SECURE: u32 = 64;
pub const IPL_RB_COMPONENT_FLAG_SIGNED: u32 = 128;
pub const IPL_RB_COMPONENT_FLAG_VERIFIED: u32 = 64;
pub const IPL_MAX_SUPPORTED_VERSION: u32 = 0;
pub const IPL_PARM_BLOCK_VERSION: u8 = 1;
pub const IPL_PARM_BLOCK_PV_VERSION: u8 = 1;
pub const ipl_pbt_IPL_PBT_FCP: ipl_pbt = 0;
pub const ipl_pbt_IPL_PBT_SCP_DATA: ipl_pbt = 1;
pub const ipl_pbt_IPL_PBT_CCW: ipl_pbt = 2;
pub const ipl_pbt_IPL_PBT_ECKD: ipl_pbt = 3;
pub const ipl_pbt_IPL_PBT_NVME: ipl_pbt = 4;
pub const ipl_pbt_IPL_PBT_PV: ipl_pbt = 5;
pub type ipl_pbt = u8;

#[repr(C)]
#[derive(Debug, Default, Clone, DekuRead, DekuWrite)]
#[deku(endian = "endian", ctx = "endian: Endian", ctx_default = "Endian::Big")]
pub struct ipl_pl_hdr {
    pub len: u32,
    pub flags: u8,
    pub reserved1: [u8; 2_usize],
    pub version: u8,
}

#[repr(C)]
#[derive(Debug, Default, Clone, DekuRead, DekuWrite)]
#[deku(endian = "endian", ctx = "endian: Endian", ctx_default = "Endian::Big")]
pub struct ipl_pb0_pv_comp {
    pub tweak_pref: u64,
    pub addr: u64,
    pub len: u64,
}
#[repr(C)]
#[derive(Debug, Clone, DekuRead, DekuWrite)]
#[deku(endian = "endian", ctx = "endian: Endian", ctx_default = "Endian::Big")]
pub struct ipl_pb0_pv {
    pub len: u32,
    pub pbt: u8,
    pub reserved1: [u8; 3_usize],
    pub loadparm: [u8; 8_usize],
    pub reserved2: [u8; 84_usize],
    pub reserved3: [u8; 3_usize],
    pub version: u8,
    pub reserved4: [u8; 4_usize],
    pub num_comp: u32,
    pub pv_hdr_addr: u64,
    pub pv_hdr_size: u64,
    #[deku(count = "num_comp")]
    pub components: Vec<ipl_pb0_pv_comp>,
}

impl Default for ipl_pb0_pv {
    fn default() -> Self {
        Self {
            len: Default::default(),
            pbt: Default::default(),
            reserved1: Default::default(),
            loadparm: Default::default(),
            reserved2: [0; 84],
            reserved3: Default::default(),
            version: Default::default(),
            reserved4: Default::default(),
            num_comp: Default::default(),
            pv_hdr_addr: Default::default(),
            pv_hdr_size: Default::default(),
            components: Default::default(),
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, Clone, DekuRead, DekuWrite)]
#[deku(endian = "endian", ctx = "endian: Endian", ctx_default = "Endian::Big")]
pub struct ipl_parameter_block {
    pub hdr: ipl_pl_hdr,
    pub pv: ipl_pb0_pv,
}

use std::iter;

impl ipl_parameter_block {
    pub fn size(num_comp: usize) -> Result<usize> {
        let comps = iter::repeat(ipl_pb0_pv_comp::default())
            .take(num_comp)
            .collect();
        let ipib = Self {
            pv: ipl_pb0_pv {
                components: comps,
                ..Default::default()
            },
            ..Default::default()
        };

        bytesize(&ipib)
    }
}

impl ipl_pb0_pv {
    pub fn size(num_comp: usize) -> Result<usize> {
        let comp = ipl_pb0_pv_comp::default();
        let comps = iter::repeat(comp).take(num_comp).collect();
        let ipl = Self {
            components: comps,
            ..Default::default()
        };
        bytesize(&ipl)
    }
}
