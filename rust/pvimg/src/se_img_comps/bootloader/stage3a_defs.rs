// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

// Based on the output of rust-bindgen 0.69.1
#![allow(nonstandard_style)]
use deku::{ctx::Endian, prelude::*};

pub const IMAGE_ENTRY: u64 = 0x10000;
pub const STAGE3A_INIT_ENTRY: u64 = IMAGE_ENTRY;
pub const STAGE3A_ENTRY: u64 = STAGE3A_INIT_ENTRY + 0x1000;
pub const STAGE3A_LOAD_ADDRESS: u64 = STAGE3A_INIT_ENTRY;
pub const STAGE3A_BSS_ADDRESS: u64 = 0xc000;
pub const STAGE3A_BSS_SIZE: u64 = 0x1000;

#[derive(Debug, Default, Clone, DekuRead, DekuWrite)]
#[deku(endian = "endian", ctx = "endian: Endian", ctx_default = "Endian::Big")]
pub struct stage3a_args {
    pub hdr_offs: u64,
    pub hdr_size: u64,
    pub ipib_offs: u64,
}

#[test]
fn bindgen_test_layout_stage3a_args() {
    const UNINIT: ::std::mem::MaybeUninit<stage3a_args> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<stage3a_args>(),
        24_usize,
        concat!("Size of: ", stringify!(stage3a_args))
    );
    assert_eq!(
        ::std::mem::align_of::<stage3a_args>(),
        8_usize,
        concat!("Alignment of ", stringify!(stage3a_args))
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).hdr_offs) as usize - ptr as usize },
        0_usize,
        concat!(
            "Offset of field: ",
            stringify!(stage3a_args),
            "::",
            stringify!(hdr_offs)
        )
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).hdr_size) as usize - ptr as usize },
        8_usize,
        concat!(
            "Offset of field: ",
            stringify!(stage3a_args),
            "::",
            stringify!(hdr_size)
        )
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).ipib_offs) as usize - ptr as usize },
        16_usize,
        concat!(
            "Offset of field: ",
            stringify!(stage3a_args),
            "::",
            stringify!(ipib_offs)
        )
    );
}
