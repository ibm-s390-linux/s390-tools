// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

// Based on the output of rust-bindgen 0.69.1
#![allow(non_camel_case_types, non_snake_case, nonstandard_style)]
use deku::{ctx::Endian, prelude::*};
use pvimg::misc::PSW;

#[derive(Debug, Default, Clone, DekuRead, DekuWrite)]
#[deku(endian = "endian", ctx = "endian: Endian", ctx_default = "Endian::Big")]
pub struct memblob {
    pub src: u64,
    pub size: u64,
}

#[test]
fn bindgen_test_layout_memblob() {
    const UNINIT: ::std::mem::MaybeUninit<memblob> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<memblob>(),
        16_usize,
        concat!("Size of: ", stringify!(memblob))
    );
    assert_eq!(
        ::std::mem::align_of::<memblob>(),
        8_usize,
        concat!("Alignment of ", stringify!(memblob))
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).src) as usize - ptr as usize },
        0_usize,
        concat!(
            "Offset of field: ",
            stringify!(memblob),
            "::",
            stringify!(src)
        )
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).size) as usize - ptr as usize },
        8_usize,
        concat!(
            "Offset of field: ",
            stringify!(memblob),
            "::",
            stringify!(size)
        )
    );
}

#[derive(Debug, Default, Clone, DekuRead, DekuWrite)]
#[deku(endian = "endian", ctx = "endian: Endian", ctx_default = "Endian::Big")]
pub struct stage3b_args {
    pub kernel: memblob,
    pub cmdline: memblob,
    pub initrd: memblob,
    pub psw: PSW,
}

#[test]
fn bindgen_test_layout_stage3b_args() {
    const UNINIT: ::std::mem::MaybeUninit<stage3b_args> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<stage3b_args>(),
        64_usize,
        concat!("Size of: ", stringify!(stage3b_args))
    );
    assert_eq!(
        ::std::mem::align_of::<stage3b_args>(),
        8_usize,
        concat!("Alignment of ", stringify!(stage3b_args))
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).kernel) as usize - ptr as usize },
        0_usize,
        concat!(
            "Offset of field: ",
            stringify!(stage3b_args),
            "::",
            stringify!(kernel)
        )
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).cmdline) as usize - ptr as usize },
        16_usize,
        concat!(
            "Offset of field: ",
            stringify!(stage3b_args),
            "::",
            stringify!(cmdline)
        )
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).initrd) as usize - ptr as usize },
        32_usize,
        concat!(
            "Offset of field: ",
            stringify!(stage3b_args),
            "::",
            stringify!(initrd)
        )
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).psw) as usize - ptr as usize },
        48_usize,
        concat!(
            "Offset of field: ",
            stringify!(stage3b_args),
            "::",
            stringify!(psw)
        )
    );
}
