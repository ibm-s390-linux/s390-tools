// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use core::slice;
use openssl::error::ErrorStack;
use openssl_sys::BIO_new_mem_buf;
use std::ffi::c_int;
use std::{marker::PhantomData, ptr};

pub struct BioMem(*mut openssl_sys::BIO);

impl Drop for BioMem {
    fn drop(&mut self) {
        // SAFETY: Pointer is valid. The pointer value is dropped after the free.
        unsafe {
            openssl_sys::BIO_free_all(self.0);
        }
    }
}

impl BioMem {
    pub fn new() -> Result<Self, ErrorStack> {
        openssl_sys::init();

        // SAFETY: Returns a valid pointer or null. null-case is tested right after this.
        let bio = unsafe { openssl_sys::BIO_new(openssl_sys::BIO_s_mem()) };
        match bio.is_null() {
            true => Err(ErrorStack::get()),
            false => Ok(Self(bio)),
        }
    }

    pub fn as_ptr(&self) -> *mut openssl_sys::BIO {
        self.0
    }

    /// Copies the content of this slice into a Vec
    pub fn to_vec(&self) -> Vec<u8> {
        let buf;
        // SAFTEY: BIO provides a continuous memory that can be used to build a slice.
        unsafe {
            let mut ptr = ptr::null_mut();
            let len = openssl_sys::BIO_get_mem_data(self.0, &mut ptr);
            buf = slice::from_raw_parts(ptr as *const _ as *const _, len as usize)
        }
        buf.to_vec()
    }
}

pub struct BioMemSlice<'a>(*mut openssl_sys::BIO, PhantomData<&'a [u8]>);
impl Drop for BioMemSlice<'_> {
    fn drop(&mut self) {
        // SAFETY: Pointer is valid. The pointer value is dropped after the free.
        unsafe {
            openssl_sys::BIO_free_all(self.0);
        }
    }
}

impl<'a> BioMemSlice<'a> {
    pub fn new(buf: &'a [u8]) -> Result<BioMemSlice<'a>, ErrorStack> {
        openssl_sys::init();

        // SAFETY: `buf` is a slice (i.e. pointer+size) pointing to a valid memory region.
        //          So the resulting bio is valid. Lifetime of the slice is connected by this Rust
        //          structure.
        assert!(buf.len() <= c_int::MAX as usize);
        let bio = unsafe {
            {
                let r = BIO_new_mem_buf(buf.as_ptr() as *const _, buf.len() as c_int);
                match r.is_null() {
                    true => Err(ErrorStack::get()),
                    false => Ok(r),
                }
            }?
        };

        Ok(BioMemSlice(bio, PhantomData))
    }

    pub fn as_ptr(&self) -> *mut openssl_sys::BIO {
        self.0
    }
}
