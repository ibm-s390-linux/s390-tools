// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

use std::{marker::PhantomData, ptr};

use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::{
    error::ErrorStack,
    stack::Stackable,
    x509::{X509Crl, X509CrlRef},
};
use openssl_sys::BIO_new_mem_buf;
use std::ffi::c_int;

#[derive(Debug)]
pub struct StackableX509Crl(*mut openssl_sys::X509_CRL);

impl ForeignType for StackableX509Crl {
    type CType = openssl_sys::X509_CRL;
    type Ref = X509CrlRef;

    unsafe fn from_ptr(ptr: *mut openssl_sys::X509_CRL) -> StackableX509Crl {
        StackableX509Crl(ptr)
    }

    fn as_ptr(&self) -> *mut openssl_sys::X509_CRL {
        self.0
    }
}
impl Drop for StackableX509Crl {
    fn drop(&mut self) {
        unsafe { (openssl_sys::X509_CRL_free)(self.0) }
    }
}
impl ::std::ops::Deref for StackableX509Crl {
    type Target = X509CrlRef;

    fn deref(&self) -> &X509CrlRef {
        unsafe { ForeignTypeRef::from_ptr(self.0) }
    }
}
impl ::std::ops::DerefMut for StackableX509Crl {
    fn deref_mut(&mut self) -> &mut X509CrlRef {
        unsafe { ForeignTypeRef::from_ptr_mut(self.0) }
    }
}
#[allow(clippy::explicit_auto_deref)]
impl ::std::borrow::Borrow<X509CrlRef> for StackableX509Crl {
    fn borrow(&self) -> &X509CrlRef {
        &**self
    }
}
#[allow(clippy::explicit_auto_deref)]
impl ::std::convert::AsRef<X509CrlRef> for StackableX509Crl {
    fn as_ref(&self) -> &X509CrlRef {
        &**self
    }
}

impl Stackable for StackableX509Crl {
    type StackType = openssl_sys::stack_st_X509_CRL;
}

pub struct MemBioSlice<'a>(*mut openssl_sys::BIO, PhantomData<&'a [u8]>);
impl<'a> Drop for MemBioSlice<'a> {
    fn drop(&mut self) {
        unsafe {
            openssl_sys::BIO_free_all(self.0);
        }
    }
}

impl<'a> MemBioSlice<'a> {
    pub fn new(buf: &'a [u8]) -> Result<MemBioSlice<'a>, ErrorStack> {
        openssl_sys::init();

        assert!(buf.len() <= c_int::MAX as usize);
        let bio = unsafe {
            {
                let r = BIO_new_mem_buf(buf.as_ptr() as *const _, buf.len() as c_int);
                if r.is_null() {
                    Err(ErrorStack::get())
                } else {
                    Ok(r)
                }
            }?
        };

        Ok(MemBioSlice(bio, PhantomData))
    }

    pub fn as_ptr(&self) -> *mut openssl_sys::BIO {
        self.0
    }
}

impl StackableX509Crl {
    pub fn stack_from_pem(pem: &[u8]) -> Result<Vec<X509Crl>, ErrorStack> {
        unsafe {
            openssl_sys::init();
            let bio = MemBioSlice::new(pem)?;

            let mut crls = vec![];
            loop {
                let r = openssl_sys::PEM_read_bio_X509_CRL(
                    bio.as_ptr(),
                    ptr::null_mut(),
                    None,
                    ptr::null_mut(),
                );
                if r.is_null() {
                    let err = openssl_sys::ERR_peek_last_error();
                    if openssl_sys::ERR_GET_LIB(err) == openssl_sys::ERR_LIB_PEM
                        && openssl_sys::ERR_GET_REASON(err) == openssl_sys::PEM_R_NO_START_LINE
                    {
                        openssl_sys::ERR_clear_error();
                        break;
                    }

                    return Err(ErrorStack::get());
                } else {
                    crls.push(X509Crl::from_ptr(r));
                }
            }

            Ok(crls)
        }
    }
}
impl From<X509Crl> for StackableX509Crl {
    fn from(value: X509Crl) -> Self {
        unsafe {
            openssl_sys::X509_CRL_up_ref(value.as_ptr());
            StackableX509Crl::from_ptr(value.as_ptr())
        }
    }
}
impl From<StackableX509Crl> for X509Crl {
    fn from(value: StackableX509Crl) -> Self {
        unsafe {
            openssl_sys::X509_CRL_up_ref(value.as_ptr());
            X509Crl::from_ptr(value.as_ptr())
        }
    }
}
