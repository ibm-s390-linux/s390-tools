// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023
pub use crate::openssl_extensions::stackable_crl::*;
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::{
    error::ErrorStack,
    stack::{Stack, StackRef},
    x509::{
        store::{X509StoreBuilderRef, X509StoreRef},
        X509CrlRef, X509NameRef, X509Ref, X509StoreContextRef, X509,
    },
};

pub fn opt_to_ptr<T: ForeignTypeRef>(o: Option<&T>) -> *mut T::CType {
    match o {
        None => std::ptr::null_mut(),
        Some(p) => p.as_ptr(),
    }
}

mod ffi {
    extern "C" {
        pub fn X509_STORE_CTX_get1_crls(
            ctx: *mut openssl_sys::X509_STORE_CTX,
            nm: *mut openssl_sys::X509_NAME,
        ) -> *mut openssl_sys::stack_st_X509_CRL;
        pub fn X509_STORE_add_crl(
            xs: *mut openssl_sys::X509_STORE,
            x: *mut openssl_sys::X509_CRL,
        ) -> std::ffi::c_int;
    }
}

pub trait X509StoreExtension {
    fn add_crl(&mut self, crl: &X509CrlRef) -> Result<(), ErrorStack>;
}

impl X509StoreExtension for X509StoreBuilderRef {
    fn add_crl(&mut self, crl: &X509CrlRef) -> Result<(), ErrorStack> {
        unsafe {
            {
                let r = ffi::X509_STORE_add_crl(self.as_ptr(), crl.as_ptr());
                if r <= 0 {
                    Err(ErrorStack::get())
                } else {
                    Ok(())
                }
            }
        }
    }
}

pub trait X509StoreContextExtension {
    fn init_opt<F, T>(
        &mut self,
        trust: &X509StoreRef,
        cert: Option<&X509Ref>,
        cert_chain: Option<&StackRef<X509>>,
        with_context: F,
    ) -> Result<T, ErrorStack>
    where
        F: FnOnce(&mut X509StoreContextRef) -> Result<T, ErrorStack>;
    fn crls(&mut self, subj: &X509NameRef) -> Result<Stack<StackableX509Crl>, ErrorStack>;
}

impl X509StoreContextExtension for X509StoreContextRef {
    fn init_opt<F, T>(
        &mut self,
        trust: &X509StoreRef,
        cert: Option<&X509Ref>,
        cert_chain: Option<&StackRef<X509>>,
        with_context: F,
    ) -> Result<T, ErrorStack>
    where
        F: FnOnce(&mut X509StoreContextRef) -> Result<T, ErrorStack>,
    {
        struct Cleanup<'a>(&'a mut X509StoreContextRef);

        impl<'a> Drop for Cleanup<'a> {
            fn drop(&mut self) {
                unsafe {
                    openssl_sys::X509_STORE_CTX_cleanup(self.0.as_ptr());
                }
            }
        }

        unsafe {
            {
                let r = openssl_sys::X509_STORE_CTX_init(
                    self.as_ptr(),
                    trust.as_ptr(),
                    opt_to_ptr(cert),
                    opt_to_ptr(cert_chain),
                );
                if r <= 0 {
                    Err(ErrorStack::get())
                } else {
                    Ok(r)
                }
            }?;
        }
        let cleanup = Cleanup(self);
        with_context(cleanup.0)
    }

    /// Get all Certificate Revocation Lists with the subject currently stored
    fn crls(&mut self, subj: &X509NameRef) -> Result<Stack<StackableX509Crl>, ErrorStack> {
        unsafe {
            {
                let r = ffi::X509_STORE_CTX_get1_crls(self.as_ptr(), subj.as_ptr());
                if r.is_null() {
                    Err(ErrorStack::get())
                } else {
                    Ok(Stack::from_ptr(r))
                }
            }
        }
    }
}
