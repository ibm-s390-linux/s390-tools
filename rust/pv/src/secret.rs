// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

use std::fmt::Debug;

/// Trait for securely zeroizing  memory.
///
/// To be used with [`Secret`]
pub trait Zeroize {
    /// Reliably overwrites the given buffer with zeros,
    fn zeroize(&mut self);
}

/* Automatically impl Zeroize for u8 arrays */
impl<const COUNT: usize> Zeroize for [u8; COUNT] {
    /// Reliably overwrites the given buffer with zeros,
    /// by performing a volatile write followed by a memory barrier
    fn zeroize(&mut self) {
        // SAFETY: given buffer(self) has the correct (compile time) size
        unsafe { std::ptr::write_volatile(self, [0u8; COUNT]) };
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl Zeroize for Vec<u8> {
    /// Reliably overwrites the given buffer with zeros,
    /// by overwriting the whole vector's capacity with zeros.
    fn zeroize(&mut self) {
        //TODO use `volatile_set_memory` when stabilized
        let mut dst = self.as_mut_ptr();
        for _ in 0..self.capacity() {
            // SAFETY:
            // * Vec allocated at least capacity elements continuously
            // * dst points always to a valid location
            unsafe {
                dst = dst.add(1);
                std::ptr::write_volatile(dst, 0)
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

/// Thin wrapper around an type implementing Zeroize.
///
/// A `Secret` represents a confidential value that must be securely overwritten during drop.
/// Will never leak its wrapped value during [`Debug`]
///
/// ```rust
/// use pv::request::Secret;
/// fn foo(value: Secret<[u8; 2]>) {
///     println!("value: {value:?}");
/// }
/// # fn main() {
/// foo([1,2].into());
/// // prints:
/// // in debug builds:
/// //     value: Secret([1, 2])
/// // in release builds:
/// //     value: Secret(***)
/// # }
/// ```
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Secret<C: Zeroize>(C);
impl<C: Zeroize> Secret<C> {
    /// Convert a type into a self overwriting one.
    ///
    /// Prefer using [`Into`]
    pub fn new(v: C) -> Self {
        Secret(v)
    }

    /// Get a reference to the contained value
    pub fn value(&self) -> &C {
        &self.0
    }
    /// Get a imutable reference to the contained value
    ///
    /// NOTE that modifications to a mutable reference can trigger reallocation.
    /// e.g. a [`Vec`] might expand if more space needed. -> preallocate enough space
    /// or operate on slices. The old locations can and will **NOT** be zeroized.
    pub fn value_mut(&mut self) -> &mut C {
        &mut self.0
    }
}

impl<C: Zeroize + Debug> Debug for Secret<C> {
    #[allow(unreachable_code)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // do NOT leak secrets in production builds
        #[cfg(not(debug_assertions))]
        return write!(f, "Secret(***)");

        let mut b = f.debug_tuple("Secret");
        b.field(&self.0);
        b.finish()
    }
}

impl<C: Zeroize> From<C> for Secret<C> {
    fn from(v: C) -> Secret<C> {
        Secret(v)
    }
}

impl<C: Zeroize> Zeroize for Secret<C> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<C: Zeroize> Drop for Secret<C> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
