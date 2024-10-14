// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023, 2024

use std::fmt::Debug;

/// Trait for securely zeroizing  memory.
///
/// To be used with [`Confidential`]
pub trait Zeroize {
    /// Reliably overwrites the given buffer with zeros,
    fn zeroize(&mut self);
}

// Automatically impl Zeroize for u8 arrays
impl<T: Default, const COUNT: usize> Zeroize for [T; COUNT] {
    /// Reliably overwrites the given buffer with zeros,
    /// by performing a volatile write followed by a memory barrier
    fn zeroize(&mut self) {
        let mut dst = self.as_mut_ptr();
        for _ in 0..self.len() {
            // SAFETY:
            // * Array allocated len elements continuously
            // * dst points always to a valid location
            unsafe {
                std::ptr::write_volatile(dst, T::default());
                dst = dst.add(1);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl<T: Default> Zeroize for Vec<T> {
    /// Reliably overwrites the given buffer with zeros,
    /// by overwriting the whole vector's capacity with zeros.
    fn zeroize(&mut self) {
        let mut dst = self.as_mut_ptr();
        for _ in 0..self.capacity() {
            // SAFETY:
            // * Vec allocated at least capacity elements continuously
            // * dst points always to a valid location
            unsafe {
                std::ptr::write_volatile(dst, T::default());
                dst = dst.add(1);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl Zeroize for String {
    fn zeroize(&mut self) {
        // SAFETY: The Vec<u8> zerorize function overwrites memory with the zero byte -> still valid UTF-8
        unsafe { self.as_mut_vec().zeroize() };
    }
}

/// Thin wrapper around an type implementing Zeroize.
///
/// A `Confidential` represents a confidential value that must be securely overwritten during drop.
/// Will never leak its wrapped value during [`Debug`]
///
/// ```rust
/// # use s390_pv_core::request::Confidential;
/// fn foo(value: Confidential<[u8; 2]>) {
///     println!("value: {value:?}");
/// }
/// # fn main() {
/// foo([1, 2].into());
/// // prints:
/// // in debug builds:
/// //     value: Confidential([1, 2])
/// // in release builds:
/// //     value: Confidential(***)
/// # }
/// ```
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Confidential<C: Zeroize>(C);
impl<C: Zeroize> Confidential<C> {
    /// Convert a type into a self overwriting one.
    ///
    /// Prefer using [`Into`]
    pub fn new(v: C) -> Self {
        Self(v)
    }

    /// Get a reference to the contained value
    pub fn value(&self) -> &C {
        &self.0
    }

    /// Get a mutable reference to the contained value
    ///
    /// NOTE that modifications to a mutable reference can trigger reallocation.
    /// e.g. a [`Vec`] might expand if more space needed. -> preallocate enough space
    /// or operate on slices. The old locations can and will **NOT** be zeroized.
    pub fn value_mut(&mut self) -> &mut C {
        &mut self.0
    }
}

impl<C: Zeroize + Clone> Confidential<C> {
    /// Consume the [`Confidential`] into its contained type as a clone.
    ///
    /// This disables any cleanups for the result.
    pub fn into_inner(self) -> C {
        // The clone is required because drop is implemented (E0509)
        self.0.clone()
    }
}

impl<C: Zeroize + Debug> Debug for Confidential<C> {
    #[allow(unreachable_code)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // do NOT leak secrets in production builds
        #[cfg(not(debug_assertions))]
        return write!(f, "Confidential(***)");

        let mut b = f.debug_tuple("Confidential");
        b.field(&self.0);
        b.finish()
    }
}

impl<C: Zeroize> From<C> for Confidential<C> {
    fn from(v: C) -> Self {
        Self(v)
    }
}

impl<C: Zeroize> Zeroize for Confidential<C> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<C: Zeroize> Drop for Confidential<C> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[derive(Debug, Default, PartialEq, Eq)]
    struct DummyStruct([u32; 8]);

    #[test]
    fn array() {
        let mut conf = Confidential::new([17; 42]);
        assert_eq!(&[17; 42], conf.value());
        conf.zeroize();
        assert_eq!(&[0; 42], conf.value());

        let mut conf2 = Confidential::new([DummyStruct([0x12u32; 8]), DummyStruct([0x24u32; 8])]);
        assert_eq!(
            &[DummyStruct([0x12u32; 8]), DummyStruct([0x24u32; 8])],
            conf2.value()
        );
        conf2.zeroize();
        assert_eq!(
            &[DummyStruct([0x0u32; 8]), DummyStruct([0x0u32; 8])],
            conf2.value()
        );
    }

    #[test]
    fn vec() {
        let mut conf = Confidential::new(vec![17; 42]);
        conf.zeroize();
        assert_eq!(&[0; 42], conf.value().as_slice());

        let mut conf2 =
            Confidential::new(vec![DummyStruct([0x12u32; 8]), DummyStruct([0x24u32; 8])]);
        assert_eq!(
            &[DummyStruct([0x12u32; 8]), DummyStruct([0x24u32; 8])],
            conf2.value().as_slice()
        );
        conf2.zeroize();
        assert_eq!(
            &[DummyStruct([0x0u32; 8]), DummyStruct([0x0u32; 8])],
            conf2.value().as_slice()
        );
    }

    #[test]
    fn string() {
        let mut conf = Confidential::new("test".to_string());
        conf.zeroize();
        assert_eq!(&[0; 4], conf.value().as_bytes());
    }
}