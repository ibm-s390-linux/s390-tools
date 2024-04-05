// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023, 2024

macro_rules! file_error {
    ($ty: tt, $ctx: expr, $path:expr, $src: expr) => {
        $crate::Error::FileIo {
            ty: $crate::FileIoErrorType::$ty,
            ctx: $ctx.to_string(),
            path: $path.as_ref().to_path_buf(),
            source: $src,
        }
    };
}
pub(crate) use file_error;

macro_rules! bail_spec {
    ($str: expr) => {
        return Err($crate::Error::Specification($str.to_string()))
    };
}
pub(crate) use bail_spec;

/// Asserts a constant expression evaluates to `true`.
///
/// If the expression is not evaluated to `true` the compilation will fail.
#[macro_export]
macro_rules! static_assert {
    ($condition:expr) => {
        const _: () = core::assert!($condition);
    };
}

/// Asserts that a type has a specific size.
///
/// Useful to validate structs that are passed to C code.
/// If the size has not the expected value the compilation will fail.
///
/// # Example
/// ```rust
/// # use s390_pv_core::assert_size;
/// # fn main() {}
/// #[repr(C)]
/// struct c_struct {
///     v: u64,
/// }
/// assert_size!(c_struct, 8);
/// // assert_size!(c_struct, 7);//won't compile
/// ```
#[macro_export]
macro_rules! assert_size {
    ($t:ty, $sz:expr ) => {
        $crate::static_assert!(::std::mem::size_of::<$t>() == $sz);
    };
}
