// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

macro_rules! path_to_str {
    ($path: expr) => {
        $path.as_ref().to_str().unwrap_or("no UTF-8 path")
    };
}
pub(crate) use path_to_str;

macro_rules! file_error {
    ($ty: tt, $ctx: expr, $path:expr, $src: expr) => {
        $crate::Error::FileIo {
            ty: $crate::FileIoErrorType::$ty,
            ctx: $ctx.to_string(),
            path: $path.to_string(),
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

#[doc(hidden)]
#[macro_export]
macro_rules! file_acc_error {
    ($ty: tt, $path:expr, $src: expr) => {
        $crate::Error::FileAccess {
            ty: $crate::FileAccessErrorType::$ty,
            path: $path.to_string(),
            source: $src,
        }
    };
}
