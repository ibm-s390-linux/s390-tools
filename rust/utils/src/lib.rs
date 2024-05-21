// SPDX-License-Identifier: MIT
//! Utils for s390-tools written in rust.
//! Not intened to be used outside of s390-tools.
//!
//! Copyright IBM Corp. 2023, 2024
mod cli;
mod log;
mod tmpfile;

pub use crate::cli::CertificateOptions;
pub use crate::cli::{get_reader_from_cli_file_arg, get_writer_from_cli_file_arg};
pub use crate::cli::{print_cli_error, print_error};
pub use crate::cli::{STDIN, STDOUT};
pub use crate::log::PvLogger;
pub use crate::tmpfile::TemporaryDirectory;

/// Get the s390-tools release string
///
/// Provides the s390-tools release string.
/// For release builds this reqquires the environment variable
/// `S390_TOOLS_RELEASE` to be present at compile time.
/// For debug builds this value defaults to `DEBUG_BUILD`
/// if that variable is not present.
/// Should only be used by binary targets!!
///
/// Collapses to a compile time constant, that is likely to be inlined
/// by the compiler in release builds.
#[macro_export]
macro_rules! release_string {
    () => {{
     #[cfg(debug_assertions)]
    match option_env!("S390_TOOLS_RELEASE") {
        Some(ver) => ver,
        None => "DEBUG BUILD",
    }
    #[cfg(not(debug_assertions))]
    env!("S390_TOOLS_RELEASE", "env 'S390_TOOLS_RELEASE' must be set for release builds. Trigger build using the s390-tools build system or export the variable yourself")
    }};
}

#[macro_export]
/// Print the version to stdout
///
/// verbosity: integer if >0 more and more details printed
/// feat: (optional) list of features
/// rel_str: a string containig the release name
macro_rules! print_version {
    ($verbosity: expr, $year: expr $( ,$feat: expr)?) => {{
        println!(
            "{} version {}\nCopyright IBM Corp. {}",
            env!("CARGO_PKG_NAME"),
            $crate::release_string!(),
            $year,
        );
        if $verbosity > 0 {
            $($feat.iter().for_each(|f| print!("{f} ")); println!("(compiled)");)?
        }
        if $verbosity > 1 {
            println!(
                "\n{}-crate {}",
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION"),
            );
        }
    }};
}

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
/// # use utils::assert_size;
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
