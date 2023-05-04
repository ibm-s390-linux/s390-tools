// SPDX-License-Identifier: MIT
//! Utils for s390-tools written in rust.
//! Not intened to be used outside of s390-tools.
//!
//! Copyright IBM Corp. 2023

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
