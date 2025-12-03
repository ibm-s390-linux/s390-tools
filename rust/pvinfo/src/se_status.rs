// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2025

//! se-status definitions for the PV Info Tool

use serde::Serialize; // Trait for serializing data structures (e.g., YAML)
use std::fmt; // Provides the `Display` trait for pretty-printing

/// Enum representing Secure Execution status

#[derive(Serialize, PartialEq, Debug)] // Automatically implements `serde::Serialize`
pub enum SeStatus {
    /// Running as a Secure Execution Guest
    Guest,

    /// Running as a Secure Execution Host
    Host,

    /// Secure Execution is not enabled
    Unsecure,

    /// Invalid state: Secure Execution is enabled as both Guest and Host
    /// This state is impossible in practice
    Invalid,
}

// Implement the `Display` trait so we can print human-readable strings instead of enum names.

impl fmt::Display for SeStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Map each enum variant to a descriptive string
        let s = match self {
            SeStatus::Guest => "Secure Execution Guest",
            SeStatus::Host => "Secure Execution Host",
            SeStatus::Unsecure => "Secure Execution is not enabled",
            SeStatus::Invalid => "Invalid state: both guest and host enabled (impossible)",
        };

        // Write the chosen string into the formatter
        write!(f, "{s}")
    }
}

// Associated functions (like static methods) for constructing SeStatus values.

impl SeStatus {
    /// Construct a `SeStatus` from two boolean flags:
    /// - `virt_guest`: true if running as a guest
    /// - `virt_host`: true if running as a host
    ///
    /// Returns the correct variant of `SeStatus`.
    pub fn from_flags(virt_guest: bool, virt_host: bool) -> Self {
        match (virt_guest, virt_host) {
            (true, false) => SeStatus::Guest,
            (false, true) => SeStatus::Host,
            (false, false) => SeStatus::Unsecure,
            (true, true) => SeStatus::Invalid,
        }
    }
}

#[cfg(test)]
mod test {
    //! Unit Tests for se_status

    use super::SeStatus;

    // Display implementation tests
    // Verifies that each enum variant of SeStatus is converted into the expected human-readable string
    // via the Display trait implementation

    #[test]
    fn test_display_strings() {
        assert_eq!(SeStatus::Guest.to_string(), "Secure Execution Guest");
        assert_eq!(SeStatus::Host.to_string(), "Secure Execution Host");
        assert_eq!(
            SeStatus::Unsecure.to_string(),
            "Secure Execution is not enabled"
        );
        assert_eq!(
            SeStatus::Invalid.to_string(),
            "Invalid state: both guest and host enabled (impossible)"
        );
    }

    // from_flags() constructor tests
    // Ensures that from_flags() correctly maps the
    // combinations of (virt_guest, virt_host) booleans
    // into the expected SeStatus variant

    #[test]
    fn test_from_flags_variants() {
        assert_eq!(SeStatus::from_flags(true, false), SeStatus::Guest);
        assert_eq!(SeStatus::from_flags(false, true), SeStatus::Host);
        assert_eq!(SeStatus::from_flags(false, false), SeStatus::Unsecure);
        assert_eq!(SeStatus::from_flags(true, true), SeStatus::Invalid);
    }
}
