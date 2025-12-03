// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2025
use clap::{Parser, Subcommand, ValueEnum};

/// Output format for pvinfo results
#[derive(Copy, Clone, Debug, ValueEnum, Default)]
pub enum OutputFormat {
    #[default]

    /// Human-readable format
    Human,

    /// YAML format
    Yaml,
}

/// Query information about IBM Secure Execution system status
///
/// The PV Info Tool queries and displays information provided by the
/// Ultravisor about IBM Secure Execution host and guest systems.
/// It can show the Secure Execution (SE) status, installed facilities,
/// supported features, supported flags, and limits.
///
/// By default, running `pvinfo` without arguments prints all available
/// information in human-readable format.
/// Specific flags allow focused queries (e.g., only SE status, only limits).
/// Output can also be formatted as YAML.
#[derive(Parser, Debug)]
#[command(author)]
pub struct CliOptions {
    /// Display the Secure Execution status of the system
    ///
    /// Prints whether this system is running as an SE-host,
    /// SE-guest, or none.
    #[arg(long)]
    pub se_status: bool,

    /// Show installed Ultravisor calls
    ///
    /// Lists all facilities supported by the Ultravisor.
    #[arg(long)]
    pub facilities: bool,

    /// Show Ultravisor feature indications
    ///
    /// Lists the feature bits reported by the Ultravisor that describe
    /// available Secure Execution functionality.
    #[arg(long)]
    pub feature_indications: bool,

    /// Show supported plaintext attestation flags
    ///
    /// Prints the list of flags that can be used in attestation requests.
    #[arg(long)]
    pub supported_plaintext_attestation_flags: bool,

    /// Show supported SE header versions
    ///
    /// Prints the list of header versions supported.
    #[arg(long)]
    pub supported_se_header_versions: bool,

    /// Show supported secret types
    ///
    /// Lists the types of secrets.
    #[arg(long)]
    pub supported_secret_types: bool,

    /// Show supported plaintext control flags
    ///
    /// Lists control flags that can be set .
    #[arg(long)]
    pub supported_plaintext_control_flags: bool,

    /// Show supported attestation request versions
    ///
    /// Lists the versions of attestation request .
    #[arg(long)]
    pub supported_attestation_request_versions: bool,

    /// Show supported add-secret request versions
    ///
    /// Lists the versions of add-secret request supported.
    #[arg(long)]
    pub supported_add_secret_request_versions: bool,

    /// Show supported plaintext add-secret flags
    ///
    /// Lists control flags available for plaintext Add-secret requests.
    #[arg(long)]
    pub supported_plaintext_add_secret_flags: bool,

    /// Show Secure Execution limits
    ///
    /// Prints limits such as the maximum number of CPUs,
    /// maximum guests, maximum retrievable secrets, etc.
    #[arg(long)]
    pub limits: bool,

    /// Print version information and exit
    #[arg(long)]
    pub version: bool,

    /// Select the output format
    ///
    /// By default, output is human-readable text.
    /// Use `--format yaml` to produce YAML output instead.
    #[arg(long, value_enum, default_value_t)]
    pub format: OutputFormat,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

/// Additional commands to query supported flags
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Query supported flags grouped by category
    ///
    /// Provides detailed information about supported secret types,
    /// attestation flags, and header versions.
    /// By default, all categories are shown if no specific options are set.
    SupportedFlags {
        /// Show supported secret-related flags
        #[arg(long)]
        secret: bool,

        /// Show supported attestation-related flags
        #[arg(long)]
        attestation: bool,

        /// Show supported header-related flags
        #[arg(long)]
        header: bool,
    },
}

impl CliOptions {
    /// Returns true if any query flags or subcommands were provided.
    pub fn any_flags_set(&self) -> bool {
        self.se_status
            || self.facilities
            || self.feature_indications
            || self.supported_plaintext_attestation_flags
            || self.supported_se_header_versions
            || self.supported_secret_types
            || self.supported_plaintext_control_flags
            || self.supported_attestation_request_versions
            || self.supported_add_secret_request_versions
            || self.supported_plaintext_add_secret_flags
            || self.limits
            || self.command.is_some()
    }

    /// Sets all flags to true if no flags or subcommands are set.
    pub fn post_process(&mut self) {
        if !self.any_flags_set() {
            self.se_status = true;
            self.facilities = true;
            self.feature_indications = true;
            self.supported_plaintext_attestation_flags = true;
            self.supported_se_header_versions = true;
            self.supported_secret_types = true;
            self.supported_plaintext_control_flags = true;
            self.supported_attestation_request_versions = true;
            self.supported_add_secret_request_versions = true;
            self.supported_plaintext_add_secret_flags = true;
            self.limits = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper function to create a base CLI with all flags false
    fn base_cli() -> CliOptions {
        CliOptions {
            se_status: false,
            facilities: false,
            feature_indications: false,
            supported_plaintext_attestation_flags: false,
            supported_se_header_versions: false,
            supported_secret_types: false,
            supported_plaintext_control_flags: false,
            supported_attestation_request_versions: false,
            supported_add_secret_request_versions: false,
            supported_plaintext_add_secret_flags: false,
            limits: false,
            version: false,
            command: None,
            format: OutputFormat::Human,
        }
    }

    #[test]
    fn test_any_flags_set_false_when_all_false() {
        let cli = base_cli();
        assert!(!cli.any_flags_set());
    }

    #[test]
    fn test_any_flags_set_true_when_single_flag_true() {
        let mut cli = base_cli();
        cli.se_status = true;
        assert!(cli.any_flags_set());
    }

    #[test]
    fn test_any_flags_set_true_when_command_set() {
        let mut cli = base_cli();
        cli.command = Some(Commands::SupportedFlags {
            secret: true,
            attestation: true,
            header: true,
        });
        assert!(cli.any_flags_set());
    }

    #[test]
    fn test_any_flags_set_true_when_multiple_flags_true() {
        let mut cli = base_cli();
        cli.se_status = true;
        cli.limits = true;
        cli.feature_indications = true;
        assert!(cli.any_flags_set());
    }
}
