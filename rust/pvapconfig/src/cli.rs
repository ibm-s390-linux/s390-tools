// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023
//
//

use clap::Parser;
use lazy_static::lazy_static;

/// The default pvapconfig config file
pub const PATH_DEFAULT_CONFIG_FILE: &str = "/etc/pvapconfig.yaml";

/// Command line interface for pvapconfig
#[derive(Parser, Clone)]
pub struct Cli {
    /// Provide a custom config file (overwrites default /etc/pvapconfig.yaml).
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<String>,

    /// Dry run: display the actions but don't actually perform them on the APQNs.
    #[arg(short = 'n', long = "dry-run")]
    pub dryrun: bool,

    /// Enforce strict match: All config entries need to be fulfilled.
    ///
    /// By default it is enough to successfully apply at least one config entry.
    /// With the strict flag enabled, all config entries within a config file
    /// need to be applied successful.
    #[arg(long = "strict")]
    pub strict: bool,

    /// Provide more detailed output.
    #[arg(short, long)]
    pub verbose: bool,

    /// Print version information and exit.
    #[arg(short = 'V', long)]
    pub version: bool,
}

lazy_static! {
    pub static ref ARGS: Cli = Cli::parse();
}

impl Cli {
    /// verbose returns true if the verbose command line option
    /// was given, otherwise false is returned.
    pub fn verbose(&self) -> bool {
        self.verbose
    }

    /// dryrun returns true if the dry-run command line option
    /// was given, otherwise false is returned.
    pub fn dryrun(&self) -> bool {
        self.dryrun
    }

    /// strict returns true if the strict flag was given, otherwise
    /// false is returned.
    pub fn strict(&self) -> bool {
        self.strict
    }
}
