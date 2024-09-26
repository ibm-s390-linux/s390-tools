// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use clap::Parser;

use crate::msa::InstructionKind;

#[derive(Clone, PartialEq, clap::ValueEnum, Default)]
pub enum Format {
    /// Human-focused, non-parsable output format
    #[default]
    Human,

    /// Use JSON format
    Json,
}

/// Command line interface to get information about CP Assist for Cryptographic Functions (CPACF)
#[derive(Parser)]
pub struct Cli {
    /// Print version information and exit
    #[arg(short, long, exclusive(true))]
    pub version: bool,

    /// Provide information about the Message Security Assist (MSA)
    ///
    /// Shows which MSA levels are available and how many functions of the ones introduced by
    /// this level are available.
    /// Compatible with option -f/--functions to list all functions under the corresponding MSA
    /// level.
    #[arg(short, long, conflicts_with("quiet"))]
    pub msa: bool,

    /// Shows available functions sorted by instructions
    ///
    /// Provides information about the subfunctions of an instruction.
    /// Functions not known to cpacfinfo are displayed as "UNKNOWN".
    #[arg(short, long)]
    pub functions: bool,

    /// Filter instructions to provide in output
    ///
    /// Multiple instructions can be supplied separated by "," to only show the supllied
    /// instructions in the output.
    #[arg(short, long, num_args = 1.., value_delimiter = ',')]
    pub instructions: Vec<InstructionKind>,

    /// Shows available functions
    ///
    /// Adds available functions to subfunction output.
    #[arg(short, long)]
    pub available: bool,

    /// Shows functions that are not available
    ///
    /// Adds non-available functions to subfunction output.
    #[arg(short, long = "not-available")]
    pub not_available: bool,

    /// Suppresses the Query Authentication Information output of Instructions
    ///
    /// By default cpacfinfo outputs the Query Authentication Information for every Instruction.
    /// To keep outputs of other options clean and minimal this can be disabled with this
    /// option.
    #[arg(short, long)]
    pub quiet: bool,

    /// Converts human readable output to JSON format
    ///
    /// Default is human to produce human readable output. When set to json will produce json
    /// output.
    #[arg(long, value_enum, default_value_t)]
    pub format: Format,
}
