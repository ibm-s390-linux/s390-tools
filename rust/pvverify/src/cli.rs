// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2025
use std::sync::OnceLock;

use clap::{ArgAction, Parser};
use utils::CertificateOptions;

static VERSION: OnceLock<String> = OnceLock::new();

#[derive(Parser, Debug)]
#[command(long_version=ver(), disable_version_flag(true))]
/// Tool to verify host-keys
///
/// Tool to verify host-keys. Use this tool to verify the chain of trust for IBM Secure
pub struct CliOptions {
    #[command(flatten)]
    pub certificate_args: CertificateOptions,

    #[arg(long, action=ArgAction::Version)]
    /// Print version information and exit.
    version: (),
}

fn ver() -> &'static str {
    VERSION.get_or_init(|| utils::tools_version_fmt!(2025))
}
