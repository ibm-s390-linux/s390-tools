// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use anyhow::Result;
use log::LevelFilter;
use pvimg::error::OwnExitCode;
use utils::print_version;

use crate::cmd;

const FEATURES: &[&[&str]] = &[cmd::CMD_FN];

/// Print the version
pub fn version(filter: LevelFilter) -> Result<OwnExitCode> {
    print_version!("2024", filter; FEATURES.concat());
    Ok(OwnExitCode::Success)
}
