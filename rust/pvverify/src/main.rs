// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2025
#![allow(missing_docs)]

mod cli;

use anyhow::Result;
use clap::Parser;
use log::{info, LevelFilter};
use utils::PvLogger;

static LOGGER: PvLogger = PvLogger;

fn main() -> Result<()> {
    LOGGER.start(LevelFilter::Trace)?;
    cli::CliOptions::parse()
        .certificate_args
        .get_verified_hkds("info")?;
    info!("Host-key documents verified.");
    Ok(())
}
