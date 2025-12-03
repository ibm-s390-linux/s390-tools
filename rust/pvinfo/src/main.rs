// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2025

//! Main function for the PV Info Tool

use anyhow::Result;
use clap::Parser;
use std::io::{self, Write};

mod cli;
mod constants;
mod handlers;
mod io_utils;
mod pvinfo;
mod se_status;
mod strings;

use crate::cli::{CliOptions, Commands, OutputFormat};
use crate::constants::*;
use crate::handlers::handle_supported_flags;
use crate::io_utils::check_uv_exists;
use crate::pvinfo::PvInfo;
use std::path::PathBuf;

fn main() -> Result<()> {
    // Parse CLI arguments and apply post-processing
    let mut cli = CliOptions::parse();
    cli.post_process();
    let base_dir = PathBuf::from(BASE_DIR);
    let query_dir = base_dir.join(QUERY_DIR);
    check_uv_exists()?;
    let mut stdout = io::stdout();
    if cli.version {
        utils::print_version!(2025);
        return Ok(());
    }
    match &cli.command {
        // Handle the supported-flags subcommand
        Some(Commands::SupportedFlags {
            secret,
            attestation,
            header,
        }) => {
            handle_supported_flags(&mut stdout, *secret, *attestation, *header, query_dir)?;
        }
        None => {
            let data = PvInfo::read(&cli, &base_dir, &query_dir);
            // Print output in the requested format
            match cli.format {
                OutputFormat::Human => data.write(&mut stdout)?,
                OutputFormat::Yaml => write!(stdout, "{}", serde_yaml::to_string(&data).unwrap())?,
            }
        }
    }

    Ok(())
}
