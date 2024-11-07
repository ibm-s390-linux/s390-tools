// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

mod cli;
mod cmd;
mod exchange;

use clap::{CommandFactory, Parser};
use cli::{CliOptions, Command};
use log::trace;
use std::process::ExitCode;
use utils::{print_cli_error, print_error, print_version, PvLogger};

use crate::cmd::*;

static LOGGER: PvLogger = PvLogger;
const FEATURES: &[&[&str]] = &[cmd::CMD_FN, cmd::UV_CMD_FN];
const EXIT_CODE_ATTESTATION_FAIL: u8 = 2;
const EXIT_CODE_LOGGER_FAIL: u8 = 3;

fn main() -> ExitCode {
    let cli: CliOptions = match CliOptions::try_parse() {
        Ok(cli) => cli,
        Err(e) => return print_cli_error(e, CliOptions::command()),
    };

    // set up logger/stderr
    let log_level = cli.verbosity.to_level_filter();
    if let Err(e) = LOGGER.start(log_level) {
        // should(TM) never happen
        eprintln!("Logger error: {e:?}");
        return EXIT_CODE_LOGGER_FAIL.into();
    }

    trace!("Trace verbosity, may leak secrets to command-line");
    trace!("Options {cli:?}");

    let res = match &cli.cmd {
        Command::Create(opt) => create(opt),
        Command::Perform(opt) => perform(opt),
        Command::Verify(opt) => verify(opt),
        Command::Version => {
            print_version!("2024", log_level; FEATURES.concat());
            Ok(ExitCode::SUCCESS)
        }
    };
    match res {
        Ok(c) => c,
        Err(e) => print_error(&e, log_level),
    }
}
