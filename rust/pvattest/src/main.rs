// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

mod cli;
mod cmd;
mod exchange;

use clap::{CommandFactory, Parser};
use cli::CliOptions;
use log::trace;
use std::process::ExitCode;
use utils::{print_cli_error, print_error, print_version, PvLogger};

use crate::cli::Command;
use crate::cmd::*;

static LOGGER: PvLogger = PvLogger;
const FEATURES: &[&[&str]] = &[cmd::CMD_FN, cmd::UV_CMD_FN];
const EXIT_CODE_ATTESTATION_FAIL: u8 = 2;
const EXIT_CODE_LOGGER_FAIL: u8 = 3;

fn print_version(verbosity: u8) -> anyhow::Result<ExitCode> {
    print_version!(verbosity, "2024", FEATURES.concat());
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    let cli: CliOptions = match CliOptions::try_parse() {
        Ok(cli) => cli,
        Err(e) => return print_cli_error(e, CliOptions::command()),
    };

    // set up logger/stderr
    if let Err(e) = LOGGER.start(cli.verbosity()) {
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
        Command::Version => print_version(cli.verbosity()),
    };
    match res {
        Ok(c) => c,
        Err(e) => print_error(&e, cli.verbosity()),
    }
}
