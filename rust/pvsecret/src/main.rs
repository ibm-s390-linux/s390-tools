// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023, 2024

#![allow(missing_docs)]
mod cli;
mod cmd;

use clap::{CommandFactory, Parser};
use cli::{validate_cli, CliOptions, Command};
use log::trace;
use std::process::ExitCode;
use utils::{print_cli_error, print_error, print_version, PvLogger};

static LOGGER: PvLogger = PvLogger;
static EXIT_LOGGER: u8 = 3;
const FEATURES: &[&[&str]] = &[cmd::CMD_FN, cmd::UV_CMD_FN];

fn main() -> ExitCode {
    let cli: CliOptions = match CliOptions::try_parse() {
        Ok(cli) => match validate_cli(&cli) {
            Ok(_) => cli,
            Err(e) => return print_cli_error(e, CliOptions::command()),
        },
        Err(e) => return print_cli_error(e, CliOptions::command()),
    };

    // set up logger/std(out,err)
    let log_level = cli.verbosity.to_level_filter();
    if let Err(e) = LOGGER.start(log_level) {
        // should(TM) never happen
        eprintln!("Logger error: {e:?}");
        return EXIT_LOGGER.into();
    }

    // NOTE trace verbosity is disabled in release builds
    trace!("Trace verbosity, may leak secrets to command-line");
    trace!("Options {cli:?}");

    // perform the command selected by the user
    let res = match &cli.cmd {
        Command::Add(opt) => cmd::add(opt),
        Command::List(opt) => cmd::list(opt),
        Command::Lock => cmd::lock(),
        Command::Create(opt) => cmd::create(opt),
        Command::Version => Ok(print_version!("2024", log_level; FEATURES.concat())),
        Command::Verify(opt) => cmd::verify(opt),
    };

    match res {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => print_error(&e, log_level),
    }
}
