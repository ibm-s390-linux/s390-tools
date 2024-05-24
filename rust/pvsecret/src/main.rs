// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023, 2024

mod cli;
mod cmd;

use clap::{CommandFactory, Parser};
use cli::{CliOptions, Command};
use log::trace;
use std::process::ExitCode;
use utils::{print_cli_error, print_error, print_version, PvLogger};

use crate::cli::validate_cli;

static LOGGER: PvLogger = PvLogger;
static EXIT_LOGGER: u8 = 3;
const FEATURES: &[&[&str]] = &[cmd::CMD_FN, cmd::UV_CMD_FN];

fn print_version(verbosity: u8) -> anyhow::Result<()> {
    print_version!(verbosity, "2024", FEATURES.concat());
    Ok(())
}

fn main() -> ExitCode {
    let cli: CliOptions = match CliOptions::try_parse() {
        Ok(cli) => match validate_cli(&cli) {
            Ok(_) => cli,
            Err(e) => return print_cli_error(e, CliOptions::command()),
        },
        Err(e) => return print_cli_error(e, CliOptions::command()),
    };

    // set up logger/std(out,err)
    if let Err(e) = LOGGER.start(cli.verbose) {
        // should(TM) never happen
        eprintln!("Logger error: {e:?}");
        return EXIT_LOGGER.into();
    }

    // NOTE trace verbosity is disabled in release builds
    trace!("Trace verbosity, may leak secrets to command-line");
    trace!("Options {cli:?}");

    if cli.version {
        let _ = print_version(cli.verbose);
        return ExitCode::SUCCESS;
    }

    // perform the command selected by the user
    let res = match &cli.cmd {
        Command::Add(opt) => cmd::add(opt),
        Command::List(opt) => cmd::list(opt),
        Command::Lock => cmd::lock(),
        Command::Create(opt) => cmd::create(opt),
        Command::Version => print_version(cli.verbose),
        Command::Verify(opt) => cmd::verify(opt),
    };

    match res {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => print_error(&e, cli.verbose),
    }
}
