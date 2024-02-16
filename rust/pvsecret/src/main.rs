// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

mod cli;
mod cmd;

use clap::CommandFactory;
use clap::Parser;
use cli::{CliOptions, Command};
use log::trace;
use pv::misc::PvLogger;
use std::process::ExitCode;
use utils::release_string;

use crate::cli::validate_cli;

static LOGGER: PvLogger = PvLogger;
static EXIT_LOGGER: u8 = 3;
const FEATURES: &[&[&str]] = &[cmd::CMD_FN, cmd::UV_CMD_FN];

fn print_error(e: anyhow::Error, verbosity: u8) -> ExitCode {
    if verbosity > 0 {
        // Debug formatter also prints the whole error stack
        // So only print it when on verbose
        eprintln!("error: {e:?}")
    } else {
        eprintln!("error: {e}")
    };
    ExitCode::FAILURE
}

fn print_cli_error(e: clap::Error) -> ExitCode {
    let ret = if e.use_stderr() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    };
    //Ignore any errors during printing of the error
    let _ = e.format(&mut CliOptions::command()).print();
    ret
}

fn print_version(verbosity: u8) -> anyhow::Result<()> {
    println!(
        "{} version {}\nCopyright IBM Corp. 2023",
        env!("CARGO_PKG_NAME"),
        release_string!()
    );
    if verbosity > 0 {
        FEATURES.concat().iter().for_each(|f| print!("{f} "));
        println!("(compiled)");
        println!(
            "\n{}-crate {}",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        );
        println!("{}", pv::crate_info());
    }
    Ok(())
}

fn main() -> ExitCode {
    let cli: CliOptions = match CliOptions::try_parse() {
        Ok(cli) => match validate_cli(&cli) {
            Ok(_) => cli,
            Err(e) => return print_cli_error(e),
        },
        Err(e) => return print_cli_error(e),
    };

    // set up logger/std(out,err)
    if let Err(e) = LOGGER.start(cli.verbose) {
        //should(TM) never happen
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
        Err(e) => print_error(e, cli.verbose),
    }
}
