// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

//! # pvimg
//!
//! `pvimg` is a command line utility to create and inspect IBM Secure
//! Execution boot images.
//!
//! Use `pvimg` to create a IBM Secure Execution boot image file, which can
//! be loaded using `zipl` or `QEMU`. The tool can also be used to inspect
//! existing Secure Execution boot images.

mod cli;
mod cmd;
mod se_img;
mod se_img_comps;

use std::{env, process::ExitCode};

use clap::{Command, CommandFactory, Parser};
use cli::{validate_cli, CliOptions, SubCommands};
use log::trace;
use pvimg::error::OwnExitCode;
use utils::{print_cli_error, print_error, PvLogger};

use crate::cli::GenprotimgCliOptions;

static LOGGER: PvLogger = PvLogger;

fn main() -> ExitCode {
    let exe = env::args_os().next().unwrap();
    let (opts, cmd): (CliOptions, Command) = match exe.to_str() {
        // Test if the symlink executable 'genprotimg' was used. If so use the
        // `pvimg create` command directly.
        Some(val) if val.ends_with("genprotimg") => (
            GenprotimgCliOptions::own_parse(),
            GenprotimgCliOptions::command(),
        ),
        _ => (CliOptions::parse(), CliOptions::command()),
    };

    let verbosity = opts.verbose.to_level_filter();
    if let Err(e) = LOGGER.start(verbosity) {
        unreachable!("Logger error: {e:?}");
    }

    match validate_cli(&opts) {
        Ok(opts) => opts,
        Err(e) => {
            let _ = print_cli_error(e, cmd);
            return OwnExitCode::UsageError.into();
        }
    };

    // NOTE trace verbosity is disabled in release builds
    trace!("Trace verbosity, may leak secrets to command-line");
    trace!("Options {opts:?}");

    let res = match &opts.cmd {
        SubCommands::Create(opt) => cmd::create(opt),
        SubCommands::Info(opt) => cmd::info(opt),
        SubCommands::Test(opt) => cmd::test(opt),
        SubCommands::Version => cmd::version(verbosity),
    };

    match res {
        Ok(own_exit_code) => own_exit_code.into(),
        Err(e) => print_error(&e, verbosity),
    }
}
