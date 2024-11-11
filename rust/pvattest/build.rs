// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024
// it under the terms of the MIT license. See LICENSE for details.
#![allow(missing_docs)]

use clap::CommandFactory;
use clap_complete::{generate_to, Shell};
use std::env;
use std::io::Error;

include!("src/cli.rs");

fn main() -> Result<(), Error> {
    let outdir = env::var_os("OUT_DIR").unwrap();
    let crate_name = env!("CARGO_PKG_NAME");
    let mut cmd = CliOptions::command();
    for &shell in Shell::value_variants() {
        generate_to(shell, &mut cmd, crate_name, &outdir)?;
    }

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/cli.rs");
    println!("cargo:rerun-if-changed=../utils/src/cli.rs");
    Ok(())
}
