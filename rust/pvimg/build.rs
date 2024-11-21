// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024
// it under the terms of the MIT license. See LICENSE for details.
#![allow(missing_docs)]

use std::io::Error;

use clap_complete::{generate_to, Shell};

include!("src/cli.rs");

fn main() -> Result<(), Error> {
    let outdir = env::var_os("OUT_DIR").unwrap();
    let crate_name = env!("CARGO_PKG_NAME");
    for &shell in Shell::value_variants() {
        for (name, mut cmd) in [
            (crate_name, CliOptions::command()),
            ("genprotimg", GenprotimgCliOptions::command()),
        ] {
            generate_to(shell, &mut cmd, name, &outdir)?;
        }
    }

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/cli.rs");
    println!("cargo:rerun-if-changed=../utils/src/cli.rs");
    Ok(())
}
