// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

use crate::cli::{ListSecretOpt, ListSecretOutputType};
use anyhow::{Context, Result};
use log::warn;
use pv::{
    misc::{get_writer_from_cli_file_arg, STDOUT},
    uv::{ListCmd, SecretList, UvDevice, UvcSuccess},
};

/// Do a List Secrets UVC
pub fn list(opt: &ListSecretOpt) -> Result<()> {
    let uv = UvDevice::open()?;
    let mut cmd = ListCmd::default();
    match uv.send_cmd(&mut cmd)? {
        UvcSuccess::RC_SUCCESS => (),
        UvcSuccess::RC_MORE_DATA => warn!("There is more data available than expected"),
    };

    let secret_list: SecretList = cmd.try_into()?;
    let mut wr_out = get_writer_from_cli_file_arg(&opt.output)?;

    match &opt.format {
        ListSecretOutputType::Human => {
            write!(wr_out, "{secret_list}").context("Cannot generate output")?
        }
        ListSecretOutputType::Yaml => write!(wr_out, "{}", serde_yaml::to_string(&secret_list)?)
            .context("Cannot generate yaml output")?,
        ListSecretOutputType::Bin => secret_list
            .encode(&mut wr_out)
            .context("Cannot encode secret list")?,
    }
    wr_out.flush()?;

    if opt.output != STDOUT {
        warn!(
            "Successfully wrote the list of secrets to '{}'",
            &opt.output
        );
    }
    Ok(())
}
