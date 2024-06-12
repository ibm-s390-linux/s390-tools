// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

use std::io::ErrorKind;

use crate::cli::{ListSecretOpt, ListSecretOutputType};
use anyhow::{Context, Error, Result};
use log::{info, warn};
use pv::uv::{ListCmd, SecretList, UvDevice};
use utils::{get_writer_from_cli_file_arg, STDOUT};

const SECRET_LIST_BUF_SIZE: usize = 4;

/// Do a List Secrets UVC
pub fn list_uvc(uv: &UvDevice) -> Result<SecretList> {
    let mut cmd = ListCmd::with_pages(SECRET_LIST_BUF_SIZE);
    let more_data = match uv.send_cmd(&mut cmd) {
        Ok(v) => Ok(v),
        Err(pv::PvCoreError::Io(e)) if e.kind() == ErrorKind::InvalidInput => {
            info!("Uvdevice does not suport longer list. Fallback to one page list.");
            cmd = ListCmd::default();
            uv.send_cmd(&mut cmd)
        }
        Err(e) => Err(e),
    }?
    .more_data();
    if more_data {
        warn!("The secret list contains more data but the uvdevice cannot show all.");
    }

    cmd.try_into().map_err(Error::new)
}

/// Do a List Secrets UVC and output the list in the requested format
pub fn list(opt: &ListSecretOpt) -> Result<()> {
    let uv = UvDevice::open()?;
    let secret_list = list_uvc(&uv)?;
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
