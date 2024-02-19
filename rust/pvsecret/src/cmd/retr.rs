// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use super::list::list_uvc;
use crate::cli::{RetrInpFmt, RetrOutFmt, RetrSecretOptions};
use anyhow::{anyhow, bail, Context, Result};
use log::{debug, info};
use pv::{
    misc::open_file,
    misc::write,
    secret::{GuestSecret, RetrievedSecret},
    uv::{RetrieveCmd, SecretId, UvDevice},
};
use utils::get_writer_from_cli_file_arg;

fn retrieve(id: &SecretId) -> Result<RetrievedSecret> {
    let uv = UvDevice::open()?;
    let secrets = list_uvc(&uv)?;
    let secret = secrets
        .into_iter()
        .find(|s| s.id() == id.as_ref())
        .ok_or(anyhow!(
            "The UV secret-store has no secret with the ID {id}"
        ))?;

    info!("Try to retrieve secret at index: {}", secret.index());
    debug!("Try to retrieve: {secret:?}");

    let mut uv_cmd = RetrieveCmd::from_entry(secret)?;
    uv.send_cmd(&mut uv_cmd)?;

    Ok(RetrievedSecret::from_cmd(uv_cmd))
}

pub fn retr(opt: &RetrSecretOptions) -> Result<()> {
    let mut output = get_writer_from_cli_file_arg(&opt.output)?;
    let id = match &opt.inform {
        RetrInpFmt::Yaml => match serde_yaml::from_reader(&mut open_file(&opt.input)?)? {
            GuestSecret::Retrievable { id, .. } => id,
            gs => bail!("The file contains a {gs}-secret, which is not retrievable."),
        },
        RetrInpFmt::Hex => {
            serde_yaml::from_str(&opt.input).context("Cannot parse SecretId information")?
        }
    };

    let retr_secret =
        retrieve(&id).context("Could not retrieve the secret from the UV secret store.")?;

    let out_data = match opt.outform {
        RetrOutFmt::Bin => retr_secret.into_bytes(),
        RetrOutFmt::Pem => retr_secret.to_pem()?.into_bytes(),
    };
    write(
        &mut output,
        out_data.value(),
        &opt.output,
        "IBM Protected Key",
    )?;
    Ok(())
}
