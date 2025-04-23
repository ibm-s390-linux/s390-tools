// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use std::collections::VecDeque;

use anyhow::{anyhow, bail, Context, Result};
use log::{debug, info, warn};
use pv::{
    misc::open_file,
    misc::write,
    secret::{GuestSecret, RetrievedSecret},
    uv::{RetrieveCmd, SecretEntry, SecretId, SecretList, UvDevice},
};
use utils::get_writer_from_cli_file_arg;

use super::list::list_uvc;
use crate::cli::{RetrInpFmt, RetrOutFmt, RetrSecretOptions};

fn find_secret_by_id(secrets: &SecretList, id: &SecretId) -> Option<SecretEntry> {
    let mut secrets: VecDeque<_> = secrets
        .into_iter()
        .filter(|s| s.id() == id.as_ref())
        .collect();
    let secret = secrets.pop_front();

    if !secrets.is_empty() {
        warn!(
            "There are multiple secrets in the secret store with that id. Indices: {}",
            secrets
                .iter()
                .fold(format!("{}", secret.unwrap().index()), |acc, e| {
                    format!("{acc}, {}", e.index())
                })
        );
    }
    secret.cloned()
}

fn retrieve(id: &SecretId) -> Result<RetrievedSecret> {
    let uv = UvDevice::open()?;
    let secrets = list_uvc(&uv)?;

    let secret = match find_secret_by_id(&secrets, id) {
        Some(s) => s,
        // hash it + try again if it is ASCII-representable
        None => match id.as_ascii() {
            Some(s) => find_secret_by_id(&secrets, &GuestSecret::name_to_id(s)?),
            None => None,
        }
        .ok_or(anyhow!(
            "The UV secret-store has no secret with the ID {id}"
        ))?,
    };

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
        RetrInpFmt::Name => SecretId::from_string(&opt.input),
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
