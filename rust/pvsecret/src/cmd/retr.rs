// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use std::collections::VecDeque;
use std::fmt::Display;

use anyhow::{anyhow, bail, Context, Result};
use log::{debug, info, warn};
use pv::misc::{open_file, write};
use pv::secret::{GuestSecret, RetrievedSecret};
use pv::uv::{RetrieveCmd, SecretEntry, SecretId, SecretList, UvDevice};
use utils::get_writer_from_cli_file_arg;

use super::list::list_uvc;
use crate::cli::{RetrInpFmt, RetrOutFmt, RetrSecretOptions, RetrSecretOptionsComb};

enum Value {
    Id(SecretId),
    Idx(u16),
}

impl Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::Id(id) => write!(f, "ID {id}"),
            Value::Idx(idx) => write!(f, "index {idx}"),
        }
    }
}

impl TryFrom<&RetrSecretOptionsComb<'_>> for Value {
    type Error = anyhow::Error;

    fn try_from(opt: &RetrSecretOptionsComb) -> Result<Self> {
        match opt.inform {
            RetrInpFmt::Yaml => match serde_yaml::from_reader(&mut open_file(opt.input)?)? {
                GuestSecret::Retrievable { id, .. } => Ok(Self::Id(id)),
                gs => bail!("The file contains a {gs}-secret, which is not retrievable."),
            },
            RetrInpFmt::Hex => serde_yaml::from_str(opt.input)
                .context("Cannot parse SecretId information")
                .map(Self::Id),
            RetrInpFmt::Name => Ok(Self::Id(SecretId::from_string(opt.input))),
            RetrInpFmt::Idx => opt
                .input
                .parse()
                .context("Invalid index value")
                .map(Self::Idx),
        }
    }
}

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

fn retrieve(value: Value) -> Result<RetrievedSecret> {
    let uv = UvDevice::open()?;
    let secrets = list_uvc(&uv)?;

    let entry = match &value {
        Value::Id(id) => {
            match find_secret_by_id(&secrets, id) {
                Some(s) => Some(s),
                // hash it + try again if it is ASCII-representable
                None => match id.as_ascii() {
                    Some(s) => find_secret_by_id(&secrets, &GuestSecret::name_to_id(s)?),
                    None => None,
                },
            }
        }
        Value::Idx(idx) => secrets.into_iter().find(|e| &e.index() == idx),
    }
    .ok_or(anyhow!(
        "The UV secret-store has no secret with the {value}"
    ))?;

    info!("Try to retrieve secret at index: {}", entry.index());
    debug!("Try to retrieve: {entry:?}");

    let mut uv_cmd = RetrieveCmd::from_entry(entry)?;
    uv.send_cmd(&mut uv_cmd)?;

    Ok(RetrievedSecret::from_cmd(uv_cmd))
}

pub fn retr(opt: &RetrSecretOptions) -> Result<()> {
    let opt_comb = RetrSecretOptionsComb::from(opt);
    let mut output = get_writer_from_cli_file_arg(opt_comb.output)?;
    let retr_secret = retrieve((&opt_comb).try_into()?)
        .context("Could not retrieve the secret from the UV secret store.")?;

    let out_data = match opt.outform {
        RetrOutFmt::Bin => retr_secret.into_bytes(),
        RetrOutFmt::Pem => retr_secret.to_pem()?.into_bytes(),
    };
    write(
        &mut output,
        out_data.value(),
        opt_comb.output,
        "IBM Protected Key",
    )?;
    Ok(())
}
