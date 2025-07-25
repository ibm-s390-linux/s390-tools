// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use std::path::PathBuf;

use anyhow::Result;
use log::info;
use pv::{misc::read_file, request::Confidential};

use crate::cli::{CreateBootImageExperimentalArgs, UserKeys};

#[macro_export]
/// Makes it easier to
macro_rules! log_println {
    ($($arg:tt)+) => { warn!($($arg)+) };
}

pub struct UserProvidedKeys {
    pub(crate) cck: Option<(PathBuf, Confidential<Vec<u8>>)>,
    pub(crate) components_key: Option<(PathBuf, Confidential<Vec<u8>>)>,
    pub(crate) aead_key: Option<(PathBuf, Confidential<Vec<u8>>)>,
}

/// Reads all user provided keys.
pub fn read_user_provided_keys(
    keys: &UserKeys,
    experimental_args: &CreateBootImageExperimentalArgs,
) -> Result<UserProvidedKeys> {
    let components_key = {
        match &experimental_args.x_comp_key {
            Some(key_path) => {
                info!(
                    "Use file '{}' as the image components protection key",
                    key_path.display()
                );
                Some((
                    key_path.to_owned(),
                    Confidential::new(read_file(key_path, "image components key")?),
                ))
            }
            None => None,
        }
    };
    let aead_key = {
        match &keys.hdr_key {
            Some(key_path) => {
                info!(
                    "Use file '{}' as the Secure Execution header protection",
                    key_path.display()
                );
                Some((
                    key_path.to_owned(),
                    Confidential::new(read_file(
                        key_path,
                        "Secure Execution header protection key",
                    )?),
                ))
            }
            None => None,
        }
    };

    let cck = {
        match &keys.cck {
            Some(key_path) => {
                info!(
                    "Use file '{}' as the customer communication key (CCK)",
                    key_path.display()
                );
                Some((
                    key_path.to_owned(),
                    (Confidential::new(read_file(key_path, "customer communication key (CCK)")?)),
                ))
            }
            None => None,
        }
    };

    Ok(UserProvidedKeys {
        cck,
        components_key,
        aead_key,
    })
}
