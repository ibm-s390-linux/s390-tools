// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

use super::AddSecretMagic;
use crate::{
    request::MagicValue,
    requires_feat,
    uv::{uv_ioctl, UvCmd, UvDevice},
    Error, Result, PAGESIZE,
};
use std::io::Read;
use std::usize;

/// _List Secrets_ Ultravisor command.
///
/// The List Secrets Ultravisor call is used to list the
/// secrets that are in the secret store for the current SE-guest.
///
#[doc = requires_feat!(uvsecret)]
pub struct ListCmd(Vec<u8>);
impl ListCmd {
    fn with_size(size: usize) -> Self {
        Self(vec![0; size])
    }
}

impl Default for ListCmd {
    fn default() -> Self {
        Self::with_size(PAGESIZE)
    }
}

impl UvCmd for ListCmd {
    fn data(&mut self) -> Option<&mut [u8]> {
        Some(self.0.as_mut_slice())
    }

    fn cmd(&self) -> u64 {
        uv_ioctl(UvDevice::LIST_SECRET_NR)
    }

    fn rc_fmt(&self, _rc: u16, _rrc: u16) -> Option<&'static str> {
        None
    }
}

/// _Add Secret_ Ultravisor command.
///
/// The Add Secret Ultravisor-call is used to add a secret
/// to the secret store for the current SE-guest.
///
#[doc = requires_feat!(uvsecret)]
pub struct AddCmd(Vec<u8>);

impl AddCmd {
    /// Create a new Add Secret command using the provided data.
    ///
    /// # Errors
    ///
    /// This function will return an error if the provided data does not start with the
    /// ['crate::AddSecretRequest'] magic Value.
    pub fn new<R: Read>(bin_add_secret_req: &mut R) -> Result<Self> {
        let mut data = Vec::with_capacity(PAGESIZE);
        bin_add_secret_req.read_to_end(&mut data)?;

        if !AddSecretMagic::starts_with_magic(&data[..6]) {
            return Err(Error::NoAsrcb);
        }
        Ok(Self(data))
    }
}

impl UvCmd for AddCmd {
    fn data(&mut self) -> Option<&mut [u8]> {
        Some(&mut self.0)
    }

    fn cmd(&self) -> u64 {
        uv_ioctl(UvDevice::ADD_SECRET_NR)
    }

    fn rc_fmt(&self, rc: u16, _rrc: u16) -> Option<&'static str> {
        match rc {
            0x0101 => Some("not allowed to modify the secret store"),
            0x0102 => Some("secret store locked"),
            0x0103 => Some("access exception when accessing request control block"),
            0x0104 => Some("unsupported add secret version"),
            0x0105 => Some("invalid request size"),
            0x0106 => Some("invalid number of host-keys"),
            0x0107 => Some("unsupported flags specified"),
            0x0108 => Some("unable to decrypt the request"),
            0x0109 => Some("unsupported secret provided"),
            0x010a => Some("invalid length for the specified secret"),
            0x010b => Some("secret store full"),
            0x010c => Some("unable to add secret"),
            0x010d => Some("dump in progress, try again later"),
            _ => None,
        }
    }
}

/// _Lock Secret Store_ Ultravisor command.
///
/// The Lock Secret Store Ultravisor-call is used to block
/// all changes to the secret store. Upon successful
/// completion of a Lock Secret Store Ultravisor-call, any
/// request to modify the secret store will fail.
///
#[doc = requires_feat!(uvsecret)]
pub struct LockCmd;
impl UvCmd for LockCmd {
    fn cmd(&self) -> u64 {
        uv_ioctl(UvDevice::LOCK_SECRET_NR)
    }

    fn rc_fmt(&self, rc: u16, _rrc: u16) -> Option<&'static str> {
        match rc {
            0x0101 => Some("not allowed to modify the secret store"),
            0x0102 => Some("secret store already locked"),
            _ => None,
        }
    }
}
