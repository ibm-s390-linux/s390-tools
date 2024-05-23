// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

use super::ffi;
use crate::{request::MagicValue, uv::UvCmd, uvsecret::AddSecretMagic, Error, Result, PAGESIZE};
use std::io::Read;

/// _List Secrets_ Ultravisor command.
///
/// The List Secrets Ultravisor call is used to list the
/// secrets that are in the secret store for the current SE-guest.
#[derive(Debug)]
pub struct ListCmd(Vec<u8>);
impl ListCmd {
    fn with_size(size: usize) -> Self {
        Self(vec![0; size])
    }

    /// Create a new list secrets command with a one page capacity
    pub fn new() -> Self {
        Self::with_size(PAGESIZE)
    }
}

impl Default for ListCmd {
    fn default() -> Self {
        Self::new()
    }
}

impl UvCmd for ListCmd {
    const UV_IOCTL_NR: u8 = ffi::UVIO_IOCTL_LIST_SECRETS_NR;

    fn data(&mut self) -> Option<&mut [u8]> {
        Some(self.0.as_mut_slice())
    }

    fn rc_fmt(&self, _rc: u16, _rrc: u16) -> Option<&'static str> {
        None
    }
}

/// _Add Secret_ Ultravisor command.
///
/// The Add Secret Ultravisor-call is used to add a secret
/// to the secret store for the current SE-guest.
#[derive(Debug)]
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

        if data.len() > ffi::UVIO_ADD_SECRET_MAX_LEN {
            return Err(Error::AscrbLarge);
        }

        if !AddSecretMagic::starts_with_magic(&data[..6]) {
            return Err(Error::NoAsrcb);
        }
        Ok(Self(data))
    }
}

impl UvCmd for AddCmd {
    const UV_IOCTL_NR: u8 = ffi::UVIO_IOCTL_ADD_SECRET_NR;

    fn data(&mut self) -> Option<&mut [u8]> {
        Some(&mut self.0)
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
#[derive(Debug)]
pub struct LockCmd;
impl UvCmd for LockCmd {
    const UV_IOCTL_NR: u8 = ffi::UVIO_IOCTL_LOCK_SECRETS_NR;

    fn rc_fmt(&self, rc: u16, _rrc: u16) -> Option<&'static str> {
        match rc {
            0x0101 => Some("not allowed to modify the secret store"),
            0x0102 => Some("secret store already locked"),
            _ => None,
        }
    }
}
