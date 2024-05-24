// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

use super::ffi::{self, uvio_uvdev_info};
use crate::{
    misc::{Flags, Lsb0Flags64},
    uv::{UvCmd, UvDevice},
    Result,
};
use std::fmt::Display;
use zerocopy::{AsBytes, FromZeroes};

/// Information of supported functions by the uvdevice
///
/// * `supp_uvio_cmds` - supported IOCTLs by this device
/// * `supp_uv_cmds` - supported UVCs corresponding to the IOCTL
///
/// UVIO request to get information about supported request types by this
/// uvdevice and the Ultravisor.
/// Everything is output.
/// If the bit is set in both, `supp_uvio_cmds` and `supp_uv_cmds`,
/// the uvdevice and the Ultravisor support that call.
///
/// Note that bit 0 is always zero for `supp_uv_cmds`
/// as there is no corresponding Info UV-call.
#[derive(Debug)]
pub struct UvDeviceInfo {
    supp_uvio_cmds: Lsb0Flags64,
    supp_uv_cmds: Option<Lsb0Flags64>,
}

impl UvDeviceInfo {
    /// Get information from the uvdevice.
    ///
    /// # Errors
    ///
    /// This function will return an error if the ioctl fails and the error code is not
    /// [`libc::ENOTTY`].
    /// `ENOTTY` is most likely because older uvdevices does not support the info IOCTL.
    /// In that case one can safely assume that the device only supports the Attestation IOCTL.
    /// Therefore this is what this function returns IOCTL support for Attestation and _Data not
    /// available_ for the UV Attestation facility.
    /// To check if the Ultravisor supports the Attestation call check at
    /// `/sys/firmware/uv/query/facilities` and check for bit 28 (Msb0 ordering!)
    pub fn get(uv: &UvDevice) -> Result<Self> {
        let mut cmd = uvio_uvdev_info::new_zeroed();
        match uv.send_cmd(&mut cmd) {
            Ok(_) => Ok(cmd.into()),
            Err(crate::Error::Io(e)) if e.raw_os_error() == Some(libc::ENOTTY) => {
                let mut supp_uvio_cmds = Lsb0Flags64::default();
                supp_uvio_cmds.set_bit(ffi::UVIO_IOCTL_ATT_NR);

                Ok(Self {
                    supp_uvio_cmds,
                    supp_uv_cmds: None,
                })
            }
            Err(e) => Err(e),
        }
    }
}

impl From<uvio_uvdev_info> for UvDeviceInfo {
    fn from(value: uvio_uvdev_info) -> Self {
        Self {
            supp_uvio_cmds: value.supp_uvio_cmds.into(),
            supp_uv_cmds: Some(value.supp_uv_cmds.into()),
        }
    }
}

impl UvCmd for uvio_uvdev_info {
    const UV_IOCTL_NR: u8 = ffi::UVIO_IOCTL_UVDEV_INFO_NR;

    fn data(&mut self) -> Option<&mut [u8]> {
        Some(self.as_bytes_mut())
    }

    fn rc_fmt(&self, _: u16, _: u16) -> Option<&'static str> {
        None
    }
}

fn nr_as_string(nr: u8) -> Option<&'static str> {
    match nr {
        ffi::UVIO_IOCTL_UVDEV_INFO_NR => Some("Info"),
        ffi::UVIO_IOCTL_ATT_NR => Some("Attestation"),
        ffi::UVIO_IOCTL_ADD_SECRET_NR => Some("Add Secret"),
        ffi::UVIO_IOCTL_LIST_SECRETS_NR => Some("List Secrets"),
        ffi::UVIO_IOCTL_LOCK_SECRETS_NR => Some("Lock Secret Store"),
        _ => None,
    }
}

fn print_uvdevice_cmd(nr: u8, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match nr_as_string(nr) {
        Some(s) => write!(f, "{s}"),
        None => write!(f, "Unknown ({nr})"),
    }
}

fn parse_flags(uv_cmds: &Lsb0Flags64, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let supp_cmds: Vec<_> = (0u8..64)
        .filter(|v| -> bool { uv_cmds.is_set(*v) })
        .enumerate()
        .collect();
    let num_supp_cmds = supp_cmds.len();
    if num_supp_cmds == 0 {
        println!("None");
        return Ok(());
    }

    for (n, cmd) in supp_cmds {
        print_uvdevice_cmd(cmd, f)?;
        if n != num_supp_cmds - 1 {
            write!(f, ", ")?;
        }
    }
    writeln!(f)
}
impl Display for UvDeviceInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "uvdevice supports:")?;
        parse_flags(&self.supp_uvio_cmds, f)?;
        writeln!(f, "Ultravisor-calls available:")?;
        match &self.supp_uv_cmds {
            Some(cmds) => parse_flags(cmds, f),
            None => writeln!(f, "Data not available"),
        }
    }
}
