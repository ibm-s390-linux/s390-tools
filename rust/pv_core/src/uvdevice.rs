// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

#![allow(non_camel_case_types)]
use crate::FileAccessErrorType;
use crate::{Error, Result};
use log::debug;
use std::{
    convert::TryInto,
    ffi::c_ulong,
    fs::File,
    os::unix::prelude::{AsRawFd, RawFd},
};

#[cfg(not(test))]
use ::libc::ioctl;
#[cfg(test)]
use test::mock_libc::ioctl;

/// Contains the rust representation of asm/uvdevice.h
/// from kernel version: 6.5 verify
mod ffi;
mod info;
mod test;
pub(crate) use ffi::uv_ioctl;
pub mod attest;
pub mod secret;
pub mod secret_list;

pub use info::UvDeviceInfo;

/// User data for the attestation UVC
pub type AttestationUserData = [u8; ffi::UVIO_ATT_USER_DATA_LEN];

/// Configuration Unique Id of the Secure Execution guest
pub type ConfigUid = [u8; ffi::UVIO_ATT_UID_LEN];

/// Bitflags as used by the Ultravisor in MSB0 ordering
///
/// Wraps an u64 to set/get individual bits
pub type UvFlags = crate::misc::Msb0Flags64;

/// Fire an ioctl.
///
/// # Safety:
/// Raw fd must point to an open file
fn ioctl_raw(raw_fd: RawFd, cmd: c_ulong, cb: &mut IoctlCb) -> Result<()> {
    debug!("calling unsafe fn wrapper uv::ioctl_raw with {raw_fd:#x?}, {cmd:#x?}, {cb:?}");

    let rc;

    // Get the raw pointer and do an ioctl.
    //
    // SAFETY: the passed pointer points to a valid memory region that
    // contains the expected C-struct. The struct outlives this function.
    unsafe {
        rc = ioctl(raw_fd, cmd, cb.as_ptr_mut());
    }

    debug!("ioctl resulted with {cb:?}");
    match rc {
        0 => Ok(()),
        // NOTE io::Error handles all errnos ioctl uses
        _ => Err(std::io::Error::last_os_error().into()),
    }
}

/// Converts UV return codes into human readable error messages
fn rc_fmt<C: UvCmd>(rc: u16, rrc: u16, cmd: &mut C) -> &'static str {
    let s = match (rc, rrc) {
        (0x0000, _) => Some("invalid rc"),
        (0x0002, _) => Some("invalid UV command"),
        (0x0005, _) => Some("request has an invalid size"),
        (0x0030, _) => Some("home address space control bit has R-bit set to one"),
        (0x0031, _) => Some("access exception"),
        (0x0032, _) => Some("request contains virtual address translating to an invalid address"),
        (UvDevice::RC_MORE_DATA, _) => unreachable!("This is no Error!!!!"),
        (UvDevice::RC_SUCCESS, _) => unreachable!("This is no Error!!!!"),

        _ => cmd.rc_fmt(rc, rrc),
    };
    s.unwrap_or("unexpected error-code")
}

/// Ultravisor Command.
///
/// Implementers provide information on the specific Ultravisor command metadata and content.
/// API users do not need to interact directly with any functions provided by this trait and refer
/// to the specialized access and tweaking functionalities of the specific command.
pub trait UvCmd {
    /// The UV IOCTL number of the UV call
    const UV_IOCTL_NR: u8;
    /// Returns the uvdevice IOCTL command that his command uses.
    ///
    /// # Returns
    ///
    /// The IOCTL cmd for this UvCmd usually something like `uv_ioctl!(CMD_NR)`
    fn cmd(&self) -> u64 {
        uv_ioctl(Self::UV_IOCTL_NR)
    }
    /// Converts UV return codes into human readable error messages
    ///
    /// # Note for implementations
    ///
    /// No need to handle `0x0000, 0x0001, 0x0002, 0x0005, 0x0030, 0x0031, 0x0032, 0x0100`
    fn rc_fmt(&self, rc: u16, rrc: u16) -> Option<&'static str>;

    /// Returns data used by this command if available.
    fn data(&mut self) -> Option<&mut [u8]> {
        None
    }
}

/// [`UvDevice`] IOCTL control block.
#[derive(Debug)]
struct IoctlCb(ffi::uvio_ioctl_cb);
impl IoctlCb {
    fn new(data: Option<&mut [u8]>) -> Result<Self> {
        let (data_raw, data_size) = match data {
            Some(data) => (
                data.as_mut_ptr(),
                data.len()
                    .try_into()
                    .map_err(|_| Error::Specification("passed data too large".to_string()))?,
            ),
            None => (std::ptr::null_mut(), 0),
        };

        Ok(Self(ffi::uvio_ioctl_cb {
            flags: 0,
            uv_rc: 0,
            uv_rrc: 0,
            argument_addr: data_raw as u64,
            argument_len: data_size,
            reserved14: [0; 44],
        }))
    }

    fn rc(&self) -> u16 {
        self.0.uv_rc
    }

    fn rrc(&self) -> u16 {
        self.0.uv_rrc
    }

    fn as_ptr_mut(&mut self) -> *mut ffi::uvio_ioctl_cb {
        &mut self.0 as *mut _
    }
}

/// The Ultravisor has two codes that represent a successful execution.
/// These are represented by this enum.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UvcSuccess {
    /// Command executed successfully
    RC_SUCCESS = UvDevice::RC_SUCCESS,
    /// Command executed successfully, but there is more data available and the buffer was to small
    /// to hold it all. The returned data is still valid.
    RC_MORE_DATA = UvDevice::RC_MORE_DATA,
}

/// The UvDevice is a (virtual) device on s390 machines to send Ultravisor commands(UVCs) from
/// userspace.
///
/// On s390 machines with Ultravisor enabled (Secure Execution guest & hosts) the device at
/// `/dev/uv` will accept ioctls.
///
/// # Example
///
/// Use a implementation of [`UvCmd`] to send a specific Ultravisor command to the uvdevice to
/// forward to Firmware.
///
/// ```rust,no_run
/// # use s390_pv_core::uv::UvDevice;
/// # use s390_pv_core::uv::AddCmd;
/// # use std::fs::File;
/// # fn main() -> s390_pv_core::Result<()> {
/// let mut file = File::open("request")?;
/// let uv = UvDevice::open()?;
/// let mut cmd = AddCmd::new(&mut file)?;
/// uv.send_cmd(&mut cmd)?;
/// # Ok(())
/// # }
/// // do something with the result
/// ```
#[derive(Debug)]
pub struct UvDevice(File);

impl UvDevice {
    const PATH: &'static str = "/dev/uv";
    const RC_MORE_DATA: u16 = 0x0100;
    const RC_SUCCESS: u16 = 0x0001;

    /// Open the uvdevice located at `/dev/uv`
    ///
    /// # Errors
    ///
    /// This function will return an error if the device file cannot be opened.
    pub fn open() -> Result<Self> {
        Ok(Self(
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(UvDevice::PATH)
                .map_err(|e| Error::FileAccess {
                    ty: FileAccessErrorType::Open,
                    path: (UvDevice::PATH).into(),
                    source: e,
                })?,
        ))
    }

    /// Send an Ultravisor Command via this uvdevice.
    ///
    /// This works by sending an IOCTL to the uvdevice.
    ///
    /// # Errors
    ///
    /// This function will return an error if the IOCTL fails or the Ultravisor does not report
    /// a success.
    ///
    /// # Returns
    ///
    /// [`UvcSuccess`] if the UVC executed successfully
    pub fn send_cmd<C: UvCmd>(&self, cmd: &mut C) -> Result<UvcSuccess> {
        let mut cb = IoctlCb::new(cmd.data())?;
        ioctl_raw(self.0.as_raw_fd(), cmd.cmd(), &mut cb)?;

        match (cb.rc(), cb.rrc()) {
            (Self::RC_SUCCESS, _) => Ok(UvcSuccess::RC_SUCCESS),
            (Self::RC_MORE_DATA, _) => Ok(UvcSuccess::RC_MORE_DATA),
            (rc, rrc) => Err(Error::Uv {
                rc,
                rrc,
                msg: rc_fmt(rc, rrc, cmd),
            }),
        }
    }
}
