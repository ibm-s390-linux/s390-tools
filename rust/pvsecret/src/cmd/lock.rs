// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

use anyhow::Result;
use log::warn;
use pv::uv::{LockCmd, UvDevice};

/// Do a Lock Secret Store UVC
pub fn lock() -> Result<()> {
    UvDevice::open()?.send_cmd(&mut LockCmd)?;
    warn!("Successfully locked secret store");
    Ok(())
}
