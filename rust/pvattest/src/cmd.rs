// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024
//
pub mod check;
pub mod create;
#[cfg(target_arch = "s390x")]
pub mod perform;
pub mod verify;

pub use check::check;
pub use create::create;
pub use verify::verify;

pub const CMD_FN: &[&str] = &["+create", "+verify"];
// s390 branch
#[cfg(target_arch = "s390x")]
mod uv_cmd {
    pub use super::perform::perform;
    pub const UV_CMD_FN: &[&str] = &["+perform"];
}

// non s390-branch
#[cfg(not(target_arch = "s390x"))]
mod uv_cmd {
    use std::process::ExitCode;

    use anyhow::{bail, Result};

    pub fn perform(_: &crate::cli::PerformAttOpt) -> Result<ExitCode> {
        bail!("Command only available on s390x")
    }
    pub const UV_CMD_FN: &[&str] = &[];
}
pub use uv_cmd::*;
