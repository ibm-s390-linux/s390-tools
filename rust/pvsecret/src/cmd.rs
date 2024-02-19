// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

mod create;
pub use create::create;

mod verify;
pub use verify::verify;

pub const CMD_FN: &[&str] = &["+create", "+verify"];

#[cfg(target_arch = "s390x")]
mod add;
#[cfg(target_arch = "s390x")]
mod list;
#[cfg(target_arch = "s390x")]
mod lock;
#[cfg(target_arch = "s390x")]
mod retr;

// Commands (directly) related to UVCs are only available on s389x
#[cfg(target_arch = "s390x")]
mod uv_cmd {
    pub use super::*;
    pub use add::add;
    pub use list::list;
    pub use lock::lock;
    pub use retr::retr;
    pub const UV_CMD_FN: &[&str] = &["+add", "+lock", "+list"];
}

#[cfg(not(target_arch = "s390x"))]
mod uv_cmd {
    use crate::cli::{AddSecretOpt, ListSecretOpt, RetrSecretOptions};
    use anyhow::{bail, Result};
    macro_rules! not_supp {
        ($name: ident $( ,$opt: ty )?) => {
            pub fn $name($(_: &$opt)?) -> Result<()> {
                bail!("Command only available on s390x")
            }
        };
    }
    not_supp!(add, AddSecretOpt);
    not_supp!(list, ListSecretOpt);
    not_supp!(retr, RetrSecretOptions);
    not_supp!(lock);
    pub const UV_CMD_FN: &[&str] = &[];
}
pub use uv_cmd::*;
