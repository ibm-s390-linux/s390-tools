// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

mod create;
pub use create::create;

mod verify;
pub use verify::verify;

// Commands (directly) related to UVCs are only available on s389x
#[cfg(target_arch = "s390x")]
mod add;
#[cfg(target_arch = "s390x")]
pub use add::add;

#[cfg(target_arch = "s390x")]
mod list;
#[cfg(target_arch = "s390x")]
pub use list::list;

#[cfg(target_arch = "s390x")]
mod lock;
#[cfg(target_arch = "s390x")]
pub use lock::lock;
