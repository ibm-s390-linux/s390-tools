// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

//! Provides functionality to manage the UV secret store.
//!
//! Provides functionality to build `add-secret` requests.
//! Also provides interfaces, to dispatch `Add Secret`, `Lock Secret Store`,
//! and `List Secrets` requests,
pub mod asrcb;
pub mod ext_secret;
pub mod guest_secret;
pub mod user_data;
