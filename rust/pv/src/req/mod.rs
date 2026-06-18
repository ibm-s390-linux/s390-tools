// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp.
//! Request encryption and key management for IBM Z Ultravisor.
//!
//! This module provides functionality for creating and encrypting requests to the
//! IBM Z Ultravisor, including host key management, keyslot encryption, and request
//! context handling.

mod context;
mod ec_coord;
mod encrypt;
mod header;
mod keyslot;
mod request;

// Re-export public types
pub use context::ReqEncrCtx;
pub use ec_coord::EcPubKeyCoord;
pub use encrypt::{Aad, Encrypt};
pub use keyslot::Keyslot;
pub use request::{BinReqValues, Request};
