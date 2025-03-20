// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

//! # Library for Secure Execution headers
//!
//! This crate provides functionalities for creating and inspecting Secure
//! Execution headers. It also provides support for preparing arbitrary
//! components as secured components and calculating the PLD, ALD, and TLD of
//! them.
//!
//! ## Secure Execution headers
//! ### Creation
//!
//! [`uvdata::SeHdrBuilder`]
//!
//! ### Serialization and Deserialization
//!
//! [`uvdata::SeHdr`]
//!
//! ## Secured components
//!
//! [`secured_comp::SecuredComponentBuilder`] and
//! [`secured_comp::SecuredComponent`].

#![allow(missing_docs)]

mod pv_utils;

pub mod misc {
    pub const PAGESIZE: usize = 4096;
    pub use crate::pv_utils::{
        bytesize, round_up, serialize_to_bytes, ShortPsw, PSW, PSW_MASK_BA, PSW_MASK_EA,
    };
}

pub mod uvdata {
    pub use crate::pv_utils::{
        AeadPlainDataTrait, BuilderTrait, ComponentMetadataV1, ControlFlagTrait, ControlFlagsTrait,
        FlagData, KeyExchangeTrait, PcfV1, PlaintextControlFlagsV1, ScfV1, SeHdr, SeHdrAadV1,
        SeHdrBinV1, SeHdrBuilder, SeHdrData, SeHdrDataV1, SeHdrPlain, SeHdrVersion, SeHdrVersioned,
        SecretControlFlagsV1, UvDataPlainTrait, UvDataTrait, UvKeyHashesV1,
    };
}

pub mod secured_comp {
    pub use crate::pv_utils::{
        ComponentTrait, Interval, Layout, SecuredComponent, SecuredComponentBuilder,
    };
}

pub mod error {
    pub use crate::pv_utils::{Error, OwnExitCode, PvError, Result};
}
