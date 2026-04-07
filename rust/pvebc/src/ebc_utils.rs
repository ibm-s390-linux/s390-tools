// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp.

use anyhow::{bail, Context, Result};
use pv_core::misc::open_file;
use std::{io::Read, path::Path};

/// Length of the MAC tag in bytes (last 16 bytes of AddSecretRequest files)
pub const MAC_TAG_LEN: usize = 16;

/// Opens a file and returns a boxed reader
pub fn get_reader_from_filepath<P: AsRef<Path>>(filepath: P) -> Result<Box<dyn Read>> {
    Ok(Box::new(open_file(filepath)?))
}

/// Get reader from &Path with additional context on error
pub fn get_reader(filepath: &Path) -> Result<Box<dyn Read>> {
    get_reader_from_filepath(filepath)
        .with_context(|| format!("unable to get reader from {:?}", filepath))
}

/// Read all data from a reader into a Vec<u8>
pub fn get_data(rd_in: &mut Box<dyn Read>) -> Result<Vec<u8>> {
    let mut data_in = Vec::new();
    rd_in
        .read_to_end(&mut data_in)
        .context("Cannot read input file")?;

    Ok(data_in)
}

/// Extract the MAC tag (last 16 bytes) from an AddSecretRequest file
///
/// # Errors
///
/// Returns an error if:
/// - The file cannot be read
/// - The file is smaller than MAC_TAG_LEN bytes
pub fn get_mac_tag(filepath: &Path) -> Result<Vec<u8>> {
    let mut rd_in = get_reader(filepath)?;
    let data_in = get_data(&mut rd_in)?;

    if data_in.len() < MAC_TAG_LEN {
        bail!(
            "File {:?} too small to contain MAC tag (expected at least {} bytes, got {})",
            filepath,
            MAC_TAG_LEN,
            data_in.len()
        );
    }

    Ok(data_in[data_in.len() - MAC_TAG_LEN..].to_vec())
}
