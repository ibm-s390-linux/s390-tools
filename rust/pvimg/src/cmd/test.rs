// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use std::path::{Path, PathBuf};

use anyhow::Result;
use log::{info, warn};
use pv::{
    misc::{open_file, read_certs, read_file},
    FileAccessErrorType, PvCoreError,
};
use pvimg::{
    error::{Error, OwnExitCode, PvError},
    uvdata::{KeyExchangeTrait, SeHdr, UvKeyHashesV1},
};
use utils::HexSlice;

use crate::{cli::TestArgs, log_println};

/// Returns `Ok(true)` if at least one of the hashes is included.
fn hdr_test_target_hashes(hdr: &SeHdr, key_hashes: &Path) -> Result<bool> {
    let file = open_file(key_hashes).map_err(|err| match err {
        PvCoreError::FileAccess {
            ref ty,
            ref path,
            ref source,
        } if matches!(ty, FileAccessErrorType::Open)
            && source.kind() == std::io::ErrorKind::NotFound
            && *path == PathBuf::from(UvKeyHashesV1::SYS_UV_KEYS_ALL) =>
        {
            Error::UnavailableQueryUvKeyHashesSupport { source: err }
        }
        err => Error::PvCore(err),
    })?;
    let hashes = UvKeyHashesV1::read_from_io(file)?;
    let mut contains = hdr.contains_hash(&hashes.pchkh);
    if contains {
        log_println!(
            " ✓ Host key hash {:#} is included",
            HexSlice::from(&hashes.pchkh)
        );
    }
    if hdr.contains_hash(&hashes.pbhkh) {
        log_println!(
            " ✓ Backup host key hash {:#} is included",
            HexSlice::from(&hashes.pbhkh)
        );
        contains = true;
    };

    for hash in hashes.res {
        if hdr.contains_hash(&hash) {
            log_println!(" ✓ Key hash {:#} is included", HexSlice::from(&hash));
            contains = true;
        }
    }

    if !contains {
        warn!(" ✘ None of the key hashes is included");
    }
    Ok(contains)
}

/// Returns `Ok(true)` if at least one of the given public key of the host key
/// documents was used for the image creation or if no host key document was
/// specified.
fn hdr_test_hkd<P>(hdr: &SeHdr, host_key_documents: &[P]) -> Result<bool>
where
    P: AsRef<Path>,
{
    if host_key_documents.is_empty() {
        return Ok(true);
    }

    let mut result = false;
    for path in host_key_documents {
        let hkd_path = path.as_ref();
        let hkd_data = read_file(hkd_path, "host key document")?;
        let certs = read_certs(&hkd_data)?;
        if certs.is_empty() {
            return Err(PvError::NoHkdInFile(hkd_path.display().to_string()).into());
        }

        if certs.len() != 1 {
            warn!("The host key document in '{}' contains more than one certificate! Only the first certificate will be used.",
                  hkd_path.display());
        }

        // Panic: len is == 1 -> unwrap will succeed/not panic
        let cert = certs.first().unwrap();
        if hdr.contains(cert.public_key()?)? {
            result = true;
            log_println!(" ✓ Host key document '{}' is included", hkd_path.display());
        } else {
            log_println!(
                " ✘ Host key document '{}' is not included",
                hkd_path.display()
            );
        }
    }
    Ok(result)
}

pub fn test(opt: &TestArgs) -> Result<OwnExitCode> {
    info!("Testing a Secure Execution image");

    let mut input = open_file(&opt.input.path)?;
    SeHdr::seek_sehdr(&mut input, None)?;
    let hdr = SeHdr::try_from_io(input)?;

    let mut success = hdr_test_hkd(&hdr, &opt.host_key_documents)?;
    if let Some(path) = &opt.key_hashes {
        success = hdr_test_target_hashes(&hdr, path)? && success;
    }

    Ok(if success {
        OwnExitCode::Success
    } else {
        OwnExitCode::GenericError
    })
}
