// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use anyhow::Result;
use log::{debug, info};
use pv::{
    misc::{read_certs, read_file},
    request::{openssl::DigestBytes, EcPubKeyCoord},
};
use serde::Serialize;
use std::{fmt::Display, path::Path};
use utils::HexSlice;

use super::CheckState;
use crate::{
    additional::AttestationResult,
    cli::{CheckOpt, HostKeyCheckPolicy},
};

#[derive(Debug, Clone, Copy)]
pub enum HkCheck {
    Image,
    Attest,
}

impl Display for HkCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} public host-key hash",
            match self {
                Self::Image => "image",
                Self::Attest => "attestation",
            }
        )
    }
}

fn load_host_keys<A: AsRef<Path>>(hkds: &[A]) -> Result<Vec<(&Path, DigestBytes)>> {
    let mut hkd_hash = Vec::with_capacity(hkds.len());
    for hkd in hkds {
        let hkd = hkd.as_ref();
        let hk = read_file(hkd, "host-key document")?;
        let certs = read_certs(&hk).map_err(|source| pv::Error::HkdNotPemOrDer {
            hkd: hkd.display().to_string(),
            source,
        })?;
        let ec_coord: EcPubKeyCoord = certs.first().unwrap().public_key()?.as_ref().try_into()?;
        hkd_hash.push((hkd, ec_coord.sha256()?));
    }
    Ok(hkd_hash)
}

fn contains_phkh<'a>(
    hkd_hashes: &[(&'a Path, DigestBytes)],
    phkh: &HexSlice<'_>,
    mode: HkCheck,
    check_enforced: bool,
) -> CheckState<HostKeyCheck<'a>> {
    let hk: Vec<_> = hkd_hashes
        .iter()
        .filter_map(|(path, hash)| match hash.as_ref() == phkh.as_ref() {
            true => Some(*path),
            false => None,
        })
        .collect();

    debug!("HK: {hk:?}");
    match hk.len() {
        0 => CheckState::Err(format!(
            "No given host-key document matches the given {mode}"
        )),
        1 => CheckState::Data(HostKeyCheck::new(check_enforced, hk.first().copied())),
        _ => CheckState::Err(format!(
            "More than one host-key document matches the given {mode}"
        )),
    }
}

#[derive(Debug, Serialize, Default)]
pub struct HostKeyCheck<'a> {
    check_enforced: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<&'a Path>,
}

impl<'a> HostKeyCheck<'a> {
    pub const fn new(check_enforced: bool, hash: Option<&'a Path>) -> Self {
        Self {
            check_enforced,
            hash,
        }
    }

    pub const fn hide(&self) -> bool {
        self.hash.is_none() && !self.check_enforced
    }
}

pub fn host_key_check<'a, 'b>(
    opt: &'a CheckOpt,
    kind: HkCheck,
    att_res: &'b AttestationResult<'b>,
) -> Result<CheckState<HostKeyCheck<'a>>> {
    if opt.host_key_documents.is_empty() {
        return Ok(CheckState::Data(HostKeyCheck::default()));
    }

    let check_enforced = opt.host_key_checks.contains(&match kind {
        HkCheck::Image => HostKeyCheckPolicy::BootKeyHash,
        HkCheck::Attest => HostKeyCheckPolicy::AttKeyHash,
    });

    let hkd_hashes = load_host_keys(&opt.host_key_documents)?;

    let res = match att_res
        .add_fields
        .as_ref()
        .and_then(|add_fields| match kind {
            HkCheck::Image => add_fields.image_public_host_key_hash(),
            HkCheck::Attest => add_fields.attestation_public_host_key_hash(),
        }) {
        Some(phkh) => contains_phkh(&hkd_hashes, phkh, kind, check_enforced),
        None if check_enforced => CheckState::Err(format!(
            "The Attestation result does not contain an {kind}, but checking was enabled."
        )),
        None => CheckState::Data(HostKeyCheck::default()),
    };

    info!("✓ Check {kind}");
    Ok(res)
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn check_hash_neq() {
        let hostkey =
            [concat!(env!("CARGO_MANIFEST_DIR"), "/tests/assets/host.pem.crt").to_string()];
        let hash = load_host_keys(&hostkey).unwrap();

        let res = contains_phkh(&hash, &HexSlice::from(&[0; 32]), HkCheck::Image, true);
        assert!(matches!(res, CheckState::Err(_)));
    }

    #[test]
    fn check_hash_mul() {
        let hostkey = [
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/assets/host.pem.crt").to_string(),
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/assets/host.pem.crt").to_string(),
        ];
        let hash = load_host_keys(&hostkey).unwrap();

        let res = contains_phkh(&hash, &HexSlice::from(&hash[0].1), HkCheck::Image, true);
        assert!(matches!(res, CheckState::Err(_)));
    }

    #[test]
    fn check_hash_eq() {
        let hostkey =
            [concat!(env!("CARGO_MANIFEST_DIR"), "/tests/assets/host.pem.crt").to_string()];
        let hash = load_host_keys(&hostkey).unwrap();

        let res = contains_phkh(&hash, &HexSlice::from(&hash[0].1), HkCheck::Image, true);
        assert!(matches!(
            res,
            CheckState::Data(s) if s.hash.unwrap() == Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/assets/host.pem.crt"))
        ))
    }
}
