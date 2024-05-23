// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

// DO NOT USE ANY OF THESE ITEMS IN PRODUCTION CODE
// USED FOR INTERNAL UNIT AND FVT TESTING ONLY!!!
use openssl::{
    bn::BigNum,
    ec::{EcGroup, EcKey},
    error::ErrorStack,
    nid::Nid,
    pkey::{PKey, Private, Public},
    x509::{X509Crl, X509},
};
use std::{
    fs,
    path::{Path, PathBuf},
};

/// TEST ONLY! Loads the specified asset into the binary at compile time.
///
/// For testing-assets only!
/// The asset must be present at `{crate}/test/assets/{file}`
#[doc(hidden)]
#[macro_export]
macro_rules! get_test_asset {
    ($file:expr) => {
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/assets/", $file))
    };
}

pub fn get_cert_asset_path<P: AsRef<Path>>(path: P) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("assets");
    p.push("cert");
    p.push(path);
    println!("CERT path: {}", p.to_str().unwrap());
    p
}

/// TEST ONLY! Load an cert
///
/// panic on errors
pub fn get_cert_asset<P: AsRef<Path>>(path: P) -> Vec<u8> {
    let p = get_cert_asset_path(path);
    fs::read(p).unwrap()
}

/// TEST ONLY! Load cert found in the asset path
///
/// panic on errors
pub fn load_gen_cert<P: AsRef<Path>>(asset_path: P) -> X509 {
    let buf = get_cert_asset(asset_path);
    let mut cert = X509::from_der(&buf)
        .map(|crt| vec![crt])
        .or_else(|_| X509::stack_from_pem(&buf))
        .unwrap();
    assert_eq!(cert.len(), 1);
    cert.pop().unwrap()
}

/// TEST ONLY! Load the CRL found in the asset path
///
/// panic on errors
pub fn load_gen_crl<P: AsRef<Path>>(asset_path: P) -> X509Crl {
    let buf = get_cert_asset(asset_path);

    X509Crl::from_der(&buf)
        .or_else(|_| X509Crl::from_pem(&buf))
        .unwrap()
}

/// TEST ONLY! Get a fixed private/public pair and a fixed public key
///
/// Intended for TESTING only. All parts of the key including the private key are checked in git and
/// visible for the public
pub fn get_test_keys() -> (PKey<Private>, PKey<Public>) {
    let pub_key = get_test_asset!("keys/public_cust.bin");
    let priv_key = get_test_asset!("keys/private_cust.bin");
    let host_key = get_test_asset!("keys/host.pem.crt");

    assert_eq!(pub_key.len(), 160);
    assert_eq!(priv_key.len(), 80);

    let cust_key = get_keypair(pub_key, priv_key).unwrap();
    let host_key = X509::from_pem(host_key).unwrap().public_key().unwrap();

    (cust_key, host_key)
}

fn read_ecdh_pubkey(coords: &[u8]) -> Result<PKey<Public>, ErrorStack> {
    assert!(coords.len() == 160);
    let x = BigNum::from_slice(&coords[..80])?;
    let y = BigNum::from_slice(&coords[80..])?;
    let group = EcGroup::from_curve_name(Nid::SECP521R1)?;

    let key = EcKey::from_public_key_affine_coordinates(&group, &x, &y)?;
    PKey::from_ec_key(key)
}

fn get_keypair(pub_coords: &[u8], priv_num: &[u8]) -> Result<PKey<Private>, ErrorStack> {
    assert!(pub_coords.len() == 160);
    assert!(priv_num.len() == 80);
    let pub_key = read_ecdh_pubkey(pub_coords)?;
    let pub_key = pub_key.ec_key()?;
    let pub_key = pub_key.public_key();
    let priv_key = BigNum::from_slice(priv_num)?;
    let group = EcGroup::from_curve_name(Nid::SECP521R1)?;

    let key = EcKey::from_private_components(&group, &priv_key, pub_key)?;
    key.check_key()?;
    PKey::from_ec_key(key)
}
