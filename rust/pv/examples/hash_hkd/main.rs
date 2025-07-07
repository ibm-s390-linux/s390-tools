#![allow(missing_docs)]

use pv::request::EcPubKeyCoord;
use pv_core::misc::encode_hex;
use s390_pv as pv;

use std::env::args;

use pv::misc::{read_certs, read_file};
use pv::{Error, Result};

fn main() -> Result<()> {
    let hkd = args().nth(1).expect("Expect one Host-key document");
    let hkd_bin = read_file(&hkd, "Host-key document")?;
    let certs = read_certs(hkd_bin).map_err(|source| Error::HkdNotPemOrDer { hkd, source })?;
    let hkd_cert = certs
        .first()
        .expect("Expect at least one certificate in the HKD file");

    let pc: EcPubKeyCoord = hkd_cert
        .public_key()
        .expect("Expected a public key in the Host-key document")
        .try_into()
        .unwrap();

    println!("{}", encode_hex(pc.sha256().unwrap()));
    Ok(())
}
