use crate::cli::VerifyOpt;
use anyhow::{anyhow, Context, Result};
use log::warn;
use pv::misc::{read_certs, read_file};
use pv::{
    request::openssl::pkey::{PKey, Public},
    secret::verify_asrcb_and_get_user_data,
};
use utils::{get_reader_from_cli_file_arg, get_writer_from_cli_file_arg};

/// read the content of a DER or PEM x509 and return the public key
fn read_sgn_key(path: &str) -> Result<PKey<Public>> {
    read_certs(read_file(path, "user-signing key")?)?
        .first()
        .ok_or(anyhow!("File does not contain a X509 certificate"))?
        .public_key()
        .map_err(anyhow::Error::new)
}

pub fn verify(opt: &VerifyOpt) -> Result<()> {
    let mut rd_in = get_reader_from_cli_file_arg(&opt.input)?;
    let mut data_in = Vec::with_capacity(0x1000);
    rd_in
        .read_to_end(&mut data_in)
        .with_context(|| format!("Cannot read input file {}", opt.input))?;

    let verify_cert = opt
        .user_cert
        .as_ref()
        .map(|p| read_sgn_key(p))
        .transpose()
        .context("Cannot read user-verification certificate.")?;

    let user_data = verify_asrcb_and_get_user_data(data_in, verify_cert)
        .context("Could not verify the the Add-secret request")?;

    if let Some(user_data) = user_data {
        get_writer_from_cli_file_arg(&opt.output)?
            .write_all(&user_data)
            .with_context(|| format!("Cannot write user data to {}", opt.output))?;
    }
    warn!("Successfully verified the request.");
    Ok(())
}
