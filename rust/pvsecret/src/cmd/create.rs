// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023, 2024

use std::path::Path;

use crate::cli::{AddSecretType, CreateSecretFlags, CreateSecretOpt};
use anyhow::{anyhow, bail, Context, Error, Result};
use log::{debug, info, trace, warn};
use pv::{
    misc::{
        decode_hex, open_file, pv_guest_bit_set, read_exact_file, read_file, try_parse_u128,
        try_parse_u64, write,
    },
    request::{
        openssl::pkey::{PKey, Private},
        BootHdrTags, ReqEncrCtx, Request, SymKeyType,
    },
    secret::{AddSecretFlags, AddSecretRequest, AddSecretVersion, ExtSecret, GuestSecret},
    uv::ConfigUid,
};
use serde_yaml::Value;
use utils::get_writer_from_cli_file_arg;

fn write_out<P, D>(path: &P, data: D, ctx: &str) -> pv::Result<()>
where
    P: AsRef<Path>,
    D: AsRef<[u8]>,
{
    let mut wr = get_writer_from_cli_file_arg(path.as_ref())?;
    write(&mut wr, data, path, ctx)?;
    Ok(())
}

/// Prepare an add-secret request
pub fn create(opt: &CreateSecretOpt) -> Result<()> {
    if pv_guest_bit_set() {
        warn!("The system seems to be a Secure Execution guest");
        if !opt.force {
            bail!("Do NOT generate Add-secret requests on a machine where you want to use the secret! Overwrite with '-f'");
        } else {
            warn!("WARNING: Enforcing of generating a request on a Secure Execution guest")
        }
    }

    let mut asrcb = build_asrcb(opt)?;
    debug!("Generated Add-secret request");

    // Add host-key documents
    opt.certificate_args
        .get_verified_hkds("secret")?
        .into_iter()
        .for_each(|k| asrcb.add_hostkey(k));

    debug!("Added all host-keys");

    // build + encrypt the request
    let rq = ReqEncrCtx::random(SymKeyType::Aes256).context("Failed to generate random input")?;
    let ser_asrbc = asrcb.encrypt(&rq)?;
    warn!("Successfully generated the request");
    write_out(&opt.output, ser_asrbc, "add-secret request")?;
    info!("Successfully wrote the request to '{}'", &opt.output);

    write_secret(&opt.secret, &asrcb, &opt.output)
}

/// Read+parse the first key from the buffer.
fn read_private_key(buf: &[u8]) -> Result<PKey<Private>> {
    PKey::private_key_from_der(buf)
        .or_else(|_| PKey::private_key_from_pem(buf))
        .map_err(Error::new)
}

/// Set-up the `add-secret request` from command-line arguments
fn build_asrcb(opt: &CreateSecretOpt) -> Result<AddSecretRequest> {
    debug!("Build add-secret request");

    let secret = match &opt.secret {
        AddSecretType::Meta => GuestSecret::Null,
        AddSecretType::Association {
            name,
            input_secret: Some(p),
            ..
        } => GuestSecret::association(name, read_exact_file(p, "Association secret")?)?,
        AddSecretType::Association {
            name,
            input_secret: None,
            ..
        } => GuestSecret::association(name, None)?,
    };
    trace!("AddSecret: {secret:x?}");

    let mut flags = match &opt.pcf {
        Some(v) => (&try_parse_u64(v, "pcf")?).into(),
        None => AddSecretFlags::default(),
    };
    opt.flags.iter().for_each(|v| match v {
        CreateSecretFlags::DisableDump => flags.set_disable_dump(),
    });
    debug!("FLAGS: {flags:x?}");

    let mut se_hdr = open_file(&opt.hdr)?;
    let mut asrcb = AddSecretRequest::new(
        AddSecretVersion::One,
        secret,
        BootHdrTags::from_se_image(&mut se_hdr)
            .with_context(|| format!("Provided SE-header in '{}' is malformed", &opt.hdr))?,
        flags,
    );

    // Set CUID
    read_cuid(&mut asrcb, opt)?;

    // Set extension secret
    if let Some(path) = &opt.extension_secret {
        asrcb.set_ext_secret(ExtSecret::Simple(
            read_exact_file(path, "extension secret")?.into(),
        ))?;
    } else if let Some(path) = &opt.cck {
        asrcb.set_ext_secret(ExtSecret::Derived(read_exact_file(path, "CCK")?.into()))?;
    }

    // add user data
    let user_data = opt
        .user_data
        .as_ref()
        .map(|p| read_file(p, "user-data"))
        .transpose()?;
    if user_data.as_ref().is_some_and(|data| data.is_empty()) {
        warn!("Added empty user-data file.");
    }

    let user_key = opt
        .user_sign_key
        .as_ref()
        .map(|p| read_file(p, "User-signing key"))
        .transpose()?
        .map(|buf| read_private_key(&buf))
        .transpose()?;

    if user_data.is_some() || user_key.is_some() {
        asrcb.set_user_data(user_data.unwrap_or_default(), user_key)?;
    }
    Ok(asrcb)
}

// Try to extract a Config-UId from a yaml structure
// The cuid field can be embedded in an abritray amount of Mappings
// The function takes the first cuid it founds (width search).
fn try_from_val(val: Value) -> Result<ConfigUid> {
    fn get_cuid_from_mapping(val: &Value, depth: u8) -> Option<String> {
        if depth >= 8 {
            return None;
        }
        match val {
            Value::Mapping(m) if m.contains_key("cuid") => {
                return m.get("cuid").and_then(|v| v.as_str()).map(|s| s.to_owned())
            }
            Value::Mapping(m) => {
                for (_, v) in m {
                    if let Some(v) = get_cuid_from_mapping(v, depth + 1) {
                        return Some(v);
                    }
                }
            }
            _ => return None,
        };
        None
    }
    let cuid = match &val {
        Value::String(s) => Some(s.clone()),
        Value::Mapping(_) => get_cuid_from_mapping(&val, 0),
        _ => None,
    }
    .ok_or(anyhow!("No 'cuid' entry found"))?;
    let cuid = cuid
        .strip_prefix("0x")
        .ok_or(anyhow!("CUID value starts not with 0x".to_string()))?
        .to_owned();
    if cuid.len() != ::std::mem::size_of::<ConfigUid>() * 2 {
        return Err(anyhow!(format!("len invalid ({})", cuid.len())));
    }
    let cuid: ConfigUid = decode_hex(&cuid)?
        .try_into()
        .map_err(|_| anyhow!("Cannot parse hex number".to_string()))?;
    Ok(cuid)
}

fn read_cuid(asrcb: &mut AddSecretRequest, opt: &CreateSecretOpt) -> Result<()> {
    if let Some(path) = &opt.cuid {
        let cuid = match read_exact_file(path, "The CUID-file") {
            Ok(v) => v,
            Err(_) => {
                let buf = read_file(path, "The CUID-file")?;
                let val: Value = serde_yaml::from_slice(&buf).context(
                    "The CUID-file does not contain a 128bit value or a yaml with a 'cuid' field",
                )?;
                try_from_val(val)?
            }
        };
        asrcb.set_cuid(cuid);
    } else if let Some(v) = &opt.cuid_hex {
        asrcb.set_cuid(try_parse_u128(v, "CUID")?);
    }
    Ok(())
}

/// Write the generated secret (if any) to the specified output stream
fn write_secret<P: AsRef<Path>>(
    secret: &AddSecretType,
    asrcb: &AddSecretRequest,
    outp_path: P,
) -> Result<()> {
    if let AddSecretType::Association {
        name,
        stdout,
        output_secret: secret_out,
        ..
    } = secret
    {
        let gen_name: String = name
            .chars()
            .map(|c| if c.is_whitespace() { '_' } else { c })
            .collect();
        let mut gen_path = outp_path
            .as_ref()
            .parent()
            .with_context(|| format!("Cannot open directory of {:?}", outp_path.as_ref()))?
            .to_owned();
        gen_path.push(format!("{gen_name}.yaml"));

        // write non confidential data (=name+id) to a yaml
        let secret_info = serde_yaml::to_string(asrcb.guest_secret())?;
        if stdout.to_owned() {
            println!("{secret_info}");
        } else {
            write_out(&gen_path, secret_info, "association secret info")?;
            debug!(
                "Non-confidential secret information: {:x?}",
                asrcb.guest_secret()
            );
            warn!(
                "Successfully wrote association info to '{}'",
                gen_path.display()
            );
        }

        if let Some(path) = secret_out {
            if let GuestSecret::Association { secret, .. } = asrcb.guest_secret() {
                write_out(path, secret.value(), "Association secret")?
            } else {
                unreachable!("The secret type has to be `association` at this point (bug)!")
            }
            info!("Successfully wrote generated association secret to '{path}'");
        }
    };
    Ok(())
}

#[cfg(test)]
mod test {

    #[test]
    fn read_private_key() {
        let key = include_bytes!("../../../pv/tests/assets/keys/rsa3072key.pem");
        let key = super::read_private_key(key).unwrap();
        assert_eq!(key.rsa().unwrap().size(), 384);
    }

    #[test]
    fn read_private_key_fail() {
        let key = include_bytes!("create.rs");
        let key = super::read_private_key(key);
        assert!(key.is_err());
    }
}
