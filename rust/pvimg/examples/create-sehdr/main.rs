// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

#![allow(missing_docs)]
use std::{
    fmt::Display,
    fs::{File, OpenOptions},
    io::{BufReader, Read, Write},
    path::PathBuf,
    str::FromStr,
};

use anyhow::{anyhow, Context, Error};
use clap::{Parser, ValueHint};
use log::{info, warn};
use pv::{
    misc::{decode_hex, open_file, read_certs, read_file, try_parse_u64},
    request::SymKeyType,
    Error as PvError, Result,
};
use pvimg::{
    misc::PSW,
    secured_comp::{ComponentTrait, Layout, SecuredComponentBuilder},
    uvdata::{BuilderTrait, SeHdrBuilder, SeHdrVersion},
};
use utils::{AtomicFile, AtomicFileOperation, HexSlice, PvLogger, VerbosityOptions};

/// Converts the hexstring into a byte vector.
///
/// # Errors
///
/// Raises an error if a non-hex character was found or the length was not a
/// multiple of two.
pub fn decode_hex_str<S: AsRef<str>>(s: S) -> Result<Vec<u8>> {
    let hex_str = s.as_ref();
    let hex_value = if hex_str.starts_with("0x") {
        hex_str.split_at(2).1
    } else {
        hex_str
    };

    Ok(decode_hex(hex_value)?)
}

fn decode_u64_hex_str(s: &str) -> Result<u64> {
    Ok(try_parse_u64(s, "The")?)
}

impl FromStr for ComponentArg {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<_> = s.split(',').collect();
        if parts.len() != 3 {
            return Err(anyhow!("Invalid component format."));
        }
        let path = parts[0].into();
        let addr = try_parse_u64(parts[1], "Invalid address")?;
        let mut tweak =
            decode_hex_str(parts[2]).with_context(|| format!("Invalid tweak {}", parts[2]))?;
        if tweak.len() > SymKeyType::AES_256_XTS_TWEAK_LEN {
            return Err(anyhow!(
                "Invalid tweak because the length of {} is greater than the expected {}.",
                tweak.len(),
                SymKeyType::AES_256_XTS_TWEAK_LEN
            ));
        }
        tweak.resize(SymKeyType::AES_256_XTS_TWEAK_LEN, 0x0);
        Ok(Self { path, addr, tweak })
    }
}

#[derive(Debug, Clone)]
struct ComponentArg {
    path: PathBuf,
    addr: u64,
    tweak: Vec<u8>,
}

impl Display for ComponentArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "component\n\
             Path ......: {:}\n\
            Address ...: {:#0x}\n\
            Tweak .....: {:#}",
            self.path.display(),
            self.addr,
            HexSlice::from(&self.tweak),
        )
    }
}

/// Create a Secure Execution header.
#[derive(Parser, Debug)]
pub struct Args {
    /// Use FILE as the component, ADDR as the component address, and TWEAK as
    /// the component tweak.
    ///
    /// ADDR and TWEAK must be a hex-string. TWEAK is right padded with zero
    /// bytes if the given tweak is not large enough. Can be specified multiple
    /// times and must be used at least once.
    #[arg(short, long = "component", required = true, value_name = "FILE,ADDR,TWEAK", value_hint = ValueHint::FilePath)]
    components: Vec<ComponentArg>,

    /// Use FILE as a host key document.
    ///
    /// Can be specified multiple times and must be used at least once.
    #[arg(short = 'k', long = "host-key", required = true)]
    pub host_key_documents: Vec<PathBuf>,

    /// Plain control flags. Must be a hex value.
    #[arg(long, default_value = "0x10000000")]
    pub pcf: String,

    /// Secret control flags. Must be a hex value.
    #[arg(long, default_value = "0x0")]
    pub scf: String,

    /// PSW address. Must be a hex value.
    #[arg(long, default_value = "0x10000", value_parser=decode_u64_hex_str)]
    pub psw_addr: u64,

    /// PSW mask. Must be a hex value.
    #[arg(long, default_value = "0x0000000180000000", value_parser=decode_u64_hex_str)]
    pub psw_mask: u64,

    /// Customer communication key (CCK) file path.
    #[arg(long)]
    pub cck: Option<PathBuf>,

    /// Secure Execution header output location.
    #[arg(short, long)]
    pub output: PathBuf,

    #[clap(flatten)]
    pub verbosity: VerbosityOptions,
}

#[derive(Debug)]
pub struct Comp {
    pub reader: BufReader<File>,
}

impl Read for Comp {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reader.read(buf)
    }
}

enum CompType {
    Dummy = 1,
}

impl ComponentTrait<CompType> for Comp {
    fn secure_mode(&self) -> bool {
        true
    }

    fn kind(&self) -> CompType {
        CompType::Dummy
    }
}

static LOGGER: PvLogger = PvLogger;

fn main() -> anyhow::Result<()> {
    let mut args = Args::parse();
    let log_level = args.verbosity.to_level_filter();
    LOGGER
        .start(log_level)
        .with_context(|| "Failed to set-up logger")?;

    info!("# Preparing components");
    let mut layout = Layout::new(0x0, SecuredComponentBuilder::COMPONENT_ALIGNMENT_V1)?;

    // Don't store the prepared components anywhere as we're only interested in
    // the hashes.
    let mut writer = std::io::empty();
    let mut secure_comp_builer = SecuredComponentBuilder::new_v1(false)?;

    // Sort components by address in ascending order
    args.components.sort_by(|a, b| a.addr.cmp(&b.addr));
    for component_arg in args.components {
        info!("## Preparing {}", component_arg);
        let mut comp = Comp {
            reader: BufReader::new(open_file(&component_arg.path)?),
        };

        let comp_addr = component_arg.addr;
        let _ = secure_comp_builer
            .prepare_and_insert_as_secure_component(
                &mut writer,
                &mut layout,
                &mut comp,
                comp_addr,
                component_arg.tweak,
            )
            .with_context(|| {
                format!(
                    "Failed to prepare component '{}'",
                    component_arg.path.display()
                )
            })?;
    }

    info!("\n# Creating Secure Execution Header");
    let addr = args.psw_addr;
    let mask = args.psw_mask;
    let mut builder = SeHdrBuilder::new(
        SeHdrVersion::V1,
        PSW { addr, mask },
        secure_comp_builer.finish()?,
    )?;
    let mut target_pub_keys = vec![];
    for hkd_path in args.host_key_documents {
        info!(
            "Use the file '{}' as a host key document",
            hkd_path.display()
        );
        let hkd_data = read_file(&hkd_path, "host key document")?;
        let certs = read_certs(&hkd_data)?;
        if certs.is_empty() {
            return Err(PvError::NoHkdInFile(hkd_path.display().to_string()).into());
        }

        if certs.len() > 1 {
            warn!("The host key document in '{}' contains more than one certificate! All keys will be used.",
                  hkd_path.display());
        }

        for cert in &certs {
            target_pub_keys.push(cert.public_key()?);
        }
    }
    builder.add_hostkeys(&target_pub_keys)?;

    let pcf = try_parse_u64(&args.pcf, "pcf")?.into();
    let scf = try_parse_u64(&args.scf, "scf")?.into();
    info!(
        "PSW addr ............: {addr:#018x}\n\
         PSW mask ............: {mask:#018x}\n\
         PCF .................: {pcf}\n\
         SCF .................: {scf}"
    );
    builder.with_pcf(&pcf)?;
    builder.with_scf(&scf)?;
    if let Some(cck) = args.cck {
        info!("CCK ................: {}", cck.display());
        builder
            .with_cck(read_file(&cck, "CCK")?.into())
            .with_context(|| format!("Invalid CCK in '{}'", &cck.display()))?;
    }

    let mut output = AtomicFile::new(args.output, &mut OpenOptions::new())?;
    output.write_all(&builder.build()?.as_bytes()?)?;
    Ok(output.finish(AtomicFileOperation::Replace)?)
}
