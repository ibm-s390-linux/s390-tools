#![allow(missing_docs)]

use anyhow::Context;
use clap::{Parser, ValueEnum, ValueHint};
use log::info;
use pv::{
    misc::{open_file, parse_hex, read_file},
    request::SymKey,
};
use pvimg::{
    error::Result,
    uvdata::{
        KeyExchangeTrait, SeHdr, SeHdrBinV1, SeHdrData, SeHdrDataV1, SeHdrVersioned,
        UvDataPlainTrait, UvDataTrait,
    },
};
use std::{fs::File, io::Write, path::PathBuf};
use utils::{PvLogger, VerbosityOptions};

#[derive(Parser, Debug)]
struct Cli {
    /// Use INPUT as the Secure Execution image.
    #[arg(short, long, value_name = "INPUT", value_hint = ValueHint::FilePath,)]
    infile: PathBuf,

    /// Use INPUT as the Secure Execution image.
    #[arg(short, long, value_name = "OUTPUT", value_hint = ValueHint::FilePath,)]
    outfile: PathBuf,

    /// Use the key in FILE to decrypt the Secure Execution header.
    /// It is the key that was specified with the command line option
    /// '--hdr-key' at the Secure Execution image creation.
    #[arg(long, value_name = "FILE", value_hint = ValueHint::FilePath, alias = "key")]
    hdr_key: PathBuf,

    #[clap(flatten)]
    verbosity: VerbosityOptions,

    /// Hdr Value to tamper with
    #[arg(long, value_enum)]
    tamp: TampVal,
}

#[non_exhaustive]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum TampVal {
    /// ALD.
    AddressListDigest,
    /// PLD.
    PageListDigest,
    /// TLD.
    TweakListDigest,
    /// Change lenght of secure header
    HdrSize,
    /// customer ECDH key
    CustomerPublicKey,
    /// host key hash
    HostKey,
    /// Secret control flags
    SecretControlFlag,
    /// Plaintext control flags
    PlaintextControlFlag,
    /// Number of keyslots
    NumKeySlots,
    /// Size encrypted area
    SizeEncArea,
    /// Number of encrypted pages
    NumEncPages,
}

static LOGGER: PvLogger = PvLogger;

fn main() -> anyhow::Result<()> {
    let opt = Cli::parse();
    LOGGER
        .start(opt.verbosity.to_level_filter())
        .with_context(|| "Failed to set-up logger")?;
    info!("Reading Secure Execution header {}", opt.infile.display());
    let mut input = open_file(&opt.infile)?;

    SeHdr::seek_sehdr(&mut input, None)?;
    let hdr = SeHdr::try_from_io(&mut input)?;
    let mut hdr_encr_v1: SeHdrBinV1 =
        <SeHdrVersioned as TryInto<SeHdrBinV1>>::try_into(hdr.clone().data).expect("SE-header V1");
    let mut decryption_required = false;
    let mut hdr_encr: SeHdr;

    // Tamper with parts of SE header that doesn't require decryption
    match &opt.tamp {
        TampVal::HdrSize => hdr_encr_v1.aad.sehs += 1,
        TampVal::HostKey => hdr_encr_v1.aad.keyslots[0].phkh[..32].copy_from_slice(&[0; 32]),
        TampVal::PlaintextControlFlag => {
            let hex_str = String::from_utf8(
                read_file("/sys/firmware/uv/query/supp_se_hdr_pcf", "input file").unwrap(),
            )
            .expect("PCF support not found");
            let hex = parse_hex(&hex_str);
            let mut hex_pad = [0u8; 8];
            hex_pad[(8 - hex.len())..].copy_from_slice(&hex);
            let supported_pcf: u64 = u64::from_be_bytes(hex_pad);
            hdr_encr_v1.aad.pcf = 0xFFFF_FFFF_FFFF_D5FF - supported_pcf;
        }
        TampVal::NumKeySlots => hdr_encr_v1.aad.nks = 0,
        TampVal::SizeEncArea => hdr_encr_v1.aad.sea = 0,
        _ => decryption_required = true,
    }

    if decryption_required {
        let key = SymKey::try_from_data(
            hdr.key_type(),
            read_file(&opt.hdr_key, "Reading key")?.into(),
        )?;
        let mut hdr_plain = hdr.decrypt(&key)?;
        let mut hdr_v1: SeHdrDataV1 =
            <SeHdrData as TryInto<SeHdrDataV1>>::try_into(hdr_plain.clone().data)
                .expect("SE-header V1");

        // Tamper with the SE header data
        match &opt.tamp {
            TampVal::AddressListDigest => hdr_v1.aad.ald[..8].copy_from_slice(&[0; 8]),
            TampVal::PageListDigest => hdr_v1.aad.pld[..8].copy_from_slice(&[0; 8]),
            TampVal::TweakListDigest => hdr_v1.aad.tld[..8].copy_from_slice(&[0; 8]),
            TampVal::CustomerPublicKey => {
                hdr_v1.aad.cust_pub_key.coord[..160].copy_from_slice(&[0; 160])
            }
            TampVal::SecretControlFlag => hdr_v1.data.value_mut().scf = 0xFFFF_FFFF_FFFF_FFFF,
            TampVal::NumEncPages => hdr_v1.aad.nep = 0,
            _ => {}
        }
        hdr_plain.data = hdr_v1.into();
        hdr_encr = hdr_plain.encrypt(&key)?;
    } else {
        hdr_encr = hdr.clone();
        hdr_encr.data = hdr_encr_v1.clone().into();
    }

    std::fs::copy(&opt.infile, &opt.outfile)?;
    match tamper_image_file(&opt.outfile, hdr_encr) {
        Ok(_) => (),
        Err(err) => {
            std::fs::remove_file(&opt.outfile)?;
            panic!("Could not seek SE header: {}", err);
        }
    };

    Ok(())
}

fn tamper_image_file(outfile: &PathBuf, hdr_encr: SeHdr) -> Result<()> {
    let mut output = File::options().read(true).write(true).open(outfile)?;
    SeHdr::seek_sehdr(&mut output, None)?;
    output.write_all(&hdr_encr.as_bytes()?)?;
    Ok(())
}
