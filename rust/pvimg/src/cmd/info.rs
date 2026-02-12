// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use std::io::Write;

use anyhow::{Context, Result};
use log::{info, warn};
use pv::{
    misc::{open_file, read_file},
    request::SymKey,
};
use pvimg::{
    error::{Error, OwnExitCode},
    uvdata::{EnvelopeSeHdrV1, KeyExchangeTrait, SeH, SeHdr, UvDataTrait},
};

use crate::cli::{InfoArgs, OutputFormatKind, OutputFormatSpec, OutputFormatVariant};

pub fn info(opt: &InfoArgs) -> Result<OwnExitCode> {
    info!(
        "Reading Secure Execution header {}",
        opt.input.path.display()
    );
    let mut img = open_file(&opt.input.path)?;
    let mut output = std::io::stdout();

    SeHdr::seek_sehdr(&mut img, None)?;
    let hdr = SeHdr::try_from_io(&mut img)?;
    let se_hdr = if let Some(key_path) = &opt.hdr_key {
        let key = SymKey::try_from_data(
            hdr.key_type(),
            read_file(key_path, "Reading header protection key")?.into(),
        )
        .map_err(|err| Error::InvalidSeHdrProtectionKey {
            source: Box::new(Error::Pv(err)),
        })?;
        let decrypted_hdr = hdr
            .decrypt(&key)
            .context("Failed to authenticate and decrypt the Secure Execution header")?;
        SeH::DecryptedSeHdr {
            se_hdr: decrypted_hdr,
            verified: true,
        }
    } else {
        warn!("WARNING: The Secure Execution header integrity and authenticity was not verified. Specify '--hdr-key' to authenticate it. Do not trust the data without verification.");
        SeH::SeHdr {
            se_hdr: hdr,
            verified: false,
        }
    };

    match opt.format {
        OutputFormatSpec {
            kind: OutputFormatKind::Json,
            variant,
        } => {
            let doc = EnvelopeSeHdrV1::new(se_hdr);
            match variant {
                OutputFormatVariant::Minify => {
                    serde_json::to_writer(&mut output, &doc)?;
                }
                OutputFormatVariant::Default | OutputFormatVariant::Pretty => {
                    serde_json::to_writer_pretty(&mut output, &doc)?;
                }
            }
            // Make sure the output ends with a new line
            writeln!(&mut output)?
        }
    }
    output.flush()?;

    Ok(OwnExitCode::Success)
}
