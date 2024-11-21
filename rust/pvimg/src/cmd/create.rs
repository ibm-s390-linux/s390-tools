// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use std::{fs::OpenOptions, io::BufReader};

use anyhow::{Context, Result};
use log::{debug, warn};
use pv::misc::{open_file, try_parse_u64};
use pvimg::{
    error::OwnExitCode,
    secured_comp::ComponentTrait,
    uvdata::{
        ControlFlagTrait, ControlFlagsTrait, FlagData, PcfV1, PlaintextControlFlagsV1, ScfV1,
        SeHdrDataV1, SecretControlFlagsV1,
    },
};
use utils::{AtomicFile, AtomicFileOperation};

use crate::{
    cli::{ComponentPaths, CreateBootImageArgs},
    cmd::common::read_user_provided_keys,
    se_img::{SeHdrArgs, SeImgBuilder},
    se_img_comps::{
        check_components, cmdline::Cmdline, kernel::S390Kernel, ramdisk::Ramdisk, Component,
    },
};

/// The returned vector is sorted by the occurrence in the memory layout:
/// First the kernel, then the ramdisk and then the kernel cmdline.
///
/// Keep this ordering in sync with the ordering of [`ComponentKind`]!
fn components(component_args: &ComponentPaths) -> Result<Vec<Component>> {
    // IMPORTANT: Don't change the order of the components: kernel, ramdisk, and
    // then parmline! This is important since ALD, PLD and TLD is sorted by the
    // component address.
    let mut components: Vec<Component> =
        vec![S390Kernel::new(Box::new(BufReader::new(open_file(&component_args.kernel)?))).into()];
    if let Some(path) = &component_args.ramdisk {
        components.push(Ramdisk::new(Box::new(BufReader::new(open_file(path)?))).into());
    }
    if let Some(path) = &component_args.parmfile {
        components.push(Cmdline::new(Box::new(BufReader::new(open_file(path)?))).into());
    }
    Ok(components)
}

fn parse_flags(
    args: &CreateBootImageArgs,
) -> Result<(PlaintextControlFlagsV1, SecretControlFlagsV1)> {
    let lf = &args.legacy_flags;
    let plaintext_flags: Vec<FlagData<PcfV1>> = [
        lf.disable_dump
            .filter(|x| *x)
            .and(Some(PcfV1::all_disabled([PcfV1::AllowDumping]))),
        lf.enable_dump
            .filter(|x| *x)
            .and(Some(PcfV1::all_disabled([PcfV1::AllowDumping]))),
        lf.disable_pckmo
            .filter(|x| *x)
            .and(Some(PcfV1::all_disabled([
                PcfV1::PckmoAes,
                PcfV1::PckmoDeaTdea,
                PcfV1::PckmoEcc,
            ]))),
        lf.enable_pckmo.filter(|x| *x).and(Some(PcfV1::all_enabled([
            PcfV1::PckmoAes,
            PcfV1::PckmoDeaTdea,
            PcfV1::PckmoEcc,
        ]))),
    ]
    .into_iter()
    .flatten()
    .flatten()
    .collect();
    // This is ensured by Clap's `conflicts_with`.
    assert!(PlaintextControlFlagsV1::no_duplicates(&plaintext_flags));

    let secret_flags: Vec<FlagData<ScfV1>> = [
        lf.disable_cck_extension_secret
            .filter(|x| *x)
            .and(Some(ScfV1::all_disabled([
                ScfV1::CCKExtensionSecretEnforcment,
            ]))),
        lf.enable_cck_extension_secret
            .filter(|x| *x)
            .and(Some(ScfV1::all_enabled([
                ScfV1::CCKExtensionSecretEnforcment,
            ]))),
    ]
    .into_iter()
    .flatten()
    .flatten()
    .collect();
    // This is ensured by Clap's `conflicts_with`.
    assert!(SecretControlFlagsV1::no_duplicates(&secret_flags));

    let mut pcf: PlaintextControlFlagsV1 = match &args.experimental_args.x_pcf {
        Some(v) => try_parse_u64(v, "x-pcf")?.into(),
        None => PlaintextControlFlagsV1::default(),
    };
    pcf.parse_flags(&plaintext_flags);
    debug!("Using plaintext flags: {pcf}");

    let mut scf: SecretControlFlagsV1 = match &args.experimental_args.x_scf {
        Some(v) => try_parse_u64(v, "x-scf")?.into(),
        None => SecretControlFlagsV1::default(),
    };
    scf.parse_flags(&secret_flags);
    debug!("Using secret flags:    {scf}");

    Ok((pcf, scf))
}

/// Create a Secure Execution boot image
pub fn create(opt: &CreateBootImageArgs) -> Result<OwnExitCode> {
    // Verify host key documents first, because if they are not valid there is
    // no reason to continue.
    let verified_host_keys = opt
        .certificate_args
        .get_verified_hkds("Secure Execution image")?;
    let user_provided_keys =
        read_user_provided_keys(opt.comm_key.as_deref(), &opt.experimental_args)?;
    let (plaintext_flags, secret_flags) = parse_flags(opt)?;

    let mut components = components(&opt.component_paths)?;
    if opt.no_component_check {
        warn!("The component check is turned off!");
    } else {
        check_components(&mut components)?;
    }

    // FIXME get rid of the legacy mode. But that's only possible as soon as all
    // available tools are updated.
    let expected_se_hdr_size = SeHdrDataV1::expected_size(verified_host_keys.len())?;
    let mut writer = AtomicFile::with_extension(&opt.output, "part", &mut OpenOptions::new())?;
    let mut seimg_ctx = SeImgBuilder::new_v1(
        &mut writer,
        plaintext_flags.is_unset(PcfV1::NoComponentEncryption),
        Some(expected_se_hdr_size),
        opt.experimental_args.x_bootloader_directory.as_ref(),
    )?;

    // Enable expert mode
    seimg_ctx.i_know_what_i_am_doing();
    if let Some((path, key)) = user_provided_keys.components_key {
        seimg_ctx.set_components_key(key).with_context(|| {
            format!(
                "Failed to use '{}' as the image components key",
                path.display()
            )
        })?;
    }

    let psw_addr: Option<u64> = match &opt.experimental_args.x_psw {
        Some(v) => try_parse_u64(v, "x-psw")?.into(),
        None => None,
    };

    for mut component in components.into_iter() {
        seimg_ctx
            .prepare_and_append_as_secure_component(&mut component, None)
            .with_context(|| format!("Failed to prepare {} component", component.kind()))?;
    }

    let img_comps = seimg_ctx.finish(SeHdrArgs {
        keys: verified_host_keys.as_slice(),
        pcf: &plaintext_flags,
        scf: &secret_flags,
        cck: &user_provided_keys.cck,
        hdr_aead_key: &user_provided_keys.aead_key,
        psw_addr: &psw_addr,
    })?;

    debug!("");
    debug!("----------------------------------------------------------------");
    debug!("| {:^60} |", "Secure Execution image layout");
    debug!("|--------------------------------------------------------------|");
    debug!("| {:<23} | {:<34} |", "Component type", "Component address");
    debug!("|-------------------------|------------------------------------|");
    img_comps
        .iter()
        .for_each(|img_comp| debug!("{img_comp:<33}"));
    debug!("----------------------------------------------------------------");

    // Rename the file `$OUTPUT.part` to `$OUTPUT` for achieving atomic file
    // creation.
    let op = match opt.overwrite {
        true => AtomicFileOperation::Replace,
        false => AtomicFileOperation::NoReplace,
    };
    writer.finish(op)?;

    warn!("Successfully generated the Secure Execution image.");
    Ok(OwnExitCode::Success)
}
