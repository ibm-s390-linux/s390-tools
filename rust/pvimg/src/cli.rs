// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use std::{env, fmt::Display, path::PathBuf};

use clap::{ArgGroup, Args, Command, CommandFactory, Parser, ValueEnum, ValueHint};
use log::warn;
use utils::{CertificateOptions, DeprecatedVerbosityOptions};

/// Create and inspect IBM Secure Execution images.
///
/// Use pvimg to create an IBM Secure Execution image, which can be loaded using
/// zipl or QEMU. pvimg can also be used to inspect existing Secure Execution
/// images.
#[derive(Parser, Debug)]
#[command()]
pub struct CliOptions {
    #[clap(flatten)]
    pub verbose: DeprecatedVerbosityOptions,

    /// Print version information and exit.
    // Implemented for the help message only. Actual parsing happens in the
    // version command.
    #[arg(long)]
    pub version: bool,

    #[command(subcommand)]
    pub cmd: SubCommands,
}

impl From<GenprotimgCliOptions> for CliOptions {
    fn from(value: GenprotimgCliOptions) -> Self {
        Self {
            verbose: value.verbose,
            version: false,
            cmd: SubCommands::Create(value.args),
        }
    }
}

impl CliOptions {
    pub fn new_version_cmd_opts() -> Self {
        Self {
            verbose: DeprecatedVerbosityOptions::default(),
            version: true,
            cmd: SubCommands::Version,
        }
    }
}

/// Validates the given command line options.
///
/// # Errors
///
/// This function will return an error if an argument is missing.
pub fn validate_cli(opts: &CliOptions) -> Result<(), clap::error::Error> {
    match &opts.cmd {
        SubCommands::Create(create_opts) => {
            if let Some(dir) = create_opts
                .experimental_args
                .x_bootloader_directory
                .as_ref()
            {
                warn!("Use bootloader directory: {}", dir.display());
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// CLI Argument collection for handling input components.
#[derive(Args, Debug)]
#[cfg_attr(test, derive(Default))]
pub struct ComponentPaths {
    /// Use the content of FILE as a raw binary Linux kernel.
    ///
    /// The Linux kernel must be a raw binary s390x Linux kernel. The ELF format
    /// is not supported.
    #[arg(short='i', long = "kernel", value_name = "FILE", value_hint = ValueHint::FilePath, visible_alias = "image")]
    pub kernel: PathBuf,

    /// Use the content of FILE as the Linux initial RAM disk.
    #[arg(short, long, value_name = "FILE", value_hint = ValueHint::FilePath)]
    pub ramdisk: Option<PathBuf>,

    /// Use the content of FILE as the Linux kernel command line.
    ///
    /// The Linux kernel command line must be shorter than the maximum kernel
    /// command line size supported by the given Linux kernel.
    #[arg(short, long, value_name = "FILE", value_hint = ValueHint::FilePath)]
    pub parmfile: Option<PathBuf>,
}

/// CLI Argument collection for handling user-provided keys.
#[derive(Args, Debug)]
#[cfg_attr(test, derive(Default))]
pub struct UserKeys {
    /// Use the content of FILE as the customer-communication key (CCK).
    ///
    /// The file must contain exactly 32 bytes of data. In previous versions,
    /// this option was called '--comm-key'.
    #[arg(
        long,
        value_name = "FILE",
        group = "cck-available",
        visible_alias = "comm-key"
    )]
    pub cck: Option<PathBuf>,

    /// Use the content of FILE as the Secure Execution header protection key.
    ///
    /// The file must contain exactly 32 bytes of data. If the option is not
    /// specified, the Secure Execution header protection key is a randomly
    /// generated key.
    #[arg(long, value_name = "FILE", alias = "x-header-key")]
    pub hdr_key: Option<PathBuf>,
}

#[derive(Args, Debug)]
#[cfg_attr(test, derive(Default))]
#[command(
    group(ArgGroup::new("header-flags").multiple(true).conflicts_with_all(["x_pcf", "x_scf"])),
    group(ArgGroup::new("cck-available").multiple(true)))]
pub struct CreateBootImageLegacyFlags {
    /// Enable Secure Execution guest dump support. This option requires the
    /// '--cck' or '--enable-cck-update' option.
    #[arg(long, action = clap::ArgAction::SetTrue, requires = "cck-available", group="header-flags")]
    pub enable_dump: Option<bool>,

    /// Disable Secure Execution guest dump support (default).
    #[arg(long, action = clap::ArgAction::SetTrue, conflicts_with="enable_dump", group="header-flags")]
    pub disable_dump: Option<bool>,

    /// Add-secret requests must provide an extension secret that matches the
    /// CCK-derived extension secret. This option requires the '--cck'
    /// option.
    #[arg(long, action = clap::ArgAction::SetTrue, requires="cck", group="header-flags")]
    pub enable_cck_extension_secret: Option<bool>,

    /// Add-secret requests don't have to provide the CCK-derived extension
    /// secret (default).
    #[arg(long, action = clap::ArgAction::SetTrue, conflicts_with="enable_cck_extension_secret", group="header-flags")]
    pub disable_cck_extension_secret: Option<bool>,

    /// Enable CCK update support. Requires z17 or up. This option cannot be
    /// used in conjunction with the '--enable-cck-extension-secret' option.
    #[arg(long, action = clap::ArgAction::SetTrue, conflicts_with="enable_cck_extension_secret", group="cck-available", group="header-flags")]
    pub enable_cck_update: Option<bool>,

    /// Disable CCK update support (default).
    #[arg(long, action = clap::ArgAction::SetTrue, conflicts_with="enable_cck_update", group="header-flags")]
    pub disable_cck_update: Option<bool>,

    /// Enable the support for the DEA, TDEA, AES, and ECC PCKMO key encryption
    /// functions (default).
    #[arg(long, action = clap::ArgAction::SetTrue, group="header-flags")]
    pub enable_pckmo: Option<bool>,

    /// Disable the support for the DEA, TDEA, AES, and ECC PCKMO key encryption
    /// functions.
    #[arg(long, action = clap::ArgAction::SetTrue, conflicts_with="enable_pckmo", group="header-flags")]
    pub disable_pckmo: Option<bool>,

    /// Enable the support for the HMAC PCKMO key encryption function.
    #[arg(long, action = clap::ArgAction::SetTrue, group="header-flags")]
    pub enable_pckmo_hmac: Option<bool>,

    /// Disable the support for the HMAC PCKMO key encryption function (default).
    #[arg(long, action = clap::ArgAction::SetTrue, conflicts_with="enable_pckmo_hmac", group="header-flags")]
    pub disable_pckmo_hmac: Option<bool>,

    /// Enable the support for backup target keys.
    #[arg(long, action = clap::ArgAction::SetTrue, group="header-flags")]
    pub enable_backup_keys: Option<bool>,

    /// Disable the support for backup target keys (default).
    #[arg(long, action = clap::ArgAction::SetTrue, conflicts_with="enable_backup_keys", group="header-flags")]
    pub disable_backup_keys: Option<bool>,

    /// Enable encryption of the image components (default).
    ///
    /// The image components are: the kernel, ramdisk, and kernel command line.
    #[arg(long, action = clap::ArgAction::SetTrue, group="header-flags")]
    pub enable_image_encryption: Option<bool>,

    /// Disable encryption of the image components.
    ///
    /// The image components are: the kernel, ramdisk, and kernel command line.
    /// Use only if the components used do not contain any confidential content
    /// (for example, secrets like non-public cryptographic keys).
    #[arg(long, action = clap::ArgAction::SetTrue, conflicts_with="enable_image_encryption", group="header-flags")]
    pub disable_image_encryption: Option<bool>,
}

#[non_exhaustive]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum OutputFormat {
    /// JSON format.
    Json,
}

impl Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Json => "JSON",
            }
        )
    }
}

#[derive(Args, Debug)]
pub struct SeImgInputArgs {
    /// Use INPUT as the Secure Execution image.
    #[arg(value_name = "INPUT", value_hint = ValueHint::FilePath,)]
    pub path: PathBuf,
}

#[derive(Args, Debug)]
pub struct InfoArgs {
    #[clap(flatten)]
    pub input: SeImgInputArgs,

    /// The output format
    #[arg(long, value_enum)]
    pub format: OutputFormat,

    /// Use the key in FILE to decrypt the Secure Execution header.
    ///
    /// It is the key that was specified with the command line option
    /// '--hdr-key' at the Secure Execution image creation.
    #[arg(long, value_name = "FILE", value_hint = ValueHint::FilePath, alias = "key")]
    pub hdr_key: Option<PathBuf>,
}

#[derive(Args, Debug)]
#[command(group(ArgGroup::new("test-args").multiple(true).required(true)))]
pub struct TestArgs {
    #[clap(flatten)]
    pub input: SeImgInputArgs,

    /// Use FILE to check for a host key document.
    ///
    /// Verifies that the image contains the host key hash of one of the
    /// specified host keys. The check fails if none of the host keys match the
    /// hash in the image. This parameter can be specified multiple times.
    /// Mutually exclusive with '--key-hashes'.
    #[arg(
        short = 'k',
        long = "host-key-document",
        value_name = "FILE",
        value_hint = ValueHint::FilePath,
        use_value_delimiter = true,
        value_delimiter = ',',
        group = "test-args",
        )]
    pub host_key_documents: Vec<PathBuf>,

    /// Use FILE to check for the host key hashes provided by the ultravisor. If
    /// no FILE is specified, FILE defaults to '/sys/firmware/uv/keys/all'.
    ///
    /// The default file is only available if the local system supports the
    /// Query Ultravisor Keys UVC. Verifies that the image contains the host key
    /// hash of one of the specified hashes in FILE. The check fails if none of
    /// the host keys match a hash in the response. Mutually exclusive with
    /// '--host-key-document'.
    #[arg(
        long = "key-hashes",
        value_name = "FILE",
        value_hint = ValueHint::FilePath,
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "/sys/firmware/uv/keys/all",
        conflicts_with="host_key_documents",
        group = "test-args",
        )]
    pub key_hashes: Option<PathBuf>,
}

/// Create an IBM Secure Execution image.
///
/// Create a new IBM Secure Execution image. Only create these images in a
/// trusted environment, such as your workstation. The 'genprotimg' command
/// creates randomly generated keys to protect the image. The generated image
/// can then be booted on an IBM Secure Execution system as a KVM guest.
///
/// Note: The 'genprotimg' command is a symbolic link to the 'pvimg create'
///       command.
#[derive(Parser, Debug)]
pub struct GenprotimgCliOptions {
    #[clap(flatten)]
    pub args: Box<CreateBootImageArgs>,

    #[clap(flatten)]
    pub verbose: DeprecatedVerbosityOptions,

    /// Print version information and exit.
    // Implemented for the help message only. Actual parsing happens in the
    // version command.
    #[arg(long, action = clap::ArgAction::SetTrue )]
    pub version: (),

    #[arg(long, action = clap::ArgAction::HelpLong, hide(true))]
    /// Print help (deprecated, use '--help' instead).
    help_all: (),

    #[arg(long, action = clap::ArgAction::HelpLong, hide(true))]
    /// Print help (deprecated, use '--help' instead).
    help_experimental: (),
}

impl GenprotimgCliOptions {
    pub fn command() -> Command {
        let cmd = <Self as CommandFactory>::command();
        // Make sure that the correct binary is shown in the clap error
        // messages.
        cmd.bin_name("genprotimg")
    }

    pub fn own_parse() -> CliOptions {
        let args = env::args_os();
        let args_len = args.len();
        let version_count = args.filter(|value| value == "--version").count();
        if version_count > 1 || version_count == 1 && (args_len != version_count + 1) {
            Self::command()
                .error(
                    clap::error::ErrorKind::UnknownArgument,
                    "unexpected argument",
                )
                .exit()
        }

        if version_count == 1 {
            CliOptions::new_version_cmd_opts()
        } else {
            let genprotimg_opts = Self::parse();
            genprotimg_opts.into()
        }
    }
}

#[derive(Parser, Debug)]
#[cfg_attr(test, derive(Default))]
pub struct CreateBootImageArgs {
    #[clap(flatten)]
    pub component_paths: ComponentPaths,

    /// Write the generated Secure Execution boot image to FILE.
    #[arg(short, long, value_name = "FILE", value_hint = ValueHint::FilePath,)]
    pub output: PathBuf,

    #[clap(flatten)]
    pub certificate_args: CertificateOptions,

    /// Disable all input component checks.
    ///
    /// For example, for the Linux kernel, it tests if the given kernel looks
    /// like a raw binary s390x kernel.
    #[arg(long)]
    pub no_component_check: bool,

    /// Overwrite an existing Secure Execution boot image.
    #[arg(long)]
    pub overwrite: bool,

    #[clap(flatten)]
    pub keys: UserKeys,

    #[clap(flatten)]
    pub legacy_flags: CreateBootImageLegacyFlags,

    #[clap(flatten)]
    pub experimental_args: CreateBootImageExperimentalArgs,
}

/// Experimental options
#[derive(Args, Debug)]
#[cfg_attr(test, derive(Default))]
pub struct CreateBootImageExperimentalArgs {
    /// Manually set the directory used to load the Secure Execution bootloaders
    /// (stage3a and stage3b) (experimental option).
    // Hidden in user documentation.
    #[arg(long, value_name = "DIR", hide(true))]
    pub x_bootloader_directory: Option<PathBuf>,

    /// Manually set the image components encryption key (experimental option).
    // Hidden in user documentation.
    #[arg(long, value_name = "FILE", hide(true))]
    pub x_comp_key: Option<PathBuf>,

    /// Manually set the PSW address used for the Secure Execution header (experimental option).
    // Hidden in user documentation.
    #[arg(long, value_name = "ADDRESS", hide(true))]
    pub x_psw: Option<String>,

    /// Manually set the plaintext control flags (experimental option).
    // No validity checks made. Hidden in user documentation.
    #[arg(long, value_name = "PCF", hide(true))]
    pub x_pcf: Option<String>,

    /// Manually set the secret control flags (experimental option).
    // No validity checks made. Hidden in user documentation.
    #[arg(long, value_name = "SCF", hide(true))]
    pub x_scf: Option<String>,
}

#[derive(Debug, clap::Subcommand)]
pub enum SubCommands {
    /// Create an IBM Secure Execution image.
    ///
    /// Create a new IBM Secure Execution image. Only create these images in a
    /// trusted environment, such as your workstation. The 'pvimg create'
    /// command creates randomly generated keys to protect the image. The
    /// generated image can then be booted on an IBM Secure Execution system as
    /// a KVM guest.
    Create(Box<CreateBootImageArgs>),

    /// Print information about the IBM Secure Execution image.
    ///
    /// Note that the API and output format is experimental and subject to
    /// change.
    Info(InfoArgs),

    /// Test different aspects of an existing IBM Secure Execution image.
    Test(Box<TestArgs>),

    /// Print version information and exit.
    #[command(aliases(["--version"]), hide(true))]
    Version,
}

#[allow(clippy::shadow_unrelated)]
#[cfg(test)]
mod test {
    use std::collections::BTreeMap;

    use super::*;

    #[derive(Hash, Eq, PartialEq, Debug, Clone)]
    struct CliOption {
        name: String,
        args: Vec<String>,
    }

    impl CliOption {
        fn new<S: AsRef<str>, T: AsRef<str>, P: AsRef<[S]>>(name: T, args: P) -> Self {
            let name = name.as_ref().to_owned();
            let args = args
                .as_ref()
                .iter()
                .map(|v| v.as_ref().to_owned())
                .collect();
            Self { name, args }
        }
    }

    impl From<CliOption> for Vec<String> {
        fn from(val: CliOption) -> Self {
            let CliOption { args, .. } = val;
            args
        }
    }

    fn flat_map_collect(map: BTreeMap<String, CliOption>) -> Vec<String> {
        map.into_values().flat_map(|v| v.args).collect()
    }

    fn insert(
        mut map: BTreeMap<String, CliOption>,
        values: Vec<CliOption>,
    ) -> BTreeMap<String, CliOption> {
        for value in values {
            map.insert(value.name.to_owned(), value);
        }
        map
    }

    fn remove<S: AsRef<str>>(
        mut map: BTreeMap<String, CliOption>,
        key: S,
    ) -> BTreeMap<String, CliOption> {
        map.remove(key.as_ref());
        map
    }

    #[test]
    #[rustfmt::skip]
    fn genprotimg_and_pvimg_create_args() {
        // Minimal valid create arguments using no-verify
        let mut mvcanv = BTreeMap::new();
        mvcanv = insert(mvcanv, vec![CliOption::new("image", ["--image", "/dev/null"])]);
        mvcanv = insert(mvcanv, vec![CliOption::new("hkd", ["--host-key-document", "/dev/null"])]);
        mvcanv = insert(mvcanv, vec![CliOption::new("output", ["--output", "/dev/null"])]);
        mvcanv = insert(mvcanv, vec![CliOption::new("no-verify", ["--no-verify"])]);

        // Minimal valid create arguments using --cert
        let mut mvca = mvcanv.clone();
        mvca.remove("no-verify");
        mvca = insert(mvca, vec![CliOption::new("cert", ["--cert", "/dev/null"])]);

        let valid_create_args = [
            flat_map_collect(mvcanv.clone()),
            flat_map_collect(insert(remove(mvcanv.clone(), "image"), vec![CliOption::new("kernel", ["--kernel", "/dev/kernel"])])),
            flat_map_collect(insert(mvcanv.clone(), vec![CliOption::new("root-ca", ["--root-ca", "/dev/null"])])),
            flat_map_collect(mvca.clone()),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("quiet", ["-q"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("verbose", ["-vvv"])])),
            // Verify the old verbosity is still working.
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("verbose", ["-VVV"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("offline", ["--offline"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("ramdisk", ["--ramdisk", "/dev/null"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("parmfile", ["--parmfile", "/dev/null"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("enable-dump", ["--enable-dump"]),
                                                   CliOption::new("comm-key", ["--comm-key", "/dev/null"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("enable-dump", ["--enable-dump"]),
                                                   CliOption::new("comm-key", ["--cck", "/dev/null"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("enable-dump", ["--enable-dump"]),
                                                   CliOption::new("comm-key", ["--comm-key", "/dev/null"]),
                                                   CliOption::new("enable-cck-update", ["--enable-cck-update"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("x-pcf", ["--x-pcf", "0x0"]),
                                                   CliOption::new("x-scf", ["--x-scf", "0x0"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("x-psw", ["--x-psw", "0x0"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("no-component-check", ["--no-component-check"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("enable-pckmo", ["--enable-pckmo"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("enable-pckmo-hmac", ["--enable-pckmo-hmac"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("enable-backup-keys", ["--enable-backup-keys"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("disable-image-encryption", ["--disable-image-encryption"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("enable-image-encryption", ["--enable-image-encryption"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("x-header-key", ["--x-header-key", "/dev/null"]),])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("x-header-key", ["--hdr-key", "/dev/null"]),])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("enable-cck-update", ["--enable-cck-update"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("disable-cck-update", ["--disable-cck-update"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("multiple-cck", ["--disable-cck-update", "--cck", "/dev/null"])])),
        ];
        let invalid_create_args = [
            flat_map_collect(remove(mvcanv.clone(), "no-verify")),
            flat_map_collect(remove(mvcanv.clone(), "image")),
            flat_map_collect(remove(mvcanv.clone(), "hkd")),
            flat_map_collect(remove(mvcanv, "output")),

            // missing both `--cck' and `--enable-cck-update'
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("enable-dump", ["--enable-dump"])])),

            // -v and -q cannot be combined
            flat_map_collect(insert(mvca.clone(), vec![
                CliOption::new("verbose", ["-v"]),
                CliOption::new("quiet", ["-q"])])),

            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("image2", ["--image", "/dev/null"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("output2", ["--output", "/dev/null"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("ramdisk", ["--ramdisk", "/dev/null"]),
                                                   CliOption::new("ramdisk2", ["--ramdisk", "/dev/null"]) ])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("parmfile", ["--parmfile", "/dev/null"]),
                                                   CliOption::new("parmfile2", ["--parmfile", "/dev/null"]) ])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("x-pcf", ["--x-pcf", "0x0"]),
                                                   CliOption::new("x-pcf2", ["--x-pcf", "0x0"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("enable-pckmo", ["--enable-pckmo"]),
                                                   CliOption::new("disable-pckmo", ["--disable-pckmo"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("enable-image-encryption", ["--enable-image-encryption"]),
                                                   CliOption::new("disable-image-encryption", ["--disable-image-encryption"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("x-header-key", ["--hdr-key"]),])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("extension", ["--enable-cck-extension-secret"]),
                                                   CliOption::new("update", ["--enable-cck-update"])])),

        ];

        let mut genprotimg_valid_args = vec![
            // See workaround `parse_version` in `pvimg/main.rs`.
            // vec!["genprotimg", "--version"],
        ];
        let mut pvimg_valid_args = vec![
            vec!["pvimg", "--version"],
            vec!["pvimg", "version"],
        ];

        // Test for invalid combinations
        let mut genprotimg_invalid_args = vec![
            vec!["genprotimg"],
        ];
        let mut pvimg_invalid_args = vec![
            vec!["pvimg"],
        ];

        // Test that `genprotimg` and `pvimg create` behave equally.
        for create_args in &valid_create_args {
            genprotimg_valid_args.push([["genprotimg"].to_vec(), Vec::from_iter(create_args.iter().map(String::as_str))].concat());
            pvimg_valid_args.push([["pvimg", "create"].to_vec(), Vec::from_iter(create_args.iter().map(String::as_str))].concat());
        }

        for invalid_create_args in &invalid_create_args {
            genprotimg_invalid_args.push([["genprotimg"].to_vec(), Vec::from_iter(invalid_create_args.iter().map(String::as_str))].concat());
            pvimg_invalid_args.push([["pvimg", "create"].to_vec(), Vec::from_iter(invalid_create_args.iter().map(String::as_str))].concat());
        }

        for arg in pvimg_valid_args {
            let res = CliOptions::try_parse_from(&arg);
            #[allow(clippy::use_debug, clippy::print_stdout)]
            if let Err(e) = &res {
                println!("arg: {arg:?}");
                println!("{e}");
            }
            assert!(res.is_ok());
        }

        for arg in pvimg_invalid_args {
            let res = CliOptions::try_parse_from(&arg);
            assert!(res.is_err());
        }

        for arg in genprotimg_valid_args {
            let res = GenprotimgCliOptions::try_parse_from(&arg);
            #[allow(clippy::use_debug, clippy::print_stdout)]
            if let Err(e) = &res {
                println!("arg: {arg:?}");
                println!("{e}");
            }
            assert!(res.is_ok());
        }

        for arg in genprotimg_invalid_args {
            let res = GenprotimgCliOptions::try_parse_from(&arg);
            assert!(res.is_err());
        }
    }

    #[test]
    fn pvimg_test_cli() {
        let args = BTreeMap::new();
        let valid_test_args = [
            flat_map_collect(insert(
                args.clone(),
                vec![
                    CliOption::new("host-key-hashes", ["--key-hashes"]),
                    CliOption::new("image", ["/dev/null"]),
                ],
            )),
            flat_map_collect(insert(
                args.clone(),
                vec![
                    CliOption::new("host-key-hashes2", ["--key-hashes=/dev/null"]),
                    CliOption::new("image", ["/dev/null"]),
                ],
            )),
            flat_map_collect(insert(
                args.clone(),
                vec![
                    CliOption::new("host-key-hashes2", ["--key-hashes=/dev/null"]),
                    CliOption::new("image", ["/dev/null"]),
                    // global works
                    CliOption::new("quiet", ["-q"]),
                ],
            )),
            // separation between keyword and positional args works
            flat_map_collect(insert(
                args.clone(),
                vec![
                    CliOption::new("host-key-hashes2", ["--key-hashes=/dev/null"]),
                    CliOption::new("image", ["--", "/dev/null"]),
                ],
            )),
            // Verify that the old verbosity is still working.
            flat_map_collect(insert(
                args.clone(),
                vec![
                    CliOption::new("host-key-hashes2", ["--key-hashes=/dev/null"]),
                    CliOption::new("image", ["/dev/null"]),
                    CliOption::new("verbose", ["-VVV"]),
                ],
            )),
        ];

        let invalid_test_args = [
            flat_map_collect(insert(
                args.clone(),
                vec![CliOption::new("image", ["/dev/null"])],
            )),
            // the argument '--key-hashes[=<FILE>]' cannot be used with '--host-key-document
            // <FILE>'
            flat_map_collect(insert(
                args.clone(),
                vec![
                    CliOption::new("host-key-hashes2", ["--key-hashes=/dev/null"]),
                    CliOption::new("host-key-document", ["--host-key-document", "/dev/null"]),
                    CliOption::new("image", ["/dev/null"]),
                ],
            )),
            flat_map_collect(insert(
                args,
                vec![
                    CliOption::new("host-key-hashes2", ["--key-hashes", "/sys/null"]),
                    CliOption::new("image", ["--", "/dev/null"]),
                ],
            )),
        ];

        let mut pvimg_valid_args = vec![];

        // Test for invalid combinations
        // Input is missing
        let mut pvimg_invalid_args = vec![vec!["pvimg", "test"]];

        for create_args in &valid_test_args {
            pvimg_valid_args.push(
                [
                    ["pvimg", "test"].to_vec(),
                    Vec::from_iter(create_args.iter().map(String::as_str)),
                ]
                .concat(),
            );
        }

        for invalid_test_arg in &invalid_test_args {
            pvimg_invalid_args.push(
                [
                    ["pvimg", "test"].to_vec(),
                    Vec::from_iter(invalid_test_arg.iter().map(String::as_str)),
                ]
                .concat(),
            );
        }

        for arg in pvimg_valid_args {
            let res = CliOptions::try_parse_from(&arg);
            #[allow(clippy::use_debug, clippy::print_stdout)]
            if let Err(e) = &res {
                println!("arg: {arg:?}");
                println!("{e}");
            }
            assert!(res.is_ok());
        }

        for arg in pvimg_invalid_args {
            let res = CliOptions::try_parse_from(&arg);
            assert!(res.is_err());
        }
    }

    #[test]
    fn pvimg_info_cli() {
        let args = BTreeMap::new();
        let valid_test_args = [
            flat_map_collect(insert(
                args.clone(),
                vec![
                    CliOption::new("format", ["--format", "json"]),
                    CliOption::new("image", ["/dev/null"]),
                ],
            )),
            flat_map_collect(insert(
                args.clone(),
                vec![
                    CliOption::new("format", ["--format=json"]),
                    CliOption::new("image", ["/dev/null"]),
                ],
            )),
            flat_map_collect(insert(
                args.clone(),
                vec![
                    CliOption::new("hdr-key", ["--hdr-key", "/dev/null"]),
                    CliOption::new("format", ["--format=json"]),
                    CliOption::new("image", ["/dev/null"]),
                ],
            )),
            flat_map_collect(insert(
                args.clone(),
                vec![
                    CliOption::new("hdr-key", ["--key", "/dev/null"]),
                    CliOption::new("format", ["--format=json"]),
                    CliOption::new("image", ["/dev/null"]),
                ],
            )),
            // separation between keyword and positional args works
            flat_map_collect(insert(
                args.clone(),
                vec![
                    CliOption::new("format", ["--format=json"]),
                    CliOption::new("image", ["--", "/dev/null"]),
                ],
            )),
            // Verify that the old verbosity is still working.
            flat_map_collect(insert(
                args.clone(),
                vec![
                    CliOption::new("format", ["--format=json"]),
                    CliOption::new("image", ["/dev/null"]),
                    CliOption::new("verbose", ["-VVV"]),
                ],
            )),
        ];

        let invalid_test_args = [
            // the argument '--key-hashes[=<FILE>]' cannot be used with '--host-key-document
            // <FILE>'
            flat_map_collect(insert(
                args.clone(),
                vec![CliOption::new("image", ["/dev/null"])],
            )),
            // No default defined for --format
            flat_map_collect(insert(
                args,
                vec![
                    CliOption::new("format", ["--format"]),
                    CliOption::new("image", ["--", "/dev/null"]),
                ],
            )),
        ];

        let mut pvimg_valid_args = vec![];

        // Test for invalid combinations
        // Input is missing
        let mut pvimg_invalid_args = vec![vec!["pvimg", "info"]];

        for create_args in &valid_test_args {
            pvimg_valid_args.push(
                [
                    ["pvimg", "info"].to_vec(),
                    Vec::from_iter(create_args.iter().map(String::as_str)),
                ]
                .concat(),
            );
        }

        for invalid_test_arg in &invalid_test_args {
            pvimg_invalid_args.push(
                [
                    ["pvimg", "info"].to_vec(),
                    Vec::from_iter(invalid_test_arg.iter().map(String::as_str)),
                ]
                .concat(),
            );
        }

        for arg in pvimg_valid_args {
            let res = CliOptions::try_parse_from(&arg);
            #[allow(clippy::use_debug, clippy::print_stdout)]
            if let Err(e) = &res {
                println!("arg: {arg:?}");
                println!("{e}");
            }
            assert!(res.is_ok());
        }

        for arg in pvimg_invalid_args {
            let res = CliOptions::try_parse_from(&arg);
            assert!(res.is_err());
        }
    }

    #[test]
    fn verify_cli() {
        use clap::CommandFactory;
        CliOptions::command().debug_assert();
    }
}
