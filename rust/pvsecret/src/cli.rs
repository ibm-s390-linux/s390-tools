// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023, 2024

use std::fmt::Display;

use clap::error::ErrorKind::ValueValidation;
use clap::{ArgGroup, Args, CommandFactory, Parser, Subcommand, ValueEnum, ValueHint};
use utils::{CertificateOptions, DeprecatedVerbosityOptions, STDOUT};

/// Manage secrets for IBM Secure Execution guests.
///
/// Use to create and send add-secret requests, list the added secrets and lock the Secret Store.
#[derive(Parser, Debug)]
pub struct CliOptions {
    #[clap(flatten)]
    pub verbosity: DeprecatedVerbosityOptions,

    /// Print version information and exit.
    // Implemented for the help message only. Actual parsing happens in the
    // version command.
    #[arg(long)]
    pub version: bool,

    #[command(subcommand)]
    pub cmd: Command,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum CreateSecretFlags {
    /// Disables host-initiated dumping for the target guest instance.
    DisableDump,
}

#[derive(Args, Debug)]
#[command(group(ArgGroup::new("as-ext").args(["cck", "extension_secret"])),)]
pub struct CreateSecretOpt {
    #[command(flatten)]
    pub certificate_args: CertificateOptions,

    /// Specifies the header of the guest image.
    ///
    /// Can be an IBM Secure Execution image created by 'pvimg/genprotimg' or an
    /// extracted IBM Secure Execution header.
    #[arg(long, value_name = "FILE", value_hint = ValueHint::FilePath)]
    pub hdr: String,

    /// Force the generation of add-secret requests on IBM Secure Execution guests.
    ///
    /// If the program detects that it is running on an IBM Secure Execution guest, it denies the
    /// generation of add-secret requests. The force flag overwrites this behavior.
    #[arg(short, long)]
    pub force: bool,

    /// Write the generated request to FILE.
    #[arg(short, long, value_name = "FILE", value_hint = ValueHint::FilePath,)]
    pub output: String,

    /// Use the content of FILE as an extension secret.
    ///
    /// The file must be exactly 32 bytes long. If this request is the first, all subsequent
    /// requests must have the same extension secret. Only makes sense if bit 1 of the secret
    /// control flags of the IBM Secure Execution header is
    /// 0. Otherwise the ultravisor rejects the request.
    #[arg(long, value_name = "FILE", value_hint = ValueHint::FilePath,)]
    pub extension_secret: Option<String>,

    /// Use the content of FILE as the customer-communication key (CCK) to derive the extension
    /// secret.
    ///
    /// The file must contain exactly 32 bytes of data. If the target guest was started
    /// with bit 1 of the secret control flag set, the ultravisor also derives the secret from the
    /// CCK. Otherwise, the ultravisor interprets the extension secret as a normal one. This still
    /// works if you use the same CCK for all requests.
    #[arg(long, value_name = "FILE")]
    pub cck: Option<String>,

    /// Use HEXSTRING as the Configuration Unique ID.
    ///
    /// Must be a hex 128-bit unsigned big endian number string. Leading zeros must be provided. If
    /// specified, the value must match with the Config-UID from the attestation result of that
    /// guest.  If not specified, the CUID will be ignored by the ultravisor during the
    /// verification of the request.
    #[arg(long, value_name = "HEXSTRING")]
    pub cuid_hex: Option<String>,

    /// Use the content of FILE as the Configuration Unique ID.
    ///
    /// The file must contain exactly 128 bit of data or a yaml with a `cuid` entry.
    /// If specified, the value must match the Config-UID from the attestation result of that
    /// guest. If not specified, the CUID will be ignored by the Ultravisor during the verification
    /// of the request.
    #[arg(long, value_name = "FILE", conflicts_with("cuid_hex"), value_hint = ValueHint::FilePath,)]
    pub cuid: Option<String>,

    #[command(subcommand)]
    pub secret: AddSecretType,

    // FLAGS
    // each flag must conflict with `flags`
    // `flags` is hidden in the help menu
    /// Manually set the add-secret request flags.
    ///
    /// No validity checks made. Hidden in user documentation.
    #[arg(long, hide(true))]
    pub pcf: Option<String>,

    /// Flags for the add-secret request.
    #[arg(
        long,
        conflicts_with("pcf"),
        value_enum,
        value_parser,
        use_value_delimiter = true,
        value_delimiter = ','
    )]
    pub flags: Vec<CreateSecretFlags>,

    /// Use the content of FILE as user-data.
    ///
    /// Passes user data defined in FILE through the add-secret request to the ultravisor. The
    /// user data can be up to 512 bytes of arbitrary data, and the maximum size depends on the
    /// size of the user-signing key:
    /// - No key: user data can be 512 bytes.
    /// - EC(secp521r1) or RSA 2048 keys: user data can be 256 bytes.
    /// - RSA 3072 key: user data can be 128 bytes.
    ///
    /// The firmware ignores this data, but the request tag protects the user-data. Optional. No
    /// user-data by default.
    #[arg(long, value_name = "FILE", value_hint = ValueHint::FilePath,)]
    pub user_data: Option<String>,

    /// Use the content of FILE as user signing key.
    ///
    /// Adds a signature calculated from the key in FILE to the add-secret request. The
    /// file must be in DER or PEM format containing a private key. Supported are RSA 2048 &
    /// 3072-bit and EC(secp521r1) keys. The firmware ignores the content, but the request tag
    /// protects the signature. The user-signing key signs the request. The location of the
    /// signature is filled with zeros during the signature calculation. The request tag also
    /// secures the signature. See man pvsecret verify for more details. Optional. No signature
    /// by default.
    #[arg(long, value_name = "FILE", value_hint = ValueHint::FilePath,)]
    pub user_sign_key: Option<String>,

    /// Do not hash the name, use it directly as secret ID.
    ///
    /// Ignored for meta-secrets.
    #[arg(long)]
    pub use_name: bool,
}

#[derive(Subcommand, Debug)]
pub enum AddSecretType {
    /// Create a meta secret.
    ///
    /// Use a meta secret to carry flags to the ultravisor without having to provide an actual
    /// secret value. Meta secrets do not appear in the list of secrets.
    Meta,

    /// Create an association secret.
    ///
    /// Use an association secret to connect a trusted I/O device to a guest. The 'pvapconfig' tool
    /// provides more information about association secrets.
    Association {
        /// String that identifies the new secret.
        ///
        /// The actual secret is set with '--input-secret'. The name is saved in `NAME.yaml` with
        /// white-spaces mapped to `_`.
        name: String,

        /// Print the hashed name to stdout.
        ///
        /// The hashed name is not written to `NAME.yaml`
        #[arg(long)]
        stdout: bool,

        /// Path from which to read the plaintext secret. Uses a random secret if not specified.
        #[arg(long, value_name = "SECRET-FILE", value_hint = ValueHint::FilePath, conflicts_with("output_secret"))]
        input_secret: Option<String>,

        /// Save the generated secret as plaintext in SECRET-FILE.
        ///
        /// The generated secret can be used to generate add-secret requests for a different guest
        /// with the same secret using '--input-secret'. Destroy the secret when it is not used
        /// anymore.
        #[arg(long, value_name = "SECRET-FILE", value_hint = ValueHint::FilePath,)]
        output_secret: Option<String>,
    },

    /// Create a retrievable secret.
    ///
    /// A retrievable secret is stored in the  per-guest storage of the Ultravisor. A SE-guest can
    /// retrieve the secret at runtime and use it. All retrievable secrets, but the plaintext
    /// secret, are retrieved as wrapped/protected key objects and only usable inside the current,
    /// running SE-guest instance.
    #[command(visible_alias = "retr")]
    Retrievable {
        /// String that identifies the new secret.
        ///
        /// The actual secret is set with '--secret'. The name is saved in `NAME.yaml` with
        /// white-spaces mapped to `_`.
        name: String,

        /// Print the hashed name to stdout.
        ///
        /// The hashed name is not written to `NAME.yaml`
        #[arg(long)]
        stdout: bool,

        /// Use SECRET-FILE as retrievable secret
        #[arg(long, value_name = "SECRET-FILE", value_hint = ValueHint::FilePath)]
        secret: String,

        /// Specify the secret type.
        ///
        /// Limitations to the input data apply depending on the secret type.
        #[arg(long = "type", value_name = "TYPE")]
        kind: RetrieveableSecretInpKind,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum RetrieveableSecretInpKind {
    /// A plaintext secret.
    /// Can be any file up to 8190 bytes long
    Plain,
    /// An AES key.
    /// Must be a plain byte file 128, 192, or 256 bit long.
    Aes,
    /// An AES-XTS key.
    /// Must be a plain byte file 512, or 1024 bit long.
    AesXts,
    /// A HMAC-SHA key.
    /// Must be a plain byte file 512, or 1024 bit long.
    HmacSha,
    /// An elliptic curve private key.
    /// Must be a PEM or DER file.
    Ec,
}

impl Display for RetrieveableSecretInpKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Plain => "PLAINTEXT",
                Self::Aes => "AES KEY",
                Self::AesXts => "AES-XTS KEY",
                Self::HmacSha => "HMAC-SHA KEY",
                Self::Ec => "EC PRIVATE KEY",
            }
        )
    }
}

// all members s390x only
#[derive(Args, Debug)]
pub struct AddSecretOpt {
    /// Specify the request to be sent.
    #[arg(value_name = "FILE", value_hint = ValueHint::FilePath,)]
    #[cfg(target_arch = "s390x")]
    pub input: String,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug, Default)]
#[cfg(target_arch = "s390x")]
pub enum ListSecretOutputType {
    /// Human-focused, non-parsable output format
    #[default]
    Human,
    /// Use yaml format.
    Yaml,
    /// Use the format the ultravisor uses to pass the list.
    Bin,
}

// all members s390x only
#[derive(Args, Debug)]
pub struct ListSecretOpt {
    /// Store the result in FILE
    #[arg(value_name = "FILE", default_value = STDOUT, value_hint = ValueHint::FilePath,)]
    #[cfg(target_arch = "s390x")]
    pub output: String,

    /// Define the output format of the list.
    #[arg(long, value_enum, default_value_t)]
    #[cfg(target_arch = "s390x")]
    pub format: ListSecretOutputType,
}

#[derive(Args, Debug)]
pub struct VerifyOpt {
    /// Specify the request to be checked.
    #[arg(value_name = "FILE", value_hint = ValueHint::FilePath,)]
    pub input: String,

    /// Certificate containing a public key used to verify the user data signature.
    ///
    /// Specifies a public key used to verify the user-data signature. The file must be a X509
    /// certificate in DSA or PEM format. The certificate must hold the public EC, RSA 2048, or RSA
    /// 3072 key corresponding to the private user-key used during `create`. No chain of trust is
    /// established. Ensuring that the certificate can be trusted is the responsibility of  the
    /// user. The EC key must use the NIST/SECG curve over a 521 bit prime field (secp521r1).
    #[arg(long, value_name = "FILE", value_hint = ValueHint::FilePath,)]
    pub user_cert: Option<String>,

    /// Store the result in FILE
    ///
    /// If the request contained abirtary user-data the output contains this user-data with padded
    /// zeros if available.
    #[arg(short, long, value_name = "FILE", default_value = STDOUT, value_hint = ValueHint::FilePath,)]
    pub output: String,
}

// all members s390x only
#[derive(Args, Debug)]
pub struct RetrSecretOptions {
    /// Specify the secret ID to be retrieved.
    ///
    /// Input type depends on '--inform'. If `yaml` (default) is specified, it must be a yaml
    /// created by the create subcommand of this tool. If `hex` is specified, it must be a hex
    /// 32-byte unsigned big endian number string. Leading zeros are required.
    #[cfg(target_arch = "s390x")]
    #[arg(value_name = "ID", value_hint = ValueHint::FilePath)]
    pub input: String,

    /// Specify the output path to place the secret value
    #[cfg(target_arch = "s390x")]
    #[arg(short, long, value_name = "FILE", default_value = STDOUT, value_hint = ValueHint::FilePath)]
    pub output: String,

    /// Define input type for the Secret ID
    #[cfg(target_arch = "s390x")]
    #[arg(long, value_enum, default_value_t)]
    pub inform: RetrInpFmt,

    /// Define the output format for the retrieved secret
    #[cfg(target_arch = "s390x")]
    #[arg(long, value_enum, default_value_t)]
    pub outform: RetrOutFmt,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug, Default)]
pub enum RetrInpFmt {
    /// Use a yaml file
    #[default]
    Yaml,
    /// Use a hex string.
    Hex,
    /// Use a name-string. Will hash it if no secret with the name found.
    Name,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug, Default)]
pub enum RetrOutFmt {
    /// Write the secret as PEM.
    ///
    /// File starts with `-----BEGIN IBM PROTECTED KEY----` and `-----BEGIN
    /// PLAINTEXT SECRET-----` for plaintext secrets it contains one header
    /// line with the type information and the base64 protected key
    #[default]
    Pem,
    /// Write the secret in binary.
    Bin,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Create a new add-secret request.
    ///
    /// Create add-secret requests for IBM Secure Execution guests. Only create these requests in a
    /// trusted environment, such as your workstation. The 'pvattest create' command creates a
    /// randomly generated key to protect the request. The generated requests can then be added on
    /// an IBM Secure Execution guest using 'pvsecret add'. The guest can then use the secrets with
    /// the use case depending on the secret type.
    Create(Box<CreateSecretOpt>),

    /// Submit an add-secret request to the Ultravisor (s390x only).
    ///
    /// Perform an add-secret request using a previously generated add-secret request. Only
    /// available on s390x.
    Add(AddSecretOpt),

    /// Lock the secret-store (s390x only).
    ///
    /// Lock the secret store (s390x only). After this command executed successfully, all
    /// subsequent add-secret requests will fail. Only available on s390x.
    Lock,

    /// List all ultravisor secrets (s390x only).
    ///
    /// Lists the IDs of all non-null secrets currently stored in the ultravisor for the currently
    /// running IBM Secure Execution guest. Only available on s390x.
    List(ListSecretOpt),

    /// Verify that an add-secret request is sane.
    ///
    /// Verifies that the given request is an add-secret request by testing for some values to be
    /// present. If the request contains signed user-data, the signature is verified with the
    /// provided key. Outputs the arbitrary user-data.
    Verify(VerifyOpt),

    /// Retrieve a secret from the UV secret store (s390x only).
    #[command(visible_alias = "retr")]
    Retrieve(RetrSecretOptions),

    /// Print version information and exit.
    #[command(aliases(["--version"]), hide(true))]
    Version,
}

/// Additional checks to assure, option integrity
pub fn validate_cli(cli: &CliOptions) -> Result<(), clap::Error> {
    if let Command::Create(opt) = &cli.cmd {
        if let AddSecretType::Association {
            name,
            stdout,
            input_secret: _,
            output_secret: secret_out,
        } = &opt.secret
        {
            if *stdout {
                return Ok(());
            }
            if secret_out == &Some(format!("{name}.yaml")) {
                return Err(CliOptions::command().error(
                    ValueValidation,
                    format!("Secret output file and the secret name '{name}.yaml' are the same."),
                ));
            }
            if format!("{name}.yaml") == opt.output {
                return Err(CliOptions::command().error(
                    ValueValidation,
                    format!(
                        "output file and the secret name '{}' are the same.",
                        &opt.output
                    ),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[rustfmt::skip]
    fn cli_args() {
        //Verify only that some arguments are optional, we do not want to test clap, only the
        //configuration
        let valid_args = [
            vec!["pvsecret", "lock"],
            vec!["pvsecret", "version"],
            vec!["pvsecret", "list"],
            #[cfg(target_arch = "s390x")]
            vec!["pvsecret", "add", "abc"],
            #[cfg(not(target_arch = "s390x"))]
            vec!["pvsecret", "add"],
            vec!["pvsecret", "create", "-k", "abc", "--hdr", "abc", "-o", "abc", "--no-verify", "meta"],
            vec!["pvsecret", "create", "-k", "abc", "--hdr", "abc", "-o", "abc", "--no-verify", "association", "name" ],
            // verify that arguments stay backwards compatible
            vec!["pvsecret", "create", "-k", "abc,cdef", "--hdr", "abc", "-o", "abc", "-C", "uuu,ggg", "--crl", "yyy,hhh", "--root-ca", "tttt",
                 "--extension-secret", "fff", "--cuid", "cuid", "--flags", "disable-dump", "meta"],
            vec!["pvsecret", "create", "--host-key-document", "abc", "-k", "y", "--hdr", "abc", "-o", "abc", "--cert", "uuu", "--crl", "yyy",
                "--root-ca", "tttt", "--cck", "cck", "--cuid-hex", "0x11223344556677889900aabbccddeeff", "--pcf", "0x123", "association", "name", "--stdout",
                "--output-secret", "secret"],
            vec!["pvsecret", "create", "-k", "abc", "--hdr", "abc", "-o", "abc", "--no-verify", "association", "name", "--output-secret", "secret"],
            #[cfg(target_arch = "s390x")]
            vec!["pvsecret", "list", "--format", "human"],
            #[cfg(target_arch = "s390x")]
            vec!["pvsecret", "list", "--format", "yaml"],
            #[cfg(target_arch = "s390x")]
            vec!["pvsecret", "list", "--format", "bin"],
        ];
        // Test for the minimal amount of flags to yield an invalid combination
        let invalid_args = [
            vec!["pvsecret"],
            vec!["pvsecret", "list", "--yaml", "--bin"],
            vec!["pvsecret", "create", "--hdr", "abc", "-o", "abc", "--no-verify" ,"null"],
            vec!["pvsecret", "create", "-k", "abc", "-o", "abc", "--no-verify", "null"],
            vec!["pvsecret", "create", "-k", "abc", "--hdr", "abc", "--no-verify", "null"],
            vec!["pvsecret", "create", "-k", "abc", "--hdr", "abc", "-o", "abc", "null"],
            vec!["pvsecret", "create", "-k", "abc", "--hdr", "abc", "-o", "abc", "--cck", "abc", "--extension_secret", "abc", "--no-verify", "null"],
            vec!["pvsecret", "create", "-k", "abc", "--hdr", "abc", "-o", "abc", "--no-verify", "--flags", "disable-dump", "--pcf", "0", "null"],
            vec!["pvsecret", "create", "-k", "abc", "--hdr", "abc", "-o", "abc", "--no-verify", "--cuid", "abc", "--cuid_hex", "9",  "null"],
            vec!["pvsecret", "create", "-k", "abc", "--hdr", "abc", "-o", "abc", "--no-verify", "association"],
            vec!["pvsecret", "create", "-k", "abc", "--hdr", "abc", "-o", "abc", "--no-verify", "association", "name", "--output-secret", "secret", "--input-secret", "secret"],
            ];
        for arg in valid_args {
            let res = CliOptions::try_parse_from(&arg);
            if let Err(e) = &res {
                println!("arg: {arg:?}");
                println!("{e}");
            }
            assert!(res.is_ok());
        }

        for arg in invalid_args {
            let res = CliOptions::try_parse_from(&arg);
            assert!(res.is_err());
        }
    }

    #[test]
    fn verify_cli() {
        use clap::CommandFactory;
        CliOptions::command().debug_assert()
    }
}
