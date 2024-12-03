// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023, 2024

use clap::{ArgAction, ArgGroup, Args, Command, ValueHint};
use log::{info, warn, LevelFilter};
use pv::misc::read_file;
use pv::{
    misc::{create_file, open_file, read_certs},
    request::{
        openssl::pkey::{PKey, Public},
        HkdVerifier,
    },
    Error, Result,
};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// CLI Argument collection for handling host-keys, IBM signing keys, and certificates.
#[derive(Args, Debug, PartialEq, Eq, Default)]
#[command(
    group(ArgGroup::new("pv_verify").required(true).args(["no_verify", "certs"])),
    )]
pub struct CertificateOptions {
    /// Use FILE as a host-key document.
    ///
    /// Can be specified multiple times and must be used at least once.
    #[arg(
        short = 'k',
        long = "host-key-document",
        value_name = "FILE",
        required = true,
        value_hint = ValueHint::FilePath,
        use_value_delimiter = true,
        value_delimiter = ',',
        )]
    pub host_key_documents: Vec<PathBuf>,

    /// Disable the host-key document verification.
    ///
    /// Does not require the host-key documents to be valid.
    /// Do not use for a production request unless you verified the host-key document beforehand.
    #[arg(long)]
    pub no_verify: bool,

    /// Use FILE as a certificate to verify the host-key or keys.
    ///
    /// The certificates are used to establish a chain of trust for the verification
    /// of the host-key documents. Specify this option twice to specify the IBM Z signing key and
    /// the intermediate CA certificate (signed by the root CA).
    #[arg(
        short= 'C',
        long = "cert",
        value_name = "FILE",
        alias("crt"),
        value_hint = ValueHint::FilePath,
        use_value_delimiter = true,
        value_delimiter = ',',
    )]
    pub certs: Vec<PathBuf>,

    /// Use FILE as a certificate revocation list.
    ///
    /// The list is used to check whether a certificate of the chain of
    /// trust is revoked. Specify this option multiple times to use multiple CRLs.
    #[arg(
        long = "crl",
        requires("certs"),
        value_name = "FILE",
        value_hint = ValueHint::FilePath,
        use_value_delimiter = true,
        value_delimiter = ',',
    )]
    pub crls: Vec<PathBuf>,

    /// Make no attempt to download CRLs.
    #[arg(long, requires("certs"))]
    pub offline: bool,

    /// Use FILE as the root-CA certificate for the verification.
    ///
    /// If omitted, the system wide-root CAs installed on the system are used.
    /// Use this only if you trust the specified certificate.
    #[arg(long, requires("certs"))]
    pub root_ca: Option<PathBuf>,
}

impl CertificateOptions {
    /// Returns the verifier of this [`CertificateOptions`] based on the given CLI options.
    ///
    /// - `protectee`: what you want to create. e.g. add-secret request or SE-image
    ///
    /// # Errors
    ///
    /// This function will return an error if [`crate::request::HkdVerifier`] cannot be created.
    fn verifier(&self, protectee: &'static str) -> Result<Box<dyn HkdVerifier>> {
        use pv::request::{CertVerifier, NoVerifyHkd};
        match self.no_verify {
            true => {
                log::warn!(
                    "Host-key document verification is disabled. The {protectee} may not be protected."
                );
                Ok(Box::new(NoVerifyHkd))
            }
            false => Ok(Box::new(CertVerifier::new(
                &self.certs,
                &self.crls,
                self.root_ca.as_ref(),
                self.offline,
            )?)),
        }
    }

    /// Read the host-keys specified and verifies them if required
    ///
    /// - `protectee`: what you want to create. e.g. add-secret request or SE-image
    ///
    /// # Error
    /// Returns an error if something went wrong during parsing the HKDs, the verification chain
    /// could not built, or when the verification
    /// failed.
    pub fn get_verified_hkds(&self, protectee: &'static str) -> Result<Vec<PKey<Public>>> {
        let hkds = &self.host_key_documents;
        let verifier = self.verifier(protectee)?;

        let mut res = Vec::with_capacity(hkds.len());
        for hkd in hkds {
            let hk = read_file(hkd, "host-key document")?;
            let certs = read_certs(&hk).map_err(|source| Error::HkdNotPemOrDer {
                hkd: hkd.display().to_string(),
                source,
            })?;
            if certs.is_empty() {
                return Err(Error::NoHkdInFile(hkd.display().to_string()));
            }
            if certs.len() != 1 {
                warn!(
                    "The host-key document in '{}' contains more than one certificate!",
                    hkd.display()
                )
            }

            // Panic: len is == 1 -> unwrap will succeed/not panic
            let c = certs.first().unwrap();
            verifier.verify(c)?;
            res.push(c.public_key()?);
            info!("Use host-key document at '{}'", hkd.display());
        }
        Ok(res)
    }
}

/// stdout
pub const STDOUT: &str = "-";
/// stdin
pub const STDIN: &str = "-";

/// Converts an argument value into a Writer.
pub fn get_writer_from_cli_file_arg<P: AsRef<Path>>(path: P) -> Result<Box<dyn Write>> {
    if path.as_ref() == Path::new(STDOUT) {
        Ok(Box::new(std::io::stdout()))
    } else {
        Ok(Box::new(create_file(path)?))
    }
}

/// Converts an argument value into a Reader.
pub fn get_reader_from_cli_file_arg<P: AsRef<Path>>(path: P) -> Result<Box<dyn Read>> {
    if path.as_ref() == Path::new(STDIN) {
        Ok(Box::new(std::io::stdin()))
    } else {
        Ok(Box::new(open_file(path)?))
    }
}

/// Print an error that occurred during CLI parsing
pub fn print_cli_error(e: clap::Error, mut cmd: Command) -> ExitCode {
    let ret = if e.use_stderr() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    };
    // Ignore any errors during printing of the error
    let _ = e.format(&mut cmd).print();
    ret
}

/// Print an error to stderr
pub fn print_error<E>(e: &E, verbosity: LevelFilter) -> ExitCode
where
    // Error trait is not required, but here to limit the usage to errors
    E: AsRef<dyn std::error::Error> + std::fmt::Debug + std::fmt::Display,
{
    if verbosity > LevelFilter::Warn {
        // Debug formatter also prints the whole error stack
        // So only print it when on verbose
        eprintln!("error: {e:?}")
    } else {
        eprintln!("error: {e}")
    };
    ExitCode::FAILURE
}

#[derive(Args, Debug, Clone, Default)]
pub struct VerbosityOptions {
    #[arg(
        long,
        short = 'v',
        action = ArgAction::Count,
        global = true,
        display_order = 999,
    )]
    /// Provide more detailed output.
    verbose: u8,

    #[arg(
        long,
        short = 'q',
        action = ArgAction::Count,
        global = true,
        conflicts_with = "verbose",
        display_order = 999,
    )]
    /// Provide less output.
    quiet: u8,
}

const fn to_level_filter(v: u8) -> LevelFilter {
    match v {
        0 => LevelFilter::Off,
        1 => LevelFilter::Error,
        2 => LevelFilter::Warn,
        3 => LevelFilter::Info,
        4 => LevelFilter::Debug,
        5.. => LevelFilter::Trace,
    }
}

impl VerbosityOptions {
    fn verbosity(&self) -> u8 {
        (LevelFilter::Warn as i16 + self.verbose as i16 - self.quiet as i16)
            .clamp(u8::MIN.into(), u8::MAX.into()) as u8
    }

    pub fn to_level_filter(&self) -> LevelFilter {
        to_level_filter(self.verbosity())
    }
}

#[derive(Args, Debug, Clone, Default)]
pub struct DeprecatedVerbosityOptions {
    #[clap(flatten)]
    verbosity: VerbosityOptions,

    #[arg(
        short = 'V',
        action = ArgAction::Count,
        global = true,
        hide = true,
    )]
    /// Provide more detailed output.
    deprecated_verbose: u8,
}

impl DeprecatedVerbosityOptions {
    pub fn to_level_filter(&self) -> LevelFilter {
        if self.deprecated_verbose > 0 {
            // Use eprintln as the logger is most likely not yet initialized.
            eprintln!("WARNING: Use of deprecated flag '-V'. Use '-v' or '--verbose' instead.")
        }
        to_level_filter(
            self.verbosity
                .verbosity()
                .saturating_add(self.deprecated_verbose),
        )
    }
}

#[cfg(test)]
mod test {
    use clap::Parser;

    use super::*;

    #[test]
    #[rustfmt::skip]
    fn cli_args() {
        //Verify only that some arguments are optional, we do not want to test clap, only the
        //configuration
        let valid_args = [vec!["pgr", "-k", "hkd.crt", "--no-verify"], vec!["pgr", "-k", "hkd.crt", "--crt", "abc.crt"]];
        // Test for the minimal amount of flags to yield an invalid combination
        let invalid_args = [
            vec!["pgr", "-k", "hkd.crt"],
            vec!["pgr", "--no-verify", "--crt", "abc.crt"],
            vec!["pgr", "--no-verify", "--crt", "abc.crt", "--offline"],
            vec!["pgr", "--no-verify", "--crt", "abc.crt", "--crl", "abc.crl"],
            vec!["pgr", "--no-verify", "--crt", "abc.crt", "--root-ca", "root.crt"],
            vec!["pgr", "--offline"],
            vec!["pgr", "--crl", "abc.crl"],
            vec!["pgr", "--root-ca", "root.crt"],
        ];
        #[derive(Parser, Debug)]
        struct TestParser {
            #[command(flatten)]
            pub verify_args: CertificateOptions,
        }

        for arg in valid_args {
            let res = TestParser::try_parse_from(&arg);
            assert!(res.is_ok());
        }

        for arg in invalid_args {
            let res = TestParser::try_parse_from(&arg);
            assert!(res.is_err());
        }
    }
}
