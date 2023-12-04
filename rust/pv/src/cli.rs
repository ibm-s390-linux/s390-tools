// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

use crate::misc::{create_file, open_file};
use crate::Result;
use clap::{ArgGroup, Args, ValueHint};
use std::io::{Read, Write};

/// CLI Argument collection for handling certificates.
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
    pub host_key_documents: Vec<String>,

    /// Disable the host-key document verification.
    ///
    /// Does not require the host-key documents to be valid.
    /// Do not use for a production request unless you verified the host-key document before.
    #[arg(long)]
    pub no_verify: bool,

    /// Use FILE as a certificate to verify the host-key(s).
    ///
    /// The certificates are used to establish a chain of trust for the verification
    /// of the host-key documents. Specify this option twice to specify the IBM Z signing key and
    /// the intermediate CA certificate (signed by the rootCA).
    #[arg(
        short= 'C',
        long = "cert",
        value_name = "FILE",
        alias("crt"),
        value_hint = ValueHint::FilePath,
        use_value_delimiter = true,
        value_delimiter = ',',
    )]
    pub certs: Vec<String>,

    /// Use FILE as a certificate revocation list.
    ///
    /// That list is used to check whether a certificate of the chain of
    /// trust is revoked. Specify this option multiple times to use multiple CRLs.
    #[arg(
        long = "crl",
        requires("certs"),
        value_name = "FILE",
        value_hint = ValueHint::FilePath,
        use_value_delimiter = true,
        value_delimiter = ',',
    )]
    pub crls: Vec<String>,

    /// Make no attempt to download CRLs.
    #[arg(long, requires("certs"))]
    pub offline: bool,

    /// Use FILE as the root-CA certificate for the verification.
    ///
    /// If omitted, the system wide root CAs installed on the system are used.
    /// Use this only if you trust the specified certificate.
    #[arg(long, requires("certs"))]
    pub root_ca: Option<String>,
}

impl CertificateOptions {
    /// Returns the verifier of this [`CertificateOptions`] based on the given CLI options.
    ///
    /// # Errors
    ///
    /// This function will return an error if [`crate::request::HkdVerifier`] cannot be created.
    pub fn verifier(&self) -> Result<Box<dyn crate::verify::HkdVerifier>> {
        use crate::verify::{CertVerifier, NoVerifyHkd};
        match self.no_verify {
            true => {
                log::warn!(
                    "Host-key document verification is disabled. The secret may not be protected."
                );
                Ok(Box::new(NoVerifyHkd))
            }
            false => Ok(Box::new(CertVerifier::new(
                &self.certs,
                &self.crls,
                &self.root_ca,
                self.offline,
            )?)),
        }
    }
}

/// stdout
pub const STDOUT: &str = "-";
/// stdin
pub const STDIN: &str = "-";

/// Converts an argument value into a Writer.
pub fn get_writer_from_cli_file_arg(path: &str) -> Result<Box<dyn Write>> {
    if path == STDOUT {
        Ok(Box::new(std::io::stdout()))
    } else {
        Ok(Box::new(create_file(path)?))
    }
}

/// Converts an argument value into a Reader.
pub fn get_reader_from_cli_file_arg(path: &str) -> Result<Box<dyn Read>> {
    if path == STDIN {
        Ok(Box::new(std::io::stdin()))
    } else {
        Ok(Box::new(open_file(path)?))
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
