// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023
//
//! Functions around handling the pvapconfig configuration file
//

use openssl::sha::sha256;
use pv_core::misc::encode_hex;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_yaml::{self};
use std::fs::File;
use std::slice::Iter;

pub const STR_MODE_EP11: &str = "ep11";
pub const STR_MODE_ACCEL: &str = "accel";

const RE_EP11_MKVP_32: &str = r"^(0x)?([[:xdigit:]]{32})$";
const RE_EP11_MKVP_64: &str = r"^(0x)?([[:xdigit:]]{64})$";
const RE_SERIALNR: &str = r"^(\S{16})$";
const RE_EP11_GEN: &str = r"^cex(8)$";
const RE_ACCEL_GEN: &str = r"^cex([4-8])$";
const RE_SECRETID: &str = r"^(0x)?([[:xdigit:]]{64})$";

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(default, deny_unknown_fields)]
pub struct ApConfigEntry {
    pub name: String,        // name and description are unmodified from the config file
    pub description: String, // accel after validation     ep11 after validation
    pub mode: String,        // "accel"                    "ep11"
    pub mkvp: String,        // empty                      32 hex lowercase characters
    pub serialnr: String,    // empty                      empty or 16 non-whitespace characters
    pub mingen: String,      // empty or "cex4"..."cex8"   empty or "cex8"
    pub secretid: String,    // empty                      64 hex lowercase characters
}

impl ApConfigEntry {
    fn validate_secretid(&mut self) -> Result<(), String> {
        // either secret id or name may be given
        if self.secretid.is_empty() && self.name.is_empty() {
            return Err("Neither secretid nor name given.".to_string());
        }
        // if name is given, calculate sha256 digest for this name
        // test for the hash calculated here can be done with openssl:
        // echo -n "Hello" >in.bin; openssl dgst -sha256 -binary -out out.bin in.bin; hexdump -C
        // out.bin
        if self.name.is_empty() {
            return Ok(());
        }
        let hash = sha256(self.name.as_bytes());
        let hashstr = encode_hex(hash);
        // if there is a secretid given, this must match to the hash
        if !self.secretid.is_empty() {
            if self.secretid != hashstr {
                return Err("Mismatch between sha256(name) and secretid.".to_string());
            }
        } else {
            self.secretid = hashstr;
        }
        Ok(())
    }

    /// # Panics
    /// Panics if the compilation of a static regular expression fails.
    fn validate_ep11_entry(&mut self) -> Result<(), String> {
        // mkvp is required
        let mut mkvp = self.mkvp.trim().to_lowercase();
        if mkvp.is_empty() {
            return Err("Mkvp value missing.".to_string());
        }
        // either 64 hex or 32 hex
        if Regex::new(RE_EP11_MKVP_64).unwrap().is_match(&mkvp) {
            // need to cut away the last 32 hex characters
            mkvp = String::from(&mkvp[..mkvp.len() - 32])
        } else if Regex::new(RE_EP11_MKVP_32).unwrap().is_match(&mkvp) {
            // nothing to do here
        } else {
            return Err(format!("Mkvp value '{}' is not valid.", &self.mkvp));
        }
        self.mkvp = match mkvp.strip_prefix("0x") {
            Some(rest) => String::from(rest),
            None => mkvp,
        };
        // serialnr is optional
        let serialnr = self.serialnr.trim().to_string();
        if !serialnr.is_empty() && !Regex::new(RE_SERIALNR).unwrap().is_match(&serialnr) {
            return Err(format!("Serialnr value '{}' is not valid.", &self.serialnr));
        }
        self.serialnr = serialnr;
        // mingen is optional, but if given only CEX8 is valid
        let mingen = self.mingen.trim().to_lowercase();
        if !mingen.is_empty() && !Regex::new(RE_EP11_GEN).unwrap().is_match(&mingen) {
            return Err(format!("Mingen value '{}' is not valid.", &self.mingen));
        }
        self.mingen = mingen;
        // secretid or name is required
        let secretid = self.secretid.trim().to_lowercase();
        if !secretid.is_empty() && !Regex::new(RE_SECRETID).unwrap().is_match(&secretid) {
            return Err(format!("Secretid value '{}' is not valid.", &self.secretid));
        }
        self.secretid = match secretid.strip_prefix("0x") {
            Some(rest) => String::from(rest),
            None => secretid,
        };
        // name is optional, ignored here
        // description is optional, ignored here
        // but the secretid needs some more validation
        self.validate_secretid()
    }

    /// # Panics
    /// Panics if the compilation of a static regular expression fails.
    fn validate_accel_entry(&mut self) -> Result<(), String> {
        // mkvp is ignored
        self.mkvp.clear();
        // serialnr is ignored
        self.serialnr.clear();
        // mingen is optional, but if given must match to CEX4..CEX8
        let mingen = self.mingen.trim().to_lowercase();
        if !mingen.is_empty() && !Regex::new(RE_ACCEL_GEN).unwrap().is_match(&mingen) {
            return Err(format!("Mingen value '{}' is not valid.", &self.mingen));
        }
        self.mingen = mingen;
        // secretid is ignored
        self.secretid.clear();
        // name is optional, ignored here
        // description is optional, ignored here
        Ok(())
    }

    fn validate(&mut self) -> Result<(), String> {
        // trim name
        self.name = self.name.trim().to_string();
        // mode is always required
        let mode = self.mode.trim().to_lowercase();
        match mode.as_str() {
            STR_MODE_EP11 => {
                self.mode = mode;
                self.validate_ep11_entry()?;
            }
            STR_MODE_ACCEL => {
                self.mode = mode;
                self.validate_accel_entry()?;
            }
            _ => return Err(format!("Unknown or invalid mode '{mode}'.")),
        }
        Ok(())
    }
}

/// Wrapper object around Vector of ApConfigEntry
#[derive(Default)]
pub struct ApConfigList(Vec<ApConfigEntry>);

impl ApConfigList {
    #[cfg(test)] // only used in test code
    pub fn from_apconfigentry_vec(apconfigs: Vec<ApConfigEntry>) -> Self {
        Self(apconfigs)
    }

    pub fn iter(&self) -> Iter<'_, ApConfigEntry> {
        self.0.iter()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn read_yaml_file(fname: &str) -> Result<Vec<ApConfigEntry>, String> {
        let file = match File::open(fname) {
            Ok(f) => f,
            Err(err) => {
                return Err(format!(
                    "Failure to open AP config file {fname}: {err:?}"
                ))
            }
        };
        match serde_yaml::from_reader(file) {
            Ok(cfg) => Ok(cfg),
            Err(err) => Err(format!(
                "Failure parsing AP config file {fname}: {err:?}"
            )),
        }
    }

    fn validate(config: &mut [ApConfigEntry]) -> Result<(), String> {
        for (i, entry) in config.iter_mut().enumerate() {
            let ename = if !entry.name.trim().is_empty() {
                format!("AP config entry {} '{}'", i, entry.name.trim())
            } else {
                format!("AP config entry {i}")
            };
            if let Err(err) = &entry.validate() {
                return Err(format!("{ename}: {err}"));
            }
        }
        Ok(())
    }

    /// Read in and validate the yaml configuration from a file.
    /// Returns a Result with Ok(ApConfigList) on success
    /// or an Err(errorstring) on failure.
    pub fn read_and_validate_yaml_file(fname: &str) -> Result<Self, String> {
        let mut apconfig = Self::read_yaml_file(fname)?;
        Self::validate(&mut apconfig)?;
        Ok(Self(apconfig))
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::env;
    use std::fs;
    use std::io::Write;

    const GOOD_CONFIGS: [&str; 8] = [
        "# good test 1
- name: my Accelerator
  mode: AcCel
  mingen: Cex7\n",
        "# good test 2
- name: my Accelerator 2
  description: Accelerator entry with description
  mode: Accel\n",
        "# good test 3
- name: my EP11 APQN 1
  mode: Ep11
  mkvp:  0xDB3C3B3C3F097DD55EC7EB0E7FDBCB93
  serialnr: 93AADFK719460083
  secretid: 0xBC9d46c052BC3574454C5715757274629a283767ed237922cfb8651c0e77320A\n",
        "# good test 4
- name: my EP11 APQN 2
  mode: EP11
  mkvp: 0xdb3c3b3c3f097dd55ec7eb0e7fdbcb93
  serialnr: 93aaDHzu42082261
  secretid: 0x2ca853f959fc5ce5f1888cb48dae39514a27bb66520ac85f6073a7f678d262c0\n",
        "# good test 5
- name: my EP11 APQN 3
  mode: EP11
  mkvp: 0xdb3c3b3c3f097dd55ec7eb0e7fdbcb93db3c3b3c3f097dd55ec7eb0e7fdbcb93
  serialnr: 93aaDHzu42082261
  secretid: 0xd146c9ae77cdff25fa87a5b3487587dc29a4e391b315c98570e8fa2e2ec91454\n",
        "# no name but secretid given
- mode: EP11
  mkvp: 0xdb3c3b3c3f097dd55ec7eb0e7fdbcb93
  secretid: 0x0767668dd22f23fa675c4641e04bb4e991f443be4df13ce3896b8eeca59fcc10\n",
        "# no secretid but name given
- mode: EP11
  name: My-EP11-AP-config
  mkvp: 0xdb3c3b3c3f097dd55ec7eb0e7fdbcb93\n",
        "# secretid and name given
- mode: EP11
  name: My-EP11-AP-config
  mkvp: 0xdb3c3b3c3f097dd55ec7eb0e7fdbcb93
  secretid: 0x0767668dd22f23fa675c4641e04bb4e991f443be4df13ce3896b8eeca59fcc10\n",
    ];

    const BAD_CONFIGS: [&str; 12] = [
        "# mode missing
- name: bad test 1
  mkvp: 0xdb3c3b3c3f097dd55ec7eb0e7fdbcb93
  secretid: 0x0767668dd22f23fa675c4641e04bb4e991f443be4df13ce3896b8eeca59fcc10\n",
        "# invalid mode
- name: bad test 2
  mode: CCA
  mkvp: 0xdb3c3b3c3f097dd55ec7eb0e7fdbcb93
  secretid: 0x0767668dd22f23fa675c4641e04bb4e991f443be4df13ce3896b8eeca59fcc10\n",
        "# Accelerator with wrong CEX3
- name: bad test 3
  mode: Accel
  mingen: Cex3\n",
        "# Accelerator with wrong CEX9
- name: bad test 4
  mode: Accel
  mingen: CEX9\n",
        "# EP11 with mkvp missing
- name: bad test 5
  mode: EP11
  serialnr: 93AADHZU42082261\n",
        "# EP11 with non hex mkvp
- name: bad test 6
  mode: EP11
  mkvp: 0xabcdefghijklmnopqqponmlkjihgfedcba
  serialnr: 93AADHZU42082261\n",
        "# EP11 with mkvp too big
- name: bad test 7
  mode: EP11
  mkvp: 0xdb3c3b3c3f097dd55ec7eb0e7fdbcb93aa
  serialnr: 93AADHZU42082261\n",
        "# EP11 with mkvp too small
- name: bad test 8
  mode: EP11
  mkvp: 0xdb3c3b3c3f097dd55ec7eb0e7fdbcb
  serialnr: 93AADHZU42082261\n",
        "# EP11 with invalid CEXx
- name: bad test 9
  mode: EP11
  mingen: CEX7
  mkvp: 0x00112233445566778899aabbccddeeff
  serialnr: 93AADHZU42082261\n",
        "# EP11 with invalid Serialnr
- name: bad test 10
  mode: EP11
  mkvp: 0x00112233445566778899aabbccddeeff
  serialnr: 93AADHZU4208226\n",
        "# EP11 with invalid Serialnr
- name: bad test 11
  mode: EP11
  mkvp: 0x00112233445566778899aabbccddeeff
  serialnr: 93AAD ZU42082261\n",
        "# EP11 with sha256(name) != secretid
- name: bad test 12
  mode: EP11
  mkvp: 0x00112233445566778899aabbccddeeff
  serialnr: AABBCCDDEEFFGGHH
  secretid: 0x2ca853f959fc5ce5f1888cb48dae39514a27bb66520ac85f6073a7f678d262c0\n",
    ];

    const BAD_DESERIALIZE: [&str; 2] = [
        "/*\ntotal nonsense\n */\n",
        "# wrong/unknown field
- name: de-serialize failure 1
  type: EP11\n",
    ];

    fn write_yaml_config_to_temp_file(content: &str) -> Result<String, String> {
        let dir = env::temp_dir();
        let rnd = rand::random::<u32>();
        let fname = format!("{}/config-test-{}.yaml", dir.to_str().unwrap(), rnd);
        let mut f = match File::create(&fname) {
            Ok(f) => f,
            Err(_) => return Err(format!("Failure creating temp file '{fname}'.")),
        };
        match f.write_all(content.as_bytes()) {
            Ok(_) => Ok(fname),
            Err(_) => {
                fs::remove_file(&fname).ok();
                Err(format!("Failure writing to temp file '{fname}'."))
            }
        }
    }

    #[test]
    fn test_good_yaml() {
        for yaml in GOOD_CONFIGS {
            let f = write_yaml_config_to_temp_file(yaml).unwrap();
            let config = ApConfigList::read_and_validate_yaml_file(&f).unwrap();
            assert!(!config.is_empty());
            fs::remove_file(&f).ok();
        }
    }
    #[test]
    fn test_bad_yaml() {
        for yaml in BAD_CONFIGS {
            let f = write_yaml_config_to_temp_file(yaml).unwrap();
            let r = ApConfigList::read_and_validate_yaml_file(&f);
            assert!(r.is_err());
            fs::remove_file(&f).ok();
        }
    }
    #[test]
    fn test_invalid_deserizalize() {
        for yaml in BAD_DESERIALIZE {
            let f = write_yaml_config_to_temp_file(yaml).unwrap();
            let r = ApConfigList::read_and_validate_yaml_file(&f);
            assert!(r.is_err());
            fs::remove_file(&f).ok();
        }
    }
    #[test]
    fn test_sha256() {
        assert!(
            encode_hex(sha256("Hello".as_bytes()))
                == "185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969"
        );
        assert!(
            encode_hex(sha256("SECRET1".as_bytes()))
                == "03153249db7ce46b0330ffb1a760b59710531af08ec4d7f8424a6870fae49360"
        );
        assert!(
            encode_hex(sha256("SECRET2".as_bytes()))
                == "258499e710e0bd3bb878d6bac7e478b30f3f3e72566989f638c4143d14f6c0b6"
        );
    }
}
