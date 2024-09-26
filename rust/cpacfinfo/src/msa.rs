// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use crate::cli::Cli;
use core::fmt::{Display, Formatter, Result};
use serde::{Serialize, Serializer};
use utils::HexSlice;

/// Number of total function codes (0 to 127)
pub const NUMBER_FUNC_CODES: usize = 128;

/// Number of MSA levels starting with MSA (0) - MSA 13
pub const MSA_LEVEL_COUNT: u8 = 14;

/// enum of all supported instructions
#[derive(PartialEq, Clone, clap::ValueEnum, Serialize)]
#[allow(clippy::upper_case_acronyms)]
pub enum InstructionKind {
    /// introduced with MSA
    KM,
    /// introduced with MSA
    KMC,
    /// introduced with MSA
    KIMD,
    /// introduced with MSA
    KLMD,
    /// introduced with MSA
    KMAC,
    /// introduced with MSA 3
    PCKMO,
    /// introduced with MSA 4
    KMF,
    /// introduced with MSA 4
    KMCTR,
    /// introduced with MSA 4
    KMO,
    /// introduced with MSA 4
    PCC,
    /// introduced with MSA 5
    PRNO,
    /// introduced with MSA 8
    KMA,
    /// introduced with MSA 9
    KDSA,
}

/// enum of all MSA levels
#[derive(Clone, Default, PartialEq)]
#[allow(clippy::upper_case_acronyms)]
pub enum Msa {
    MSA,
    MSA1,
    MSA2,
    MSA3,
    MSA4,
    MSA5,
    MSA6,
    MSA7,
    MSA8,
    MSA9,
    MSA10,
    MSA11,
    MSA12,
    MSA13,
    #[default]
    UNKNOWN,
}

impl Serialize for Msa {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            Self::MSA => serializer.serialize_unit_variant("Msa", 0, "0"),
            Self::MSA1 => serializer.serialize_unit_variant("Msa", 1, "1"),
            Self::MSA2 => serializer.serialize_unit_variant("Msa", 2, "2"),
            Self::MSA3 => serializer.serialize_unit_variant("Msa", 3, "3"),
            Self::MSA4 => serializer.serialize_unit_variant("Msa", 4, "4"),
            Self::MSA5 => serializer.serialize_unit_variant("Msa", 5, "5"),
            Self::MSA6 => serializer.serialize_unit_variant("Msa", 6, "6"),
            Self::MSA7 => serializer.serialize_unit_variant("Msa", 7, "7"),
            Self::MSA8 => serializer.serialize_unit_variant("Msa", 8, "8"),
            Self::MSA9 => serializer.serialize_unit_variant("Msa", 9, "9"),
            Self::MSA10 => serializer.serialize_unit_variant("Msa", 10, "10"),
            Self::MSA11 => serializer.serialize_unit_variant("Msa", 11, "11"),
            Self::MSA12 => serializer.serialize_unit_variant("Msa", 12, "12"),
            Self::MSA13 => serializer.serialize_unit_variant("Msa", 13, "13"),
            Self::UNKNOWN => serializer.serialize_unit_variant("Msa", 14, "UNKNOWN"),
        }
    }
}

impl Display for Msa {
    fn fmt(&self, f: &mut Formatter) -> Result {
        match *self {
            Self::MSA => write!(f, "MSA   "),
            Self::MSA1 => write!(f, "MSA  1"),
            Self::MSA2 => write!(f, "MSA  2"),
            Self::MSA3 => write!(f, "MSA  3"),
            Self::MSA4 => write!(f, "MSA  4"),
            Self::MSA5 => write!(f, "MSA  5"),
            Self::MSA6 => write!(f, "MSA  6"),
            Self::MSA7 => write!(f, "MSA  7"),
            Self::MSA8 => write!(f, "MSA  8"),
            Self::MSA9 => write!(f, "MSA  9"),
            Self::MSA10 => write!(f, "MSA 10"),
            Self::MSA11 => write!(f, "MSA 11"),
            Self::MSA12 => write!(f, "MSA 12"),
            Self::MSA13 => write!(f, "MSA 13"),
            Self::UNKNOWN => write!(f, "UNKNOWN"),
        }
    }
}

/// converts Instruction enum to a string representation
impl Display for InstructionKind {
    fn fmt(&self, f: &mut Formatter) -> Result {
        match *self {
            Self::KM => write!(f, "KM"),
            Self::KMC => write!(f, "KMC"),
            Self::KIMD => write!(f, "KIMD"),
            Self::KLMD => write!(f, "KLMD"),
            Self::KMAC => write!(f, "KMAC"),
            Self::PCKMO => write!(f, "PCKMO"),
            Self::KMF => write!(f, "KMF"),
            Self::KMCTR => write!(f, "KMCTR"),
            Self::KMO => write!(f, "KMO"),
            Self::PCC => write!(f, "PCC"),
            Self::PRNO => write!(f, "PRNO"),
            Self::KMA => write!(f, "KMA"),
            Self::KDSA => write!(f, "KDSA"),
        }
    }
}

#[derive(Serialize, Default)]
pub struct MsaLevel {
    pub msa_level: Msa,
    total_functions: u8,
    pub available_functions: u8,
    #[serde(skip)]
    dynamic_total_functions: u8,
    #[serde(skip)]
    pub dynamic_available_functions: u8,
    pub stfle_bit: Option<u8>,
    pub enabled: bool,
}

impl MsaLevel {
    pub fn new(msa_level: Msa, stfle_bit: Option<u8>) -> Self {
        Self {
            msa_level,
            stfle_bit,
            ..Default::default()
        }
    }
}

impl Display for MsaLevel {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "{} ", self.msa_level)?;
        match self.stfle_bit {
            Some(bit) => write!(f, "STFLE bit [ {:>3} ] : ", bit)?,
            None => write!(f, "                  : ")?,
        }
        match self.enabled {
            true => write!(f, "    AVAILABLE")?,
            false => write!(f, "NOT AVAILABLE")?,
        }
        write!(
            f,
            " ( {:>2} / {:<2} functions available )",
            self.dynamic_available_functions, self.dynamic_total_functions
        )
    }
}

#[derive(Serialize, Clone, Default)]
pub struct Function {
    name: String,
    pub function_code: u8,
    pub available: bool,
    #[serde(skip)]
    pub msa: Msa,
}

impl Function {
    pub fn new(fc: u8, msa: Msa, name: &str) -> Self {
        Self {
            function_code: fc,
            name: name.to_string(),
            msa,
            ..Default::default()
        }
    }
}

impl Display for Function {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "({:3}) ", self.function_code)?;
        match self.available {
            true => write!(f, "[    AVAILABLE]")?,
            false => write!(f, "[NOT AVAILABLE]")?,
        }
        write!(f, " {}", self.name)
    }
}

#[derive(Serialize, Default)]
pub struct QueryAuthInfo {
    pub format: u8,
    pub hash_len: u16,
    pub version: u32,
    // #[serde(with = "hex::serde")]
    #[serde(serialize_with = "ser_hex")]
    pub hash: Vec<u8>,
}

impl Display for QueryAuthInfo {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "  Format: {}", self.format)?;
        if self.format != 0 {
            writeln!(f, " (unknown format)")?;
            return Ok(());
        }
        write!(f, "; Hash length: {}", self.hash_len)?;
        writeln!(f, "; IFCL version: {}", self.version)?;
        writeln!(f, "  Hash:")?;

        for chunk in self.hash.chunks(16) {
            writeln!(f, "    {:-}", HexSlice::from(chunk))?;
        }
        Ok(())
    }
}

#[derive(Serialize, Default)]
pub struct InstructionInfo {
    pub name: String,
    pub available: bool,
    pub stfle_bit: u8,
    #[serde(skip)]
    pub qai_available: bool,
    pub qai: QueryAuthInfo,
}

impl InstructionInfo {
    fn new(stfle_bit: u8, name: &str) -> Self {
        Self {
            stfle_bit,
            name: name.to_string(),
            ..Default::default()
        }
    }
}

#[derive(Serialize)]
pub struct Instruction {
    pub kind: InstructionKind,
    pub info: InstructionInfo,
    pub funcs: Vec<Function>,
}

impl Instruction {
    fn new(instruction: InstructionKind, stfle_bit: u8, name: &str) -> Self {
        Self {
            kind: instruction,
            info: InstructionInfo::new(stfle_bit, name),
            funcs: Vec::new(),
        }
    }

    pub fn add(&mut self, func: Function) {
        self.funcs.push(func);
    }
}

impl Display for Instruction {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "{} ({})", self.info.name, self.kind)
    }
}

/// returns stfle bit based on given MSA level
pub fn msa2stfle(msa_level: &Msa) -> Option<u8> {
    match msa_level {
        Msa::MSA => Some(17),
        Msa::MSA3 => Some(76),
        Msa::MSA4 => Some(77),
        Msa::MSA5 => Some(57),
        Msa::MSA8 => Some(146),
        Msa::MSA9 => Some(155),
        Msa::MSA12 => Some(86),
        _ => None,
    }
}

/// returns MSA level based on given u8
pub fn num2msa(num: u8) -> Option<Msa> {
    match num {
        0 => Some(Msa::MSA),
        1 => Some(Msa::MSA1),
        2 => Some(Msa::MSA2),
        3 => Some(Msa::MSA3),
        4 => Some(Msa::MSA4),
        5 => Some(Msa::MSA5),
        6 => Some(Msa::MSA6),
        7 => Some(Msa::MSA7),
        8 => Some(Msa::MSA8),
        9 => Some(Msa::MSA9),
        10 => Some(Msa::MSA10),
        11 => Some(Msa::MSA11),
        12 => Some(Msa::MSA12),
        13 => Some(Msa::MSA13),
        _ => None,
    }
}

/// Initializes all functions known by cpacfinfo
#[rustfmt::skip]
pub fn init_instructions(instructions: &mut Vec<Instruction>) {
    let mut km = Instruction::new(InstructionKind::KM, 17, "Cipher Message");
    km.add(Function::new(0, Msa::MSA, "KM-Query"));
    km.add(Function::new(1, Msa::MSA, "KM-DEA"));
    km.add(Function::new(2, Msa::MSA, "KM-TDEA-128"));
    km.add(Function::new(3, Msa::MSA, "KM-TDEA-192"));
    km.add(Function::new(9, Msa::MSA3, "KM-Encrypted-DEA"));
    km.add(Function::new(10, Msa::MSA3, "KM-Encrypted-TDEA-128"));
    km.add(Function::new(11, Msa::MSA3, "KM-Encrypted-TDEA-192"));
    km.add(Function::new(18, Msa::MSA1, "KM-AES-128"));
    km.add(Function::new(19, Msa::MSA2, "KM-AES-192"));
    km.add(Function::new(20, Msa::MSA2, "KM-AES-256"));
    km.add(Function::new(26, Msa::MSA3, "KM-Encrypted-AES-128"));
    km.add(Function::new(27, Msa::MSA3, "KM-Encrypted-AES-192"));
    km.add(Function::new(28, Msa::MSA3, "KM-Encrypted-AES-256"));
    km.add(Function::new(50, Msa::MSA4, "KM-XTS-AES-128"));
    km.add(Function::new(52, Msa::MSA4, "KM-XTS-AES-256"));
    km.add(Function::new(58, Msa::MSA4, "KM-XTS-Encrypted-AES-128"));
    km.add(Function::new(60, Msa::MSA4, "KM-XTS-Encrypted-AES-256"));
    km.add(Function::new(82, Msa::MSA10, "KM-FULL-XTS-AES-128"));
    km.add(Function::new(84, Msa::MSA10, "KM-FULL-XTS-AES-256"));
    km.add(Function::new(90, Msa::MSA10, "KM-FULL-XTS-Encrypted-AES-128"));
    km.add(Function::new(92, Msa::MSA10, "KM-FULL-XTS-Encrypted-AES-256"));
    km.add(Function::new(127, Msa::MSA13, "KM-Query-Authentication-Information"));

    let mut kmc = Instruction::new(InstructionKind::KMC, 17, "Cipher Message with Chaining");
    kmc.add(Function::new(0, Msa::MSA, "KMC-Query"));
    kmc.add(Function::new(1, Msa::MSA, "KMC-DEA"));
    kmc.add(Function::new(2, Msa::MSA, "KMC-TDEA-128"));
    kmc.add(Function::new(3, Msa::MSA, "KMC-TDEA-192"));
    kmc.add(Function::new(9, Msa::MSA3, "KMC-Encrypted-DEA"));
    kmc.add(Function::new(10, Msa::MSA3, "KMC-Encrypted-TDEA-128"));
    kmc.add(Function::new(11, Msa::MSA3, "KMC-Encrypted-TDEA-192"));
    kmc.add(Function::new(18, Msa::MSA1, "KMC-AES-128"));
    kmc.add(Function::new(19, Msa::MSA2, "KMC-AES-192"));
    kmc.add(Function::new(20, Msa::MSA2, "KMC-AES-256"));
    kmc.add(Function::new(26, Msa::MSA3, "KMC-Encrypted-AES-128"));
    kmc.add(Function::new(27, Msa::MSA3, "KMC-Encrypted-AES-192"));
    kmc.add(Function::new(28, Msa::MSA3, "KMC-Encrypted-AES-256"));
    kmc.add(Function::new(67, Msa::MSA1, "KMC-PRNG"));
    kmc.add(Function::new(127, Msa::MSA13, "KMC-Query-Authentication-Information"));

    let mut kimd = Instruction::new(InstructionKind::KIMD, 17, "Compute Intermediate Message Digest");
    kimd.add(Function::new(0, Msa::MSA, "KIMD-Query"));
    kimd.add(Function::new(1, Msa::MSA, "KIMD-SHA-1"));
    kimd.add(Function::new(2, Msa::MSA1, "KIMD-SHA-256"));
    kimd.add(Function::new(3, Msa::MSA2, "KIMD-SHA-512"));
    kimd.add(Function::new(32, Msa::MSA6, "KIMD-SHA3-224"));
    kimd.add(Function::new(33, Msa::MSA6, "KIMD-SHA3-256"));
    kimd.add(Function::new(34, Msa::MSA6, "KIMD-SHA3-384"));
    kimd.add(Function::new(35, Msa::MSA6, "KIMD-SHA3-512"));
    kimd.add(Function::new(36, Msa::MSA6, "KIMD-SHAKE-128"));
    kimd.add(Function::new(37, Msa::MSA6, "KIMD-SHAKE-256"));
    kimd.add(Function::new(65, Msa::MSA4, "KIMD-GHASH"));
    kimd.add(Function::new(127, Msa::MSA13, "KIMD-Query-Authentication-Information"));

    let mut klmd = Instruction::new(InstructionKind::KLMD, 17, "Compute Last Message Digest");
    klmd.add(Function::new(0, Msa::MSA, "KLMD-Query"));
    klmd.add(Function::new(1, Msa::MSA, "KLMD-SHA-1"));
    klmd.add(Function::new(2, Msa::MSA1, "KLMD-SHA-256"));
    klmd.add(Function::new(3, Msa::MSA2, "KLMD-SHA-512"));
    klmd.add(Function::new(32, Msa::MSA6, "KLMD-SHA3-224"));
    klmd.add(Function::new(33, Msa::MSA6, "KLMD-SHA3-256"));
    klmd.add(Function::new(34, Msa::MSA6, "KLMD-SHA3-384"));
    klmd.add(Function::new(35, Msa::MSA6, "KLMD-SHA3-512"));
    klmd.add(Function::new(36, Msa::MSA6, "KLMD-SHAKE-128"));
    klmd.add(Function::new(37, Msa::MSA6, "KLMD-SHAKE-256"));
    klmd.add(Function::new(127, Msa::MSA13, "KLMD-Query-Authentication-Information"));

    let mut kmac = Instruction::new(InstructionKind::KMAC, 17, "Compute Message Authentication Code");
    kmac.add(Function::new(0, Msa::MSA, "KMAC-Query"));
    kmac.add(Function::new(1, Msa::MSA, "KMAC-DEA"));
    kmac.add(Function::new(2, Msa::MSA, "KMAC-TDEA-128"));
    kmac.add(Function::new(3, Msa::MSA, "KMAC-TDEA-192"));
    kmac.add(Function::new(9, Msa::MSA3, "KMAC-Encrypted-DEA"));
    kmac.add(Function::new(10, Msa::MSA3, "KMAC-Encrypted-TDEA-128"));
    kmac.add(Function::new(11, Msa::MSA3, "KMAC-Encrypted-TDEA-192"));
    kmac.add(Function::new(18, Msa::MSA4, "KMAC-AES-128"));
    kmac.add(Function::new(19, Msa::MSA4, "KMAC-AES-192"));
    kmac.add(Function::new(20, Msa::MSA4, "KMAC-AES-256"));
    kmac.add(Function::new(26, Msa::MSA4, "KMAC-Encrypted-AES-128"));
    kmac.add(Function::new(27, Msa::MSA4, "KMAC-Encrypted-AES-192"));
    kmac.add(Function::new(28, Msa::MSA4, "KMAC-Encrypted-AES-256"));
    kmac.add(Function::new(112, Msa::MSA11, "KMAC-HMAC-SHA-224"));
    kmac.add(Function::new(113, Msa::MSA11, "KMAC-HMAC-SHA-256"));
    kmac.add(Function::new(114, Msa::MSA11, "KMAC-HMAC-SHA-384"));
    kmac.add(Function::new(115, Msa::MSA11, "KMAC-HMAC-SHA-512"));
    kmac.add(Function::new(120, Msa::MSA11, "KMAC-HMAC-Encrypted-SHA-224"));
    kmac.add(Function::new(121, Msa::MSA11, "KMAC-HMAC-Encrypted-SHA-256"));
    kmac.add(Function::new(122, Msa::MSA11, "KMAC-HMAC-Encrypted-SHA-384"));
    kmac.add(Function::new(123, Msa::MSA11, "KMAC-HMAC-Encrypted-SHA-512"));
    kmac.add(Function::new(127, Msa::MSA13, "KMAC-Query-Authentication-Information"));

    let mut pckmo = Instruction::new(InstructionKind::PCKMO, 76, "Perform Cryptographic Key Management Operation");
    pckmo.add(Function::new(0, Msa::MSA3, "PCKMO-Query"));
    pckmo.add(Function::new(1, Msa::MSA3, "PCKMO-Encrypt-DEA-Key"));
    pckmo.add(Function::new(2, Msa::MSA3, "PCKMO-Encrypt-TDEA-128-Key"));
    pckmo.add(Function::new(3, Msa::MSA3, "PCKMO-Encrypt-TDEA-192-Key"));
    pckmo.add(Function::new(18, Msa::MSA3, "PCKMO-Encrypt-AES-128-Key"));
    pckmo.add(Function::new(19, Msa::MSA3, "PCKMO-Encrypt-AES-192-Key"));
    pckmo.add(Function::new(20, Msa::MSA3, "PCKMO-Encrypt-AES-256-Key"));
    pckmo.add(Function::new(21, Msa::MSA10, "PCKMO-AES-XTS-128-Double"));
    pckmo.add(Function::new(22, Msa::MSA10, "PCKMO-AES-XTS-256-Double"));
    pckmo.add(Function::new(32, Msa::MSA9, "PCKMO-Encrypt-ECC-P256-Key"));
    pckmo.add(Function::new(33, Msa::MSA9, "PCKMO-Encrypt-ECC-P384-Key"));
    pckmo.add(Function::new(34, Msa::MSA9, "PCKMO-Encrypt-ECC-P521-Key"));
    pckmo.add(Function::new(40, Msa::MSA9, "PCKMO-Encrypt-ECC-Ed25519-Key"));
    pckmo.add(Function::new(41, Msa::MSA9, "PCKMO-Encrypt-ECC-Ed448-Key"));
    pckmo.add(Function::new(118, Msa::MSA11, "PCKMO-Encrypted-HMAC-512-KEY"));
    pckmo.add(Function::new(122, Msa::MSA11, "PCKMO-Encrypted-HMAC-1024-KEY"));
    pckmo.add(Function::new(127, Msa::MSA13, "PCKMO-Query-Authentication-Information"));

    let mut kmf = Instruction::new(InstructionKind::KMF, 77, "Cipher Message with Cipher Feedback");
    kmf.add(Function::new(0, Msa::MSA4, "KMF-Query"));
    kmf.add(Function::new(1, Msa::MSA4, "KMF-DEA"));
    kmf.add(Function::new(2, Msa::MSA4, "KMF-TDEA-128"));
    kmf.add(Function::new(3, Msa::MSA4, "KMF-TDEA-192"));
    kmf.add(Function::new(9, Msa::MSA4, "KMF-Encrypted-DEA"));
    kmf.add(Function::new(10, Msa::MSA4, "KMF-Encrypted-TDEA-128"));
    kmf.add(Function::new(11, Msa::MSA4, "KMF-Encrypted-TDEA-192"));
    kmf.add(Function::new(18, Msa::MSA4, "KMF-AES-128"));
    kmf.add(Function::new(19, Msa::MSA4, "KMF-AES-192"));
    kmf.add(Function::new(20, Msa::MSA4, "KMF-AES-256"));
    kmf.add(Function::new(26, Msa::MSA4, "KMF-Encrypted-AES-128"));
    kmf.add(Function::new(27, Msa::MSA4, "KMF-Encrypted-AES-192"));
    kmf.add(Function::new(28, Msa::MSA4, "KMF-Encrypted-AES-256"));
    kmf.add(Function::new(127, Msa::MSA13, "KMF-Query-Authentication-Information"));

    let mut kmctr = Instruction::new(InstructionKind::KMCTR, 77, "Cipher Message with Counter");
    kmctr.add(Function::new(0, Msa::MSA4, "KMCTR-Query"));
    kmctr.add(Function::new(1, Msa::MSA4, "KMCTR-DEA"));
    kmctr.add(Function::new(2, Msa::MSA4, "KMCTR-TDEA-128"));
    kmctr.add(Function::new(3, Msa::MSA4, "KMCTR-TDEA-192"));
    kmctr.add(Function::new(9, Msa::MSA4, "KMCTR-Encrypted-DEA"));
    kmctr.add(Function::new(10, Msa::MSA4, "KMCTR-Encrypted-TDEA-128"));
    kmctr.add(Function::new(11, Msa::MSA4, "KMCTR-Encrypted-TDEA-192"));
    kmctr.add(Function::new(18, Msa::MSA4, "KMCTR-AES-128"));
    kmctr.add(Function::new(19, Msa::MSA4, "KMCTR-AES-192"));
    kmctr.add(Function::new(20, Msa::MSA4, "KMCTR-AES-256"));
    kmctr.add(Function::new(26, Msa::MSA4, "KMCTR-Encrypted-AES-128"));
    kmctr.add(Function::new(27, Msa::MSA4, "KMCTR-Encrypted-AES-192"));
    kmctr.add(Function::new(28, Msa::MSA4, "KMCTR-Encrypted-AES-256"));
    kmctr.add(Function::new(127, Msa::MSA13, "KMCTR-Query-Authentication-Information"));

    let mut kmo = Instruction::new(InstructionKind::KMO, 77, "Cipher Message with Output Feedback");
    kmo.add(Function::new(0, Msa::MSA4, "KMO-Query"));
    kmo.add(Function::new(1, Msa::MSA4, "KMO-DEA"));
    kmo.add(Function::new(2, Msa::MSA4, "KMO-TDEA-128"));
    kmo.add(Function::new(3, Msa::MSA4, "KMO-TDEA-192"));
    kmo.add(Function::new(9, Msa::MSA4, "KMO-Encrypted-DEA"));
    kmo.add(Function::new(10, Msa::MSA4, "KMO-Encrypted-TDEA-128"));
    kmo.add(Function::new(11, Msa::MSA4, "KMO-Encrypted-TDEA-192"));
    kmo.add(Function::new(18, Msa::MSA4, "KMO-AES-128"));
    kmo.add(Function::new(19, Msa::MSA4, "KMO-AES-192"));
    kmo.add(Function::new(20, Msa::MSA4, "KMO-AES-256"));
    kmo.add(Function::new(26, Msa::MSA4, "KMO-Encrypted-AES-128"));
    kmo.add(Function::new(27, Msa::MSA4, "KMO-Encrypted-AES-192"));
    kmo.add(Function::new(28, Msa::MSA4, "KMO-Encrypted-AES-256"));
    kmo.add(Function::new(127, Msa::MSA13, "KMO-Query-Authentication-Information"));

    let mut pcc = Instruction::new(InstructionKind::PCC, 77, "Perform Cryptographic Computation");
    pcc.add(Function::new(0, Msa::MSA4, "PCC-Query"));
    pcc.add(Function::new(1, Msa::MSA4, "PCC-Compute-Last-Block-CMAC-Using-DEA"));
    pcc.add(Function::new(2, Msa::MSA4, "PCC-Compute-Last-Block-CMAC-Using-TDEA-128"));
    pcc.add(Function::new(3, Msa::MSA4, "PCC-Compute-Last-Block-CMAC-Using-TDEA-192"));
    pcc.add(Function::new(9, Msa::MSA4, "PCC-Compute-Last-Block-CMAC-Using-Encrypted-DEA"));
    pcc.add(Function::new(10, Msa::MSA4, "PCC-Compute-Last-Block-CMAC-Using-Encrypted-TDEA-128"));
    pcc.add(Function::new(11, Msa::MSA4, "PCC-Compute-Last-Block-CMAC-Using-Encrypted-TDEA-192"));
    pcc.add(Function::new(18, Msa::MSA4, "PCC-Compute-Last-Block-CMAC-Using-AES-128"));
    pcc.add(Function::new(19, Msa::MSA4, "PCC-Compute-Last-Block-CMAC-Using-AES-192"));
    pcc.add(Function::new(20, Msa::MSA4, "PCC-Compute-Last-Block-CMAC-Using-AES-256"));
    pcc.add(Function::new(26, Msa::MSA4, "PCC-Compute-Last-Block-CMAC-Using-Encrypted-AES-128"));
    pcc.add(Function::new(27, Msa::MSA4, "PCC-Compute-Last-Block-CMAC-Using-Encrypted-AES-192"));
    pcc.add(Function::new(28, Msa::MSA4, "PCC-Compute-Last-Block-CMAC-Using-Encrypted-AES-256"));
    pcc.add(Function::new(50, Msa::MSA4, "PCC-Compute-XTS-Parameter-Using-AES-128"));
    pcc.add(Function::new(52, Msa::MSA4, "PCC-Compute-XTS-Parameter-Using-AES-256"));
    pcc.add(Function::new(58, Msa::MSA4, "PCC-Compute-XTS-Parameter-Using-Encrypted-AES-128"));
    pcc.add(Function::new(60, Msa::MSA4, "PCC-Compute-XTS-Parameter-Using-Encrypted-AES-256"));
    pcc.add(Function::new(64, Msa::MSA9, "PCC-Scalar-Multiply-P256"));
    pcc.add(Function::new(65, Msa::MSA9, "PCC-Scalar-Multiply-P384"));
    pcc.add(Function::new(66, Msa::MSA9, "PCC-Scalar-Multiply-P521"));
    pcc.add(Function::new(72, Msa::MSA9, "PCC-Scalar-Multiply-Ed25519"));
    pcc.add(Function::new(73, Msa::MSA9, "PCC-Scalar-Multiply-Ed448"));
    pcc.add(Function::new(80, Msa::MSA9, "PCC-Scalar-Multiply-X25519"));
    pcc.add(Function::new(81, Msa::MSA9, "PCC-Scalar-Multiply-X448"));
    pcc.add(Function::new(127, Msa::MSA13, "PCC-Query-Authentication-Information"));

    let mut prno = Instruction::new(InstructionKind::PRNO, 57, "Perform Random Number Operation");
    prno.add(Function::new(0, Msa::MSA5, "PRNO-Query"));
    prno.add(Function::new(3, Msa::MSA5, "PRNO-SHA-512-DRNG"));
    prno.add(Function::new(112, Msa::MSA7, "PRNO-TRNG-Query-Raw-to-Conditioned-Ratio"));
    prno.add(Function::new(114, Msa::MSA7, "PRNO-TRNG"));
    prno.add(Function::new(127, Msa::MSA13, "PRNO-Query-Authentication-Information"));

    let mut kma = Instruction::new(InstructionKind::KMA, 146, "Cipher Message with Authentication");
    kma.add(Function::new(0, Msa::MSA8, "KMA-Query"));
    kma.add(Function::new(18, Msa::MSA8, "KMA-GCM-AES-128"));
    kma.add(Function::new(19, Msa::MSA8, "KMA-GCM-AES-192"));
    kma.add(Function::new(20, Msa::MSA8, "KMA-GCM-AES-256"));
    kma.add(Function::new(26, Msa::MSA8, "KMA-GCM-Encrypted-AES-128"));
    kma.add(Function::new(27, Msa::MSA8, "KMA-GCM-Encrypted-AES-192"));
    kma.add(Function::new(28, Msa::MSA8, "KMA-GCM-Encrypted-AES-256"));
    kma.add(Function::new(127, Msa::MSA13, "KMA-Query-Authentication-Information"));

    let mut kdsa = Instruction::new(InstructionKind::KDSA, 155, "Compute Digital Signature Authentication");
    kdsa.add(Function::new(0, Msa::MSA9, "KDSA-Query"));
    kdsa.add(Function::new(1, Msa::MSA9, "KDSA-ECDSA-Verify-P256"));
    kdsa.add(Function::new(2, Msa::MSA9, "KDSA-ECDSA-Verify-P384"));
    kdsa.add(Function::new(3, Msa::MSA9, "KDSA-ECDSA-Verify-P521"));
    kdsa.add(Function::new(9, Msa::MSA9, "KDSA-ECDSA-Sign-P256"));
    kdsa.add(Function::new(10, Msa::MSA9, "KDSA-ECDSA-Sign-P384"));
    kdsa.add(Function::new(11, Msa::MSA9, "KDSA-ECDSA-Sign-P521"));
    kdsa.add(Function::new(17, Msa::MSA9, "KDSA-Encrypted-ECDSA-Sign-P256"));
    kdsa.add(Function::new(18, Msa::MSA9, "KDSA-Encrypted-ECDSA-Sign-P384"));
    kdsa.add(Function::new(19, Msa::MSA9, "KDSA-Encrypted-ECDSA-Sign-P521"));
    kdsa.add(Function::new(32, Msa::MSA9, "KDSA-EdDSA-Verify-Ed25519"));
    kdsa.add(Function::new(36, Msa::MSA9, "KDSA-EdDSA-Verify-Ed448"));
    kdsa.add(Function::new(40, Msa::MSA9, "KDSA-EdDSA-Sign-Ed25519"));
    kdsa.add(Function::new(44, Msa::MSA9, "KDSA-EdDSA-Sign-Ed448"));
    kdsa.add(Function::new(48, Msa::MSA9, "KDSA-Encrypted-EdDSA-Sign-Ed25519"));
    kdsa.add(Function::new(52, Msa::MSA9, "KDSA-Encrypted-EdDSA-Sign-Ed448"));
    kdsa.add(Function::new(127, Msa::MSA13, "KDSA-Query-Authentication-Information"));

    instructions.push(km);
    instructions.push(kmc);
    instructions.push(kimd);
    instructions.push(klmd);
    instructions.push(kmac);
    instructions.push(pckmo);
    instructions.push(kmf);
    instructions.push(kmctr);
    instructions.push(kmo);
    instructions.push(pcc);
    instructions.push(prno);
    instructions.push(kma);
    instructions.push(kdsa);
}

/// number of functions introduced by a level is dynamically counted to ease extension
pub fn update_msa_function_count(args: &Cli, msa: &mut MsaLevel, ins: &Vec<Instruction>) {
    for i in ins {
        let num_of_funcs_in_level = i.funcs.iter().filter(|f| f.msa == msa.msa_level).count() as u8;

        msa.total_functions += num_of_funcs_in_level;
        if args.instructions.is_empty() || args.instructions.contains(&i.kind) {
            msa.dynamic_total_functions += num_of_funcs_in_level;
        }
    }
}

pub fn ser_hex<S: Serializer>(data: &Vec<u8>, ser: S) -> std::result::Result<S::Ok, S::Error> {
    HexSlice::from(data).serialize(ser)
}
