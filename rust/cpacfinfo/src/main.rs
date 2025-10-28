// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

mod cli;
mod msa;
mod query;
mod stfle;

use anyhow::bail;
use anyhow::Result as anyhowRes;
use clap::Parser;
use std::io::ErrorKind;
use std::result::Result::Ok;
use utils::print_version;

use crate::cli::{Cli, Format};
use crate::msa::*;
use crate::query::*;
use crate::stfle::*;

/// producing -m/--msa output
fn out_msa(args: &Cli, levels: &Vec<MsaLevel>, instructions: &Vec<Instruction>) {
    // produce json output
    if args.format == Format::Json {
        println!("{}", serde_json::to_string(levels).unwrap());
        return;
    }

    // produce human readable output
    for lvl in levels {
        // print current level
        println!("{lvl}");

        // if -f/--functions is not specified continue to next level
        if !args.functions {
            continue;
        }

        // print all functions introduced by the current level sorted by instruction
        for ins in instructions {
            // skip instructions for which the current level introduces no new functions
            if !args.instructions.contains(&ins.kind) && !args.instructions.is_empty()
                || !ins.info.available
            {
                continue;
            }

            // filter all functions that do not fit the command line arguments
            let funcs_to_be_printed = ins
                .funcs
                .iter()
                .filter(|func| {
                    !(!func.available && !args.not_available
                        || func.available && !args.available && args.not_available)
                })
                .filter(|func| func.msa == lvl.msa_level);

            // print all functions matching the command line arguments
            let mut ins_printed = false;
            for func in funcs_to_be_printed {
                if !ins_printed {
                    println!("\t{ins}");
                    ins_printed = true;
                }
                println!("\t\t{func}");
            }
        }
    }
}

/// produces output for all cpacfinfo commands that do not contain the -m/--msa flag
fn out_instructions(args: &Cli, instructions: &Vec<Instruction>) {
    // produce json output
    if args.format == Format::Json {
        println!("{}", serde_json::to_string(instructions).unwrap());
        return;
    }

    // produce human readable output
    for ins in instructions {
        if !args.instructions.contains(&ins.kind) && !args.instructions.is_empty()
            || !ins.info.available
        {
            continue;
        }
        println!("{ins}");

        // --no-auth-info/-n suppresses the Authentication Information output
        if !args.quiet && ins.info.qai_available {
            println!("{}", ins.info.qai);
        } else if !args.quiet {
            println!("Query Authentication Information not available for {ins} instruction! (potentially insufficient machine level)");
        }

        // --functions/-f lists functions of instructions
        if args.functions {
            ins.funcs
                .iter()
                .filter(|func| {
                    !(!func.available && !args.not_available
                        || func.available && !args.available && args.not_available)
                })
                .for_each(|func| println!("\t{func}"));
            println!();
        }
    }
}

fn main() -> anyhowRes<()> {
    // ---- PARSE COMMAND LINE ARGUMENTS ----
    let args: Cli = Cli::parse();

    // ---- PRINT VERSION STRING ----
    if args.version {
        print_version!("2024");
        return Ok(());
    }

    // ---- SET CONSTANTS ----
    let mut instructions = Vec::new();
    init_instructions(&mut instructions);

    let mut levels = Vec::new();
    for lvl in 0..MSA_LEVEL_COUNT {
        let temp = match num2msa(lvl) {
            Some(l) => l,
            None => panic!("programming error"),
        };
        let stfle_bit = msa2stfle(&temp);
        levels.push(MsaLevel::new(temp, stfle_bit));
        let idx_of_last_element = levels.len() - 1;
        update_msa_function_count(&args, &mut levels[idx_of_last_element], &instructions);
    }

    // ---- GET INFORMATION ----
    // get stfle bits
    let stfle_bits = Stfle::new()?;

    // check stfle bits for available MSA levels
    for lvl in &mut levels {
        match lvl.stfle_bit {
            Some(bit) => lvl.enabled = stfle_bits.check_bit_in_stfle(bit),
            None => continue,
        }
    }

    // check if SYSFS_PATH is available
    match check_sysfs() {
        true => (),
        false => return Ok(()),
    }

    // run query function (fc 0) for every instruction to check available functions
    for ins in &mut instructions {
        if stfle_bits.check_bit_in_stfle(ins.info.stfle_bit) {
            ins.info.available = true;

            // run query; save result in param
            let mut param = match query(&ins.kind, QUERY_FUNCTION_CODE) {
                Ok(pb) => match pb {
                    Param::QueryParam(_) => pb,
                    Param::QaiParam(_) => panic!("programming error"),
                },
                Err(e) => match e.kind() {
                    ErrorKind::NotFound => {
                        println!("Warning: Not able to retrieve subfunction information from sysfs for {ins} instruction");
                        continue;
                    }
                    _ => return Err(e.into()),
                },
            };

            // check if bit for functions of current instruction is set in param
            for func in &mut ins.funcs {
                if !param.check_bit_in_param(func.function_code as usize) {
                    continue;
                }

                func.available = true;

                // unset the bit in param to later see if any unsupported functions may be available
                param.unset_bit_in_param(func.function_code);

                // check if qai is available
                if func.function_code == QAI_FUNCTION_CODE {
                    ins.info.qai_available = true;
                }

                // sync MsaLevel struct
                for lvl in &mut levels {
                    if lvl.msa_level == func.msa {
                        lvl.enabled = true;
                        lvl.available_functions += 1;
                        if args.instructions.is_empty() || args.instructions.contains(&ins.kind) {
                            lvl.dynamic_available_functions += 1;
                        }
                        break;
                    }
                }
            }

            // look for any unsupported functions that my be available
            for i in 0..NUMBER_FUNC_CODES {
                // every bit in param that is 1 is an unsupported function
                if !param.check_bit_in_param(i) {
                    continue;
                }

                // add function to instruction as UNKNOWN
                Instruction::add(ins, Function::new(i as u8, Msa::UNKNOWN, "UNKNOWN"));

                // set function as available
                match ins.funcs.last_mut() {
                    Some(ret) => ret.available = true,
                    None => panic!("programming error"),
                }
            }

            // if query authentication information (fc 127) available run query authentication
            // information
            if ins.info.qai_available {
                // get qai from sysfs
                let param = match query(&ins.kind, QAI_FUNCTION_CODE) {
                    Ok(pb) => match pb {
                        Param::QueryParam(_) => panic!("programming error"),
                        Param::QaiParam(_) => pb,
                    },
                    Err(e) => match e.kind() {
                        ErrorKind::NotFound => {
                            println!("Warning: Not able to retrieve Query Authentication Information from sysfs for {ins} instruction");
                            continue;
                        }
                        _ => return Err(e.into()),
                    },
                };

                // parse qai information into QueryAuthInfo struct
                match param.parse_qai_based_on_format(&mut ins.info.qai) {
                    Ok(true) => (),
                    Ok(false) => println!("WARNING: format {} in query authentication information of instruction {} is UNKNOWN", ins.info.qai.format, ins.kind),
                    Err(e) => bail!(e.to_string()),
                }
            }
        }
    }

    // ---- OUTPUT ----
    match args.msa {
        true => out_msa(&args, &levels, &instructions),
        false => out_instructions(&args, &instructions),
    }
    Ok(())
}
