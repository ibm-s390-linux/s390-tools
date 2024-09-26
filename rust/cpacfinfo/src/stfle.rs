// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use anyhow::Error;

/// Specifies the number of u64 values needed to store the stfle block
pub const STFLE_LEN: usize = 3;

pub struct Stfle {
    data: [u64; STFLE_LEN],
}

impl Stfle {
    /// Constructs a STFLE block, and saves the STFLE information in the structure.
    pub fn new() -> Result<Self, Error> {
        let mut ret = Self {
            data: [0; STFLE_LEN],
        };

        // SAFETY: this call is safe because ret can store 64 bits * 3 which equals the required 192
        // bits.
        let rc = unsafe { stfle(&mut ret.data[0], STFLE_LEN as u32) };
        let rc = match rc {
            0 => {
                println!("Unable to fetch STFLE which is only available on s390x architecture");
                return Ok(ret);
            }
            rc if rc as usize >= STFLE_LEN => STFLE_LEN as u32,
            rc => rc + 1,
        };

        if rc != STFLE_LEN as u32 {
            println!("Partial read of STFLE, information might be incomplete");
        }

        Ok(ret)
    }

    /// check specific bit in stfle (accounts for big-endianness of stfle)
    pub fn check_bit_in_stfle(&self, check_bit: u8) -> bool {
        // stfle is big endian while check_bit is little endian
        let byte = (check_bit / 64) as usize;
        if byte >= STFLE_LEN {
            return false;
        }
        // conversion from little endian check_bit to big endian
        let bit = ((check_bit / 64 + 1) * 64 - 1) - check_bit;
        self.data[byte] & 1 << bit > 0
    }
}

// STFLE bits cannot be retrieved from the system but have to be fetched by running the STFLE
// instruction of Z. This is done in linked C code
extern "C" {
    /// Retrieve STFLE bits into list
    ///
    /// List is in big-endian when returned.
    /// @list is to return the outcome of the stfle operation. Pointer must be able to store
    /// 192 bits.
    /// @doublewords specifies the length of the pointer @list as a number of elements behind
    /// the pointer.
    fn stfle(list: *mut u64, doublewords: u32) -> u32;
}

#[cfg(test)]
#[test]
fn test_check_bit_in_stfle() {
    let mut stfle = match Stfle::new() {
        Ok(ret) => ret,
        Err(e) => panic!("{e}"),
    };

    for b in 0..(STFLE_LEN * 64) {
        // set bit
        stfle.data[b / 64] = u64::pow(2, (63 - (b - ((b / 64) * 64))) as u32);

        // check if bit is set
        assert!(stfle.check_bit_in_stfle(b as u8));

        // reset stfle
        stfle.data = [0; STFLE_LEN];
    }
}
