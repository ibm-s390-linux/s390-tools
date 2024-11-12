// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use pv::PvCoreError;

use crate::error::{Error, Result};

/// Rounds up the given `value` to a multiple of `multiple`.
///
/// # Errors
///
/// This function will return an error if there was an unexpected arithmetic
/// overflow.
pub fn round_up(value: u64, multiple: u64) -> Result<u64> {
    assert!(multiple >= 1);
    Ok((value
        .checked_add(multiple)
        .ok_or(Error::UnexpectedOverflow)?
        - 1)
        & !(multiple - 1))
}

/// Try to copy a slice to an array.
///
/// # Errors
///
/// This function will return an error if the length of the slice is not equal
/// to the length of the destination array.
pub fn try_copy_slice_to_array<const COUNT: usize, T: Copy + Default>(
    src: &[T],
) -> Result<[T; COUNT]> {
    if COUNT != src.len() {
        return Err(Error::PvCore(PvCoreError::LengthMismatch {
            expected: COUNT,
            actual: src.len(),
        }));
    }

    let mut result = [T::default(); COUNT];
    result.copy_from_slice(src);
    Ok(result)
}

#[allow(clippy::shadow_unrelated)]
#[cfg(test)]
mod tests {
    use pv::PvCoreError;

    use crate::{
        error::{Error, Result},
        pv_utils::try_copy_slice_to_array,
    };

    #[test]
    fn test_try_copy_slice_to_array() {
        let data = vec![];
        let result: [u8; 0] = try_copy_slice_to_array(data.as_slice()).expect("should not fail");
        assert_eq!(data, result);

        let data = vec![0x1_u8, 0x2_u8, 0x3_u8];
        let result: [u8; 3] = try_copy_slice_to_array(data.as_slice()).expect("should not fail");
        assert_eq!(data, result);

        let result: Result<[u8; 4]> = try_copy_slice_to_array(data.as_slice());
        assert!(matches!(
            result,
            Err(Error::PvCore(PvCoreError::LengthMismatch {
                expected: 4,
                actual: 3
            }))
        ));
    }
}
