// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024
use std::{collections::BTreeSet, fmt::Display, rc::Rc};

use crate::{
    misc::round_up,
    pv_utils::error::{Error, Result},
};

/// Represents a range from [start, stop) (inclusive start, exclusive stop)
#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct Interval {
    pub start: u64,
    pub stop: u64,
}

impl Display for Interval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        format!("start: {:#10x} stop: {:#10x}", self.start, self.stop - 1).fmt(f)
    }
}

impl Interval {
    /// Create a new [`Interval`].
    ///
    /// # Errors
    ///
    /// This function will return an error if `stop` is not larger than `start`.
    const fn new(start: u64, stop: u64) -> Result<Self> {
        if stop <= start {
            return Err(Error::InvalidInterval { start, stop });
        }
        Ok(Self { start, stop })
    }

    /// Creates a new [`Interval`] with the start address `start` and the size
    /// of `size`.
    ///
    /// # Errors
    ///
    /// This function will return an error if `size == 0` or if there was an
    /// unexpected overflow.
    pub fn new_with_size(start: u64, size: u64) -> Result<Self> {
        Self::new(
            start,
            start.checked_add(size).ok_or(Error::UnexpectedOverflow)?,
        )
    }

    const fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.stop
    }

    /// Returns the size of this [`Interval`].
    pub const fn size(&self) -> u64 {
        self.stop - self.start
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Layout {
    pub next_addr: u64,
    pub alignment: u64,
    chunks: BTreeSet<Rc<Interval>>,
}

impl Layout {
    /// Creates a new [`Layout`].
    ///
    /// # Errors
    ///
    /// This function will return an error if `start_addr` is not aligned.
    pub fn new(start_addr: u64, alignment: u64) -> Result<Self> {
        if start_addr != round_up(start_addr, alignment)? {
            return Err(Error::UnalignedAddress {
                addr: start_addr,
                alignment,
            });
        }

        Ok(Self {
            next_addr: start_addr,
            alignment,
            chunks: BTreeSet::new(),
        })
    }

    fn is_aligned(&self, addr: u64) -> Result<bool> {
        Ok(addr == round_up(addr, self.alignment)?)
    }

    fn overlaps(&self, b: &Interval) -> Option<Rc<Interval>> {
        for a in self.chunks.iter() {
            if a.start < b.stop && b.start < a.stop {
                return Some(a.clone());
            }
        }
        None
    }

    /// Returns the maximum chunk size at the given address `addr`. If there is
    /// no limit `None` is returned.
    ///
    /// # Errors
    ///
    /// This function will return an error if the address is in use already.
    pub fn max_size_of_chunk_at_addr(&self, addr: u64) -> Result<Option<usize>> {
        if !self.is_aligned(addr)? {
            return Err(Error::UnalignedAddress {
                addr,
                alignment: self.alignment,
            });
        }

        if addr >= self.next_addr {
            return Ok(None);
        }

        for chunk in &self.chunks {
            if chunk.contains(addr) {
                return Err(Error::NoUnusedAddr { addr });
            }

            if chunk.start >= addr {
                let max_size = usize::try_from(chunk.start - addr).unwrap();
                return Ok(Some(max_size));
            }
        }

        Ok(None)
    }

    /// Insert an interval in the layout.
    ///
    /// # Errors
    ///
    /// This function will return an error if the given address was unaligned or
    /// the interval would overlap with an existing interval in the layout.
    pub fn insert_interval(&mut self, addr: u64, size: u64) -> Result<Rc<Interval>> {
        let interval = Interval::new_with_size(addr, size)?;

        assert!(self.next_addr % self.alignment == 0);

        if interval.start != round_up(interval.start, self.alignment)? {
            return Err(Error::UnalignedAddress {
                addr: interval.start,
                alignment: self.alignment,
            });
        }

        if let Some(overlapped) = self.overlaps(&interval) {
            let msg = format!("{overlapped} ... {interval}");
            return Err(Error::IntervalOverlap(msg));
        }

        let interval = Rc::new(interval);
        self.chunks.insert(interval.clone());
        let maybe_next_addr = interval
            .start
            .checked_add(round_up(size, self.alignment)?)
            .ok_or(Error::UnexpectedOverflow)?;
        if maybe_next_addr > self.next_addr {
            self.next_addr = maybe_next_addr;
        }

        assert!(self.next_addr % self.alignment == 0);

        Ok(interval)
    }

    /// Creates and appends this newly created interval with size `size` to the
    /// layout. Returns the created interval.
    ///
    /// # Errors
    ///
    /// This function will return an error if it was not possible to append the
    /// newly created interval.
    pub fn push(&mut self, size: u64) -> Result<Rc<Interval>> {
        let addr = self.next_addr;
        self.insert_interval(addr, size)
    }
}

impl IntoIterator for Layout {
    type IntoIter = <BTreeSet<Rc<Interval>> as IntoIterator>::IntoIter;
    type Item = Rc<Interval>;

    fn into_iter(self) -> Self::IntoIter {
        self.chunks.into_iter()
    }
}

#[allow(clippy::shadow_unrelated)]
#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, rc::Rc};

    use proptest::{
        prelude::{Just, Strategy},
        prop_assert, prop_assert_eq, proptest,
    };

    use crate::pv_utils::{Interval, Layout};

    proptest! {
        #[test]
        fn interval_new(
            (a,b) in (0..u64::MAX).prop_flat_map(|a| (Just(a), 0..a))
        ) {
            prop_assert!(b < a);
            Interval::new(b, a).expect("should not fail");
        }

        #[test]
        fn interval_new_with_size(
            (start, size) in (0..u64::MAX).prop_flat_map(|a| (Just(a), 1..=u64::MAX - a))
        ) {
            Interval::new_with_size(start, size).expect("should not fail");
        }

        #[test]
        fn interval_contains(
            (start, size, c) in (0_u16..4_u16).prop_flat_map(|a| (Just(a), 1_u16..4_u16)).prop_flat_map(|(a,b)| (Just(a), Just(b), a..(a + b)))
        ) {
            let interval = Interval::new_with_size(start.into(), size.into()).expect("should not fail");
            prop_assert!(interval.contains(c.into()));
        }

        #[test]
        fn interval_cmp(
            (start, size, start2) in (1..16_u64).prop_flat_map(|a| (Just(a), 1..16_u16)).prop_flat_map(|(a,b)| (Just(a), Just(b), 0..a))
        ) {
            let interval = Interval::new_with_size(start, size.into()).expect("should not fail");
            let interval2 = Interval::new_with_size(start2, size.into()).expect("should not fail");
            let interval3 = Interval::new_with_size(start, <u16 as Into<u64>>::into(size) + 1).expect("should not fail");
            let interval4 = Interval::new_with_size(start, size.into()).expect("should not fail");
            prop_assert!(interval > interval2);
            prop_assert!(interval != interval2);
            prop_assert!(interval < interval3);
            prop_assert!(interval == interval4);
        }

        #[test]
        fn interval_size((start, size) in (0..u64::MAX).prop_flat_map(|a| (Just(a), 1..=u64::MAX - a))
        )
        {
            let interval = Interval::new_with_size(start, size).expect("should not fail");
            prop_assert_eq!(interval.size(), size);
        }
    }

    #[test]
    fn interval_overflow() {
        Interval::new_with_size(u64::MAX, 1).expect_err("should fail");
    }

    #[test]
    fn memory_layout_test() {
        // Unaligned start address
        let layout = Layout::new(0x1_u64, 0x1000_u64);
        assert!(layout.is_err());

        let mut layout = Layout::new(0x1000_u64, 0x1000_u64).unwrap();
        assert_eq!(
            layout,
            Layout {
                next_addr: 0x1000,
                alignment: 0x1000,
                chunks: BTreeSet::new(),
            }
        );
        layout.push(0x16).unwrap();
        layout.push(0x1000).unwrap();
        layout.push(0x1).unwrap();
        let mut bin = BTreeSet::from([
            Rc::new(Interval::new_with_size(0x1000, 0x16).expect("should not fail")),
            Rc::new(Interval::new_with_size(0x2000, 0x1000).expect("should not fail")),
            Rc::new(Interval::new_with_size(0x3000, 0x1).expect("should not fail")),
        ]);
        assert_eq!(
            layout,
            Layout {
                next_addr: 0x4000,
                alignment: 0x1000,
                chunks: bin.clone()
            }
        );

        // Invalid chunk size
        assert!(layout.push(0x0).is_err());

        // NonMonolithic address
        assert!(layout.insert_interval(0x0, 0x1001).is_err());
        assert!(layout.insert_interval(0x0, 0x1000).is_ok());
        assert!(layout.insert_interval(0x10, 0x1000).is_err());

        bin.insert(Rc::new(
            Interval::new_with_size(0x0, 0x1000).expect("should not fail"),
        ));
        assert_eq!(
            layout,
            Layout {
                next_addr: 0x4000,
                alignment: 0x1000,
                chunks: bin.clone()
            }
        );

        assert!(layout.insert_interval(0x3000, 0x400).is_err());
        assert!(layout.insert_interval(0x4000, 0x400).is_ok());

        bin.insert(Rc::new(
            Interval::new_with_size(0x4000, 0x400).expect("should not fail"),
        ));
        assert_eq!(
            layout,
            Layout {
                next_addr: 0x5000,
                alignment: 0x1000,
                chunks: bin
            }
        );
    }

    #[test]
    fn test_max_interval_size_at_addr() {
        let mut layout = Layout::new(0x0_u64, 0x1000_u64).expect("should not fail");
        assert_eq!(
            layout,
            Layout {
                next_addr: 0x0,
                alignment: 0x1000,
                chunks: BTreeSet::new(),
            }
        );
        layout.push(0x16).unwrap();
        layout.push(0x1000).unwrap();
        layout.push(0x1).unwrap();
        layout.push(0x0).expect_err("should fail");
        let bin = BTreeSet::from([
            Rc::new(Interval::new_with_size(0x0, 0x16).expect("should not fail")),
            Rc::new(Interval::new_with_size(0x1000, 0x1000).expect("should not fail")),
            Rc::new(Interval::new_with_size(0x2000, 0x1).expect("should not fail")),
        ]);
        assert_eq!(
            layout,
            Layout {
                next_addr: 0x3000,
                alignment: 0x1000,
                chunks: bin,
            }
        );

        layout
            .max_size_of_chunk_at_addr(0x5)
            .expect_err("should fail");
        layout
            .max_size_of_chunk_at_addr(0x2000)
            .expect_err("should fail");
        layout
            .max_size_of_chunk_at_addr(0x2fff)
            .expect_err("should fail");
        assert_eq!(
            layout
                .max_size_of_chunk_at_addr(0x3000)
                .expect("should not fail"),
            None
        );

        layout.alignment = 1;
        assert_eq!(
            layout
                .max_size_of_chunk_at_addr(0x16)
                .expect("should not fail"),
            Some(0x1000 - 0x16)
        );
        assert_eq!(
            layout
                .max_size_of_chunk_at_addr(0xfff)
                .expect("should not fail"),
            Some(0x1)
        );
        layout
            .max_size_of_chunk_at_addr(0x1000)
            .expect_err("should not fail");
        assert_eq!(
            layout
                .max_size_of_chunk_at_addr(0x2fff)
                .expect("should not fail"),
            None
        );
        assert_eq!(
            layout
                .max_size_of_chunk_at_addr(0x3000)
                .expect("should not fail"),
            None
        );
    }
}
