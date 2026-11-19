//! Host address ranges the guest gave back through the balloon (UFFD_EVENT_REMOVE).
//! Faults there must be served with zeros: the snapshot file no longer holds
//! the page's contents.

#[derive(Debug, Default, Clone)]
pub struct Ranges(Vec<(u64, u64)>);

impl Ranges {
    /// Add `[start, end)`, merging with overlapping or adjacent ranges.
    pub fn add(&mut self, start: u64, end: u64) {
        if start >= end {
            return;
        }
        let (mut s, mut e) = (start, end);
        self.0.retain(|&(a, b)| {
            if b < s || a > e {
                true
            } else {
                s = s.min(a);
                e = e.max(b);
                false
            }
        });
        let i = self.0.partition_point(|&(a, _)| a < s);
        self.0.insert(i, (s, e));
    }

    pub fn contains(&self, addr: u64) -> bool {
        let i = self.0.partition_point(|&(a, _)| a <= addr);
        i > 0 && addr < self.0[i - 1].1
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_and_lookup() {
        let mut r = Ranges::default();
        r.add(100, 200);
        r.add(300, 400);
        assert_eq!(r.len(), 2);
        assert!(r.contains(100) && r.contains(199) && !r.contains(200) && !r.contains(99));
        r.add(200, 300); // adjacent on both sides: one range
        assert_eq!(r.len(), 1);
        assert!(r.contains(250) && r.contains(399) && !r.contains(400));
        r.add(10, 20);
        r.add(5, 15);
        assert_eq!(r.len(), 2);
        assert!(r.contains(5) && !r.contains(20));
        r.add(50, 50);
        assert_eq!(r.len(), 2);
    }
}
