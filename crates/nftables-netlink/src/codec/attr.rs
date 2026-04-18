//! `nfattr` TLV iterator.
//!
//! Each nfattr record is:
//!   - `nfa_len:  u16` (little-endian) — total record length including header
//!   - `nfa_type: u16` (little-endian) — attribute type; top bit signals nested
//!   - `data:     [u8; nfa_len - 4]`
//!
//! Records are padded to 4-byte boundaries in the stream.

use crate::constants::NFA_TYPE_MASK;
use crate::error::NftError;

/// A single decoded nfattr entry.
#[derive(Debug, Clone, Copy)]
pub struct NfAttr<'a> {
    pub attr_type: u16,
    pub data: &'a [u8],
}

impl<'a> NfAttr<'a> {
    /// Return `data` as a `u32` (big-endian / network byte order, as the
    /// kernel sends scalar netfilter attrs).
    pub fn as_be_u32(&self) -> Option<u32> {
        self.data.try_into().ok().map(u32::from_be_bytes)
    }

    /// Return `data` as a `u64` big-endian.
    pub fn as_be_u64(&self) -> Option<u64> {
        self.data.try_into().ok().map(u64::from_be_bytes)
    }

    /// Return `data` as a NUL-stripped UTF-8 string.
    pub fn as_str(&self) -> Option<&'a str> {
        let s = std::str::from_utf8(self.data).ok()?;
        Some(s.trim_end_matches('\0'))
    }

    /// Iterate nested attrs inside this attr's data.
    pub fn nested(&self) -> AttrIter<'a> {
        AttrIter { buf: self.data }
    }
}

/// Iterator over a flat `nfattr` stream.
pub struct AttrIter<'a> {
    buf: &'a [u8],
}

impl<'a> AttrIter<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }
}

impl<'a> Iterator for AttrIter<'a> {
    type Item = Result<NfAttr<'a>, NftError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.len() < 4 {
            return None;
        }
        let len = u16::from_le_bytes([self.buf[0], self.buf[1]]) as usize;
        if len < 4 {
            return Some(Err(NftError::Parse(format!("nfattr len {len} < 4"))));
        }
        if len > self.buf.len() {
            return Some(Err(NftError::Parse(format!(
                "nfattr len {len} > remaining buf {}",
                self.buf.len()
            ))));
        }
        let attr_type = u16::from_le_bytes([self.buf[2], self.buf[3]]) & NFA_TYPE_MASK;
        let data = &self.buf[4..len];
        // Advance by padded length (round up to next 4-byte boundary).
        let padded = (len + 3) & !3;
        self.buf = if padded <= self.buf.len() {
            &self.buf[padded..]
        } else {
            &[]
        };
        Some(Ok(NfAttr { attr_type, data }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_attr(attr_type: u16, data: &[u8]) -> Vec<u8> {
        let len = (4 + data.len()) as u16;
        let padded = ((len as usize + 3) & !3) as usize;
        let mut v = vec![0u8; padded];
        v[0..2].copy_from_slice(&len.to_le_bytes());
        v[2..4].copy_from_slice(&attr_type.to_le_bytes());
        v[4..4 + data.len()].copy_from_slice(data);
        v
    }

    #[test]
    fn single_string_attr() {
        let mut buf = make_attr(1, b"inet\0");
        let attrs: Vec<_> = AttrIter::new(&mut buf)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].attr_type, 1);
        assert_eq!(attrs[0].as_str().unwrap(), "inet");
    }

    #[test]
    fn two_attrs_padded() {
        let mut buf = Vec::new();
        buf.extend(make_attr(1, b"tcp\0"));
        buf.extend(make_attr(2, &22u32.to_be_bytes()));
        let attrs: Vec<_> = AttrIter::new(&buf).collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0].as_str().unwrap(), "tcp");
        assert_eq!(attrs[1].as_be_u32().unwrap(), 22);
    }

    #[test]
    fn nested_flag_stripped() {
        // Top bit (0x8000) is the nested flag; attr_type should be masked off.
        let buf = make_attr(0x8001, &[]);
        let attrs: Vec<_> = AttrIter::new(&buf).collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(attrs[0].attr_type, 1);
    }
}
