// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::builder::RtpPacketWriter;
use crate::extension::RtpExtensionWriteError;
use crate::{RtpExtensionWrite, RtpExtensionsBlock, RtpExtensionsBlockWrite, RtpParseError};

/// A one byte RTP extension as specified in RFC 8285 Section 4.2.
#[derive(Debug)]
pub struct RtpSingleByteExtension<'a> {
    data: &'a [u8],
}

struct RtpSingleByteExtensionIter<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for RtpSingleByteExtensionIter<'a> {
    type Item = (u8, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.offset >= self.data.len() {
                return None;
            }
            let data = &self.data[self.offset..];
            let id = (data[0] & 0xf0) >> 4;
            let len = (data[0] & 0x0f) as usize + 1;

            if self.offset + 1 + len > self.data.len() {
                return None;
            }
            if id == 15 {
                return None;
            }
            self.offset += 1;

            // id 0 is padding, and id 15 is reserved and all subsequent data should be ignored
            if id == 0 {
                continue;
            }
            let data = &self.data[self.offset..self.offset + len];
            self.offset += len;
            return Some((id, data));
        }
    }
}

impl<'a> RtpSingleByteExtension<'a> {
    /// An iterator over the values in this extension.
    ///
    /// Returns the extension identifier and the associated data with the extension.
    pub fn iter(&self) -> impl Iterator<Item = (u8, &'a [u8])> {
        RtpSingleByteExtensionIter {
            data: self.data,
            offset: 0,
        }
    }
}

impl<'a> RtpExtensionsBlock<'a> for RtpSingleByteExtension<'a> {
    fn parse(id: u16, data: &'a [u8]) -> Result<Self, RtpParseError> {
        if id != 0xbede {
            return Err(RtpParseError::UnsupportedExtensionImplementation);
        }

        if data.is_empty() || data.len() % 4 != 0 {
            return Err(RtpParseError::Truncated {
                expected: data.len() + 4 - data.len() % 4,
                actual: data.len(),
            });
        }

        Ok(Self { data })
    }
}

impl<'a> RtpExtensionsBlockWrite for RtpSingleByteExtension<'a> {
    fn extension_id(&self) -> u16 {
        0xbede
    }

    fn byte_len(&self) -> usize {
        self.data.len()
    }

    fn write<P, O>(&self, writer: &mut impl RtpPacketWriter<Payload = P, Output = O>) {
        writer.push(self.data);
    }
}

/// Builder for single byte RTP Header extensions as specified in RFC 8285 Section 4.2.
#[derive(Debug, Default)]
pub struct RtpSingleByteExtensionBuilder {
    extensions: smallvec::SmallVec<[(u8, Box<dyn RtpExtensionWrite>); 8]>,
}

impl RtpSingleByteExtensionBuilder {
    /// Add an extension to this extension block.
    pub fn push_extension<E: RtpExtensionWrite + 'static>(
        &mut self,
        id: u8,
        ext: E,
    ) -> Result<(), RtpExtensionWriteError> {
        if !(1..15).contains(&id) {
            return Err(RtpExtensionWriteError::IdOutOfRange {
                id: id as usize,
                range: 1..15,
            });
        }
        let len = ext.byte_len();
        if !(1..=16).contains(&len) {
            return Err(RtpExtensionWriteError::LengthOutOfRange { len, range: 1..16 });
        }
        self.extensions.push((id, Box::new(ext)));
        Ok(())
    }
}

impl RtpExtensionsBlockWrite for RtpSingleByteExtensionBuilder {
    fn extension_id(&self) -> u16 {
        0xbede
    }

    fn byte_len(&self) -> usize {
        let len = self
            .extensions
            .iter()
            .map(|(_id, ext)| ext.byte_len() + 1)
            .sum::<usize>();
        (len + 3) & !0x3
    }

    fn write<P, O>(&self, writer: &mut impl RtpPacketWriter<Payload = P, Output = O>) {
        let mut data: smallvec::SmallVec<[u8; 16]> = smallvec::smallvec![0; self.byte_len()];
        let mut offset = 0;
        for (id, ext) in self.extensions.iter() {
            let id = *id;
            data[offset] = (id & 0xf) << 4 | ((ext.byte_len() - 1) & 0xf) as u8;
            offset += 1;
            offset += ext.write_into(&mut data[offset..]);
        }
        writer.push(&data);
    }
}

#[cfg(test)]
mod tests {
    use crate::{extension::Mid, RtpExtension, RtpPacketWriterVec};

    use super::*;

    #[test]
    fn parse_single_byte() {
        let data = [0x00, 0x20, 0x94, 0x11, 0x15, 0x99, 0x00, 0x00];
        let ext = RtpSingleByteExtension::parse(0xbede, &data).unwrap();
        let mut it = ext.iter();
        assert_eq!(it.next(), Some((0x2, [0x94].as_ref())));
        assert_eq!(it.next(), Some((0x1, [0x15, 0x99].as_ref())));
        assert_eq!(it.next(), None);
    }

    #[test]
    fn parse_single_byte_id15_stops_processing() {
        let data = [0x00, 0x20, 0x94, 0xf1, 0x11, 0x99, 0x00, 0x00];
        let ext = RtpSingleByteExtension::parse(0xbede, &data).unwrap();
        let mut it = ext.iter();
        assert_eq!(it.next(), Some((0x2, [0x94].as_ref())));
        assert_eq!(it.next(), None);
    }

    #[test]
    fn parse_single_byte_wrong_id() {
        let data = [0x20, 0x94, 0x00, 0x00];
        assert!(matches!(
            RtpSingleByteExtension::parse(0x0, &data),
            Err(RtpParseError::UnsupportedExtensionImplementation)
        ));
    }

    #[test]
    fn parse_single_byte_wrong_padding() {
        let data = [0x20, 0x94, 0x00];
        assert!(matches!(
            RtpSingleByteExtension::parse(0xbede, &data),
            Err(RtpParseError::Truncated {
                expected: 4,
                actual: 3
            })
        ));
    }

    #[test]
    fn parse_serialize_roundtrip() {
        let data = [0x20, 0x94, 0x11, 0x15];
        let ext = RtpSingleByteExtension::parse(0xbede, &data).unwrap();
        assert_eq!(ext.extension_id(), 0xbede);
        let mut writer = RtpPacketWriterVec::default();
        ext.write(&mut writer);
        assert_eq!(writer.finish(), data);
    }

    #[test]
    fn builder_single_extension_not_multiple_of_4() {
        let ext = Mid::new("1".to_string());
        let mut block = RtpSingleByteExtensionBuilder::default();
        block.push_extension(1, ext).unwrap();
        let mut writer = RtpPacketWriterVec::default();
        block.write(&mut writer);
        let data = writer.finish();
        assert_eq!(&data, &[0x10, 0x31, 0x0, 0x0]);
        let ext = RtpSingleByteExtension::parse(0xbede, &data).unwrap();
        let mut it = ext.iter();
        let (id, ext_data) = it.next().unwrap();
        assert_eq!(id, 1);
        let mid = Mid::parse(ext_data).unwrap();
        assert_eq!(mid.mid(), "1");
    }

    #[test]
    fn builder_single_extension_multiple_of_4() {
        let ext = Mid::new("123".to_string());
        let mut block = RtpSingleByteExtensionBuilder::default();
        block.push_extension(1, ext).unwrap();
        let mut writer = RtpPacketWriterVec::default();
        block.write(&mut writer);
        let data = writer.finish();
        assert_eq!(&data, &[0x12, 0x31, 0x32, 0x33]);
        let ext = RtpSingleByteExtension::parse(0xbede, &data).unwrap();
        let mut it = ext.iter();
        let (id, ext_data) = it.next().unwrap();
        assert_eq!(id, 1);
        let mid = Mid::parse(ext_data).unwrap();
        assert_eq!(mid.mid(), "123");
    }

    #[test]
    fn builder_id_out_range() {
        let ext = Mid::new("1".to_string());
        let mut block = RtpSingleByteExtensionBuilder::default();
        assert!(
            matches!(block.push_extension(0, ext.clone()), Err(RtpExtensionWriteError::IdOutOfRange { id: 0, range }) if range.start == 1 && range.end == 15)
        );
        assert!(
            matches!(block.push_extension(15, ext.clone()), Err(RtpExtensionWriteError::IdOutOfRange { id: 15, range }) if range.start == 1 && range.end == 15)
        );
        assert!(
            matches!(block.push_extension(0xff, ext), Err(RtpExtensionWriteError::IdOutOfRange { id: 0xff, range }) if range.start == 1 && range.end == 15)
        );
    }

    #[test]
    fn builder_length_out_range() {
        let ext = Mid::new("".to_string());
        let mut block = RtpSingleByteExtensionBuilder::default();
        assert!(
            matches!(block.push_extension(1, ext), Err(RtpExtensionWriteError::LengthOutOfRange { len: 0, range }) if range.start == 1 && range.end == 16)
        );
    }
}
