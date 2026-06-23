// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    builder::RtpPacketWriter, extension::RtpExtensionWriteError, RtpExtensionWrite,
    RtpExtensionsBlock, RtpExtensionsBlockWrite, RtpParseError,
};

/// A two byte RTP extension as specified in RFC 8285 Section 4.3.
#[derive(Debug)]
pub struct RtpTwoByteExtension<'a> {
    data: &'a [u8],
    app_bits: u8,
}

struct RtpTwoByteExtensionIter<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for RtpTwoByteExtensionIter<'a> {
    type Item = (u8, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.offset + 1 >= self.data.len() {
                return None;
            }
            let data = &self.data[self.offset..];
            let id = data[0];
            let len = data[1] as usize;
            if id == 0 {
                // padding byte
                self.offset += 1;
                continue;
            };

            if self.offset + 2 + len > self.data.len() {
                return None;
            }
            self.offset += 2;

            let data = &self.data[self.offset..][..len];
            self.offset += len;
            return Some((id, data));
        }
    }
}

impl<'a> RtpTwoByteExtension<'a> {
    /// An iterator over the values in this extension.
    ///
    /// Returns the extension identifier and the associated data with the extension.
    pub fn iter(&self) -> impl Iterator<Item = (u8, &'a [u8])> {
        RtpTwoByteExtensionIter {
            data: self.data,
            offset: 0,
        }
    }

    /// Returns the application specific value.
    ///
    /// This value has the extension id 256 and is only valid if negotiated out of band.
    pub fn app_bits(&self) -> u8 {
        self.app_bits
    }
}

impl<'a> RtpExtensionsBlock<'a> for RtpTwoByteExtension<'a> {
    fn parse(id: u16, data: &'a [u8]) -> Result<Self, RtpParseError> {
        if id & 0xfff0 != 0x1000 {
            return Err(RtpParseError::UnsupportedExtensionImplementation);
        }

        if data.is_empty() || data.len() % 4 != 0 {
            return Err(RtpParseError::Truncated {
                expected: data.len() + 4 - data.len() % 4,
                actual: data.len(),
            });
        }

        Ok(Self {
            data,
            app_bits: (id & 0x0000f) as u8,
        })
    }
}

impl<'a> RtpExtensionsBlockWrite for RtpTwoByteExtension<'a> {
    fn extension_id(&self) -> u16 {
        0x1000 | ((self.app_bits & 0x0f) as u16)
    }

    fn byte_len(&self) -> usize {
        self.data.len()
    }

    fn write<P, O>(
        &self,
        writer: &mut impl crate::prelude::RtpPacketWriter<Payload = P, Output = O>,
    ) {
        writer.push(self.data);
    }
}

/// Builder for single byte RTP Header extensions as specified in RFC 8285 Section 4.2.
#[derive(Debug, Default)]
pub struct RtpTwoByteExtensionBuilder {
    app_bits: u8,
    extensions: smallvec::SmallVec<[(u8, Box<dyn RtpExtensionWrite>); 8]>,
}

impl RtpTwoByteExtensionBuilder {
    /// Add an extension to this extension block.
    pub fn push_extension<E: RtpExtensionWrite + 'static>(
        &mut self,
        id: u8,
        ext: E,
    ) -> Result<(), RtpExtensionWriteError> {
        if !(1..255).contains(&id) {
            return Err(RtpExtensionWriteError::IdOutOfRange {
                id: id as usize,
                range: 1..255,
            });
        }
        self.extensions.push((id, Box::new(ext)));
        Ok(())
    }

    /// Set the application bits on the created RTP header extension.
    ///
    /// Panics:
    ///  - if `app_bits` >= 0x10
    pub fn app_bits(&mut self, app_bits: u8) {
        assert!(app_bits <= 0xf);
        self.app_bits = app_bits;
    }
}

impl RtpExtensionsBlockWrite for RtpTwoByteExtensionBuilder {
    fn extension_id(&self) -> u16 {
        0x1000 | self.app_bits as u16
    }

    fn byte_len(&self) -> usize {
        let len = self
            .extensions
            .iter()
            .map(|(_id, ext)| ext.byte_len() + 2)
            .sum::<usize>();
        (len + 3) & !0x3
    }

    fn write<P, O>(&self, writer: &mut impl RtpPacketWriter<Payload = P, Output = O>) {
        let mut data: smallvec::SmallVec<[u8; 16]> = smallvec::smallvec![0; self.byte_len()];
        let mut offset = 0;
        for (id, ext) in self.extensions.iter() {
            let id = *id;
            data[offset] = id;
            offset += 1;
            data[offset] = ext.byte_len() as u8;
            offset += 1;
            offset += ext.write_into(&mut data[offset..]);
        }
        writer.push(&data);
    }
}

#[cfg(test)]
mod tests {
    use crate::{builder::RtpPacketWriter, extension::Mid, RtpExtension, RtpPacketWriterVec};

    use super::*;

    #[test]
    fn parse_two_byte() {
        let data = [0x02, 0x01, 0x94, 0x00];
        let ext = RtpTwoByteExtension::parse(0x100a, &data).unwrap();
        let mut it = ext.iter();
        assert_eq!(it.next(), Some((0x2, [0x94].as_ref())));
        assert_eq!(it.next(), None);
    }

    #[test]
    fn parse_two_byte_with_app() {
        let data = [0x00, 0x02, 0x01, 0x94];
        let ext = RtpTwoByteExtension::parse(0x100a, &data).unwrap();
        let mut it = ext.iter();
        assert_eq!(it.next(), Some((0x2, [0x94].as_ref())));
        assert_eq!(it.next(), None);
        assert_eq!(ext.app_bits(), 0xa);
    }

    #[test]
    fn parse_serialize_roundtrip() {
        let data = [0x02, 0x01, 0x94, 0x00];
        let ext = RtpTwoByteExtension::parse(0x1000, &data).unwrap();
        assert_eq!(ext.extension_id(), 0x1000);
        let mut writer = RtpPacketWriterVec::default();
        ext.write(&mut writer);
        assert_eq!(writer.finish(), data);
    }

    #[test]
    fn parse_serialize_roundtrip_with_app() {
        let data = [0x00, 0x02, 0x01, 0x94];
        let ext = RtpTwoByteExtension::parse(0x100a, &data).unwrap();
        assert_eq!(ext.extension_id(), 0x100a);
        let mut writer = RtpPacketWriterVec::default();
        ext.write(&mut writer);
        assert_eq!(writer.finish(), data);
    }

    #[test]
    fn builder_single_extension_not_multiple_of_4() {
        let ext = Mid::new("1".to_string());
        let mut block = RtpTwoByteExtensionBuilder::default();
        block.push_extension(1, ext).unwrap();
        let mut writer = RtpPacketWriterVec::default();
        block.write(&mut writer);
        let data = writer.finish();
        assert_eq!(&data, &[0x1, 0x1, 0x31, 0x0]);
        let ext = RtpTwoByteExtension::parse(0x1000, &data).unwrap();
        let mut it = ext.iter();
        let (id, ext_data) = it.next().unwrap();
        assert_eq!(id, 1);
        let mid = Mid::parse(ext_data).unwrap();
        assert_eq!(mid.mid(), "1");
    }

    #[test]
    fn builder_single_extension_multiple_of_4() {
        let ext = Mid::new("12".to_string());
        let mut block = RtpTwoByteExtensionBuilder::default();
        block.push_extension(1, ext).unwrap();
        let mut writer = RtpPacketWriterVec::default();
        block.write(&mut writer);
        let data = writer.finish();
        assert_eq!(&data, &[0x1, 0x2, 0x31, 0x32]);
        let ext = RtpTwoByteExtension::parse(0x1000, &data).unwrap();
        let mut it = ext.iter();
        let (id, ext_data) = it.next().unwrap();
        assert_eq!(id, 1);
        let mid = Mid::parse(ext_data).unwrap();
        assert_eq!(mid.mid(), "12");
    }

    #[test]
    fn builder_id_out_range() {
        let ext = Mid::new("1".to_string());
        let mut block = RtpTwoByteExtensionBuilder::default();
        assert!(
            matches!(block.push_extension(0, ext.clone()), Err(RtpExtensionWriteError::IdOutOfRange { id: 0, range }) if range.start == 1 && range.end == 255)
        );
    }
}
