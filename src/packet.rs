// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt;

/// An error produced when parsing a packet
#[derive(Debug, thiserror::Error)]
pub enum RtpParseError {
    /// Version is unsupported.  This implementation only supports version 2
    #[error("Unsupported RTP version {}", .0)]
    UnsupportedVersion(u8),
    /// There is not enough data available to successfully parse the packet
    #[error("Not enough data available to parse the packet: expected {}, actual {}", .expected, .actual)]
    Truncated {
        /// The expected size
        expected: usize,
        /// The actual size encountered
        actual: usize,
    },
    /// The padding byte does not contain a valid value
    #[error("Padding contains invalid value {}", .0)]
    PaddingInvalid(u8),
}

/// A parsed RTP packet.  A wrapper around a byte slice.  Each field is only accessed when needed
#[repr(transparent)]
pub struct RtpPacket<'a> {
    data: &'a [u8],
}

impl<'a> fmt::Debug for RtpPacket<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct DebugCsrc<'a>(&'a RtpPacket<'a>);

        impl<'a> fmt::Debug for DebugCsrc<'a> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let mut list = f.debug_list();

                for csrc in self.0.csrc() {
                    list.entry(&csrc);
                }

                list.finish()
            }
        }

        f.debug_struct("RtpPacket")
            .field("version", &self.version())
            .field("marker", &self.marker())
            .field("payload_type", &self.payload_type())
            .field("sequence_number", &self.sequence_number())
            .field("timestamp", &self.timestamp())
            .field("ssrc", &self.ssrc())
            .field("csrc", &DebugCsrc(self))
            .field("extension", &self.extension())
            .field("payload", &self.payload())
            .field("padding", &self.padding())
            .finish()
    }
}

impl<'a> RtpPacket<'a> {
    /// The minimum number of bytes a RTP packet must be to be parsed correctly
    pub const MIN_RTP_PACKET_LEN: usize = 12;

    /// The maximum number of CSRCs a RTP packet can contain
    pub const MAX_N_CSRCS: usize = 0xf;

    /// Parse a byte slice into a [`RtpPacket`].  This implementation prefers to fail fast and will
    /// return errors when the size of passed in data is not sufficient for values described in the
    /// data.
    pub fn parse(data: &'a [u8]) -> Result<RtpPacket<'a>, RtpParseError> {
        if data.len() < Self::MIN_RTP_PACKET_LEN {
            return Err(RtpParseError::Truncated {
                expected: Self::MIN_RTP_PACKET_LEN,
                actual: data.len(),
            });
        }

        let ret = Self { data };
        if ret.version() != 2 {
            return Err(RtpParseError::UnsupportedVersion(ret.version()));
        }

        if ret.n_csrcs() > 0 {
            // aka the end of the list of csrcs
            let expected = ret.extension_offset();
            if ret.data.len() < expected {
                return Err(RtpParseError::Truncated {
                    expected,
                    actual: ret.data.len(),
                });
            }
        }

        if ret.extension_bit() {
            // extension offset plus 4 byte extension header
            let expected = ret.extension_offset() + 4;
            if ret.data.len() < expected {
                return Err(RtpParseError::Truncated {
                    expected,
                    actual: ret.data.len(),
                });
            }
            let expected = expected + ret.extension_len();
            if ret.data.len() < expected {
                return Err(RtpParseError::Truncated {
                    expected,
                    actual: ret.data.len(),
                });
            }
        }

        if ret.padding_bit() {
            // offset of the payload plus at least one byte for the ending padding byte
            let expected = ret.payload_offset() + 1;
            if ret.data.len() < expected {
                return Err(RtpParseError::Truncated {
                    expected,
                    actual: ret.data.len(),
                });
            }
            let padding_len = ret.padding().unwrap();
            // padding must be >= 1
            if padding_len == 0 {
                return Err(RtpParseError::PaddingInvalid(0));
            }
            let expected = ret.payload_offset() + padding_len as usize;
            if ret.data.len() < expected {
                // padding extends (at least) back into the RTP header
                return Err(RtpParseError::Truncated {
                    expected,
                    actual: ret.data.len(),
                });
            }
        }
        Ok(ret)
    }

    /// The RTP version in this packet.  Only version 2 is supported.
    pub fn version(&self) -> u8 {
        (self.data[0] & 0b1100_0000) >> 6
    }

    fn padding_bit(&self) -> bool {
        self.data[0] & 0b0010_0000 != 0
    }

    /// Returns the number of bytes of padding used by this packet or `None`
    pub fn padding(&self) -> Option<u8> {
        if self.padding_bit() {
            Some(self.data[self.data.len() - 1])
        } else {
            None
        }
    }

    /// Returns whether the extension bit is set for this packet.
    pub fn extension_bit(&self) -> bool {
        (self.data[0] & 0b0001_0000) != 0
    }

    /// Returns the number of Contribution Sources for this packet.  May not be used by this
    /// packet.
    pub fn n_csrcs(&self) -> u8 {
        self.data[0] & 0b0000_1111
    }

    /// Returns whether the marker bit is set for this packet.  The meaning of the marker bit
    /// is payload-specific
    pub fn marker(&self) -> bool {
        (self.data[1] & 0b1000_0000) != 0
    }

    /// Returns the payload type for this packet.
    pub fn payload_type(&self) -> u8 {
        self.data[1] & 0b0111_1111
    }

    /// Returns the sequence number for this packet
    pub fn sequence_number(&self) -> u16 {
        (self.data[2] as u16) << 8 | self.data[3] as u16
    }

    /// Returns the RTP timestamp for this packet
    pub fn timestamp(&self) -> u32 {
        (self.data[4] as u32) << 24
            | (self.data[5] as u32) << 16
            | (self.data[6] as u32) << 8
            | (self.data[7] as u32)
    }

    /// Returns the Sychronisation Source for this packet
    pub fn ssrc(&self) -> u32 {
        (self.data[8] as u32) << 24
            | (self.data[9] as u32) << 16
            | (self.data[10] as u32) << 8
            | (self.data[11] as u32)
    }

    /// Returns a (potentially empty) iterator over the Contribution Sources for this packet
    pub fn csrc(&self) -> impl Iterator<Item = u32> + '_ {
        self.data[Self::MIN_RTP_PACKET_LEN..]
            .chunks_exact(4)
            .take(self.n_csrcs() as usize)
            .map(|bytes| {
                (bytes[0] as u32) << 24
                    | (bytes[1] as u32) << 16
                    | (bytes[2] as u32) << 8
                    | bytes[3] as u32
            })
    }

    fn extension_offset(&self) -> usize {
        Self::MIN_RTP_PACKET_LEN + (self.n_csrcs() as usize) * 4
    }

    /// Returns the length of the extension data in this packet.
    pub fn extension_len(&self) -> usize {
        if self.extension_bit() {
            let offset = self.extension_offset();
            4 * ((self.data[offset + 2] as usize) << 8 | self.data[offset + 3] as usize)
        } else {
            0
        }
    }

    /// Returns the extension data for this packet.  The first value is an identifier and is
    /// 'defined by the RTP profile'.  The second value is the extension data.
    pub fn extension(&self) -> Option<(u16, &[u8])> {
        if self.extension_bit() {
            let offset = self.extension_offset();
            let id = (self.data[offset] as u16) << 8 | self.data[offset + 1] as u16;
            let offset = offset + 4;
            Some((id, &self.data[offset..offset + self.extension_len()]))
        } else {
            None
        }
    }

    /// Returns the offset of the payload in this packet relative to the beginning of the packet.
    pub fn payload_offset(&self) -> usize {
        self.extension_offset()
            + if self.extension_bit() {
                self.extension_len() + 4
            } else {
                0
            }
    }

    /// Returns the length of the payload in this packet without padding.
    pub fn payload_len(&self) -> usize {
        let offset = self.payload_offset();
        let pad = self.padding().unwrap_or_default() as usize;

        self.data.len() - pad - offset
    }

    /// Returns the payload data
    pub fn payload(&self) -> &[u8] {
        let offset = self.payload_offset();
        let pad = if let Some(pad) = self.padding() {
            pad as usize
        } else {
            0
        };
        &self.data[offset..self.data.len() - pad]
    }

    /// Creates a builder that will be able to reconstruct this packet byte for byte (excluding
    /// any padding bytes).  Any aspect of the returned builder can be modified.
    pub fn as_builder(&'a self) -> crate::RtpPacketBuilder<&'a [u8], &'a [u8]> {
        let mut builder = crate::RtpPacketBuilder::new()
            .marker(self.marker())
            .payload_type(self.payload_type())
            .sequence_number(self.sequence_number())
            .timestamp(self.timestamp())
            .ssrc(self.ssrc())
            .payload(self.payload());
        for csrc in self.csrc() {
            builder = builder.add_csrc(csrc);
        }
        if let Some((ext_id, ext_data)) = self.extension() {
            builder = builder.extension(ext_id, ext_data);
        }
        if let Some(padding) = self.padding() {
            builder = builder.padding(padding);
        }
        builder
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rtp_no_payload_no_extension_no_csrc() {
        let data: [u8; 12] = [
            0x80, 0x60, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,
        ];
        let rtp = RtpPacket::parse(data.as_ref()).unwrap();
        assert_eq!(rtp.version(), 2);
        assert_eq!(rtp.padding(), None);
        assert_eq!(rtp.n_csrcs(), 0);
        assert!(!rtp.marker());
        assert_eq!(rtp.payload_type(), 96);
        assert_eq!(rtp.sequence_number(), 0x0102);
        assert_eq!(rtp.timestamp(), 0x03040506);
        assert_eq!(rtp.ssrc(), 0x07080910);
        assert_eq!(rtp.csrc().count(), 0);
        assert_eq!(rtp.extension(), None);
        assert_eq!(rtp.payload(), &[]);
        let built = rtp.as_builder().write_vec().unwrap();
        assert_eq!(built, data.as_ref());
    }

    #[test]
    fn parse_truncated_rtp_packet() {
        let data: [u8; 11] = [
            0x80, 0x60, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        ];
        assert!(matches!(
            RtpPacket::parse(data.as_ref()),
            Err(RtpParseError::Truncated {
                expected: 12,
                actual: 11
            })
        ));
    }

    #[test]
    fn parse_rtp_with_csrc() {
        let data: [u8; 16] = [
            0x81, 0x60, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12,
            0x13, 0x14,
        ];
        let rtp = RtpPacket::parse(data.as_ref()).unwrap();
        assert_eq!(rtp.version(), 2);
        assert_eq!(rtp.padding(), None);
        assert_eq!(rtp.n_csrcs(), 1);
        assert!(!rtp.marker());
        assert_eq!(rtp.payload_type(), 96);
        assert_eq!(rtp.sequence_number(), 0x0102);
        assert_eq!(rtp.timestamp(), 0x03040506);
        assert_eq!(rtp.ssrc(), 0x07080910);
        let mut csrc = rtp.csrc();
        assert_eq!(csrc.next(), Some(0x11121314));
        assert_eq!(csrc.next(), None);
        assert_eq!(rtp.extension(), None);
        assert_eq!(rtp.payload(), &[]);
        let built = rtp.as_builder().write_vec().unwrap();
        assert_eq!(built, data.as_ref());
    }

    #[test]
    fn parse_rtp_with_short_csrc_data() {
        let data: [u8; 15] = [
            0x81, 0x60, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12,
            0x13,
        ];
        assert!(matches!(
            RtpPacket::parse(data.as_ref()),
            Err(RtpParseError::Truncated {
                expected: 16,
                actual: 15
            })
        ));
    }

    #[test]
    fn parse_rtp_with_extension() {
        let data: [u8; 20] = [
            0x90, 0x60, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x00, 0x1, 0x0d, 0x0e, 0x0f, 0x10,
        ];
        let rtp = RtpPacket::parse(data.as_ref()).unwrap();
        assert_eq!(rtp.version(), 2);
        assert_eq!(rtp.padding(), None);
        assert_eq!(rtp.n_csrcs(), 0);
        assert!(!rtp.marker());
        assert_eq!(rtp.payload_type(), 96);
        assert_eq!(rtp.sequence_number(), 0x0102);
        assert_eq!(rtp.timestamp(), 0x03040506);
        assert_eq!(rtp.ssrc(), 0x0708090a);
        assert_eq!(rtp.csrc().count(), 0);
        assert_eq!(
            rtp.extension(),
            Some((0x0b0c, [0x0d, 0x0e, 0x0f, 0x10].as_ref()))
        );
        assert_eq!(rtp.payload(), &[]);
        let built = rtp.as_builder().write_vec().unwrap();
        assert_eq!(built, data.as_ref());
    }

    #[test]
    fn parse_rtp_with_short_extension_header() {
        let data: [u8; 15] = [
            0x90, 0x60, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x00,
        ];
        assert!(matches!(
            RtpPacket::parse(data.as_ref()),
            Err(RtpParseError::Truncated {
                expected: 16,
                actual: 15
            })
        ));
    }

    #[test]
    fn parse_rtp_with_short_extension_data() {
        let data: [u8; 19] = [
            0x90, 0x60, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x00, 0x01, 0x0d, 0x0e, 0x0f,
        ];
        assert!(matches!(
            RtpPacket::parse(data.as_ref()),
            Err(RtpParseError::Truncated {
                expected: 20,
                actual: 19
            })
        ));
    }

    #[test]
    fn parse_rtp_with_payload() {
        let data: [u8; 16] = [
            0x80, 0x60, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x0d, 0x0e,
        ];
        let rtp = RtpPacket::parse(data.as_ref()).unwrap();
        assert_eq!(rtp.version(), 2);
        assert_eq!(rtp.padding(), None);
        assert_eq!(rtp.n_csrcs(), 0);
        assert!(!rtp.marker());
        assert_eq!(rtp.payload_type(), 96);
        assert_eq!(rtp.sequence_number(), 0x0102);
        assert_eq!(rtp.timestamp(), 0x03040506);
        assert_eq!(rtp.ssrc(), 0x0708090a);
        assert_eq!(rtp.csrc().count(), 0);
        assert_eq!(rtp.extension(), None);
        assert_eq!(rtp.payload(), &[0x0b, 0x0c, 0x0d, 0x0e]);
        let built = rtp.as_builder().write_vec().unwrap();
        assert_eq!(built, data.as_ref());
    }

    #[test]
    fn parse_rtp_with_padding() {
        let data: [u8; 16] = [
            0xa0, 0x60, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x00, 0x02,
        ];
        let rtp = RtpPacket::parse(data.as_ref()).unwrap();
        assert_eq!(rtp.version(), 2);
        assert_eq!(rtp.padding(), Some(2));
        assert_eq!(rtp.n_csrcs(), 0);
        assert!(!rtp.marker());
        assert_eq!(rtp.payload_type(), 96);
        assert_eq!(rtp.sequence_number(), 0x0102);
        assert_eq!(rtp.timestamp(), 0x03040506);
        assert_eq!(rtp.ssrc(), 0x0708090a);
        assert_eq!(rtp.csrc().count(), 0);
        assert_eq!(rtp.extension(), None);
        assert_eq!(rtp.payload(), &[0x0b, 0x0c]);
        let built = rtp.as_builder().write_vec().unwrap();
        assert_eq!(built, data.as_ref());
    }

    #[test]
    fn parse_rtp_with_too_large_padding() {
        let data: [u8; 13] = [
            0xa0, 0x60, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x02,
        ];
        assert!(matches!(
            RtpPacket::parse(data.as_ref()),
            Err(RtpParseError::Truncated {
                expected: 14,
                actual: 13
            })
        ));
    }

    #[test]
    fn parse_rtp_with_zero_padding_length() {
        let data: [u8; 13] = [
            0xa0, 0x60, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x00,
        ];
        assert!(matches!(
            RtpPacket::parse(data.as_ref()),
            Err(RtpParseError::PaddingInvalid(0))
        ));
    }
}
