// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::RtpPacket;

/// Errors produced when wrting a packet
#[derive(Debug, PartialEq, Eq)]
pub enum RtpWriteError {
    /// Output buffer is not large enough to fit the resulting buffer.  The requested size is
    /// returned.
    OutputTooSmall(usize),
    /// The payload type provided is not valid.
    InvalidPayloadType(u8),
    /// The requested packet is too large.
    PacketTooLarge,
    /// Too many Contribution Sources specified.  The number of requested Contribution sources is
    /// returned.
    TooManyContributionSources(usize),
    /// The extension data is not padded to a multiple of 4 bytes.
    ExtensionDataNotPadded,
    /// Padding value is invalid.
    InvalidPadding,
}

/// Struct for building a new RTP packet
#[derive(Clone)]
pub struct RtpPacketBuilder<'a> {
    padding: Option<u8>,
    csrcs: smallvec::SmallVec<[u32; 15]>,
    marker: bool,
    payload_type: u8,
    sequence_number: u16,
    timestamp: u32,
    ssrc: u32,
    extension: Option<(u16, &'a [u8])>,
    payload: Option<&'a [u8]>,
}

impl<'a> Default for RtpPacketBuilder<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> RtpPacketBuilder<'a> {
    const MAX_N_CSRCS: usize = 0xf;

    /// Construct a new packet builder
    pub fn new() -> RtpPacketBuilder<'a> {
        Self {
            padding: None,
            csrcs: smallvec::smallvec![],
            marker: false,
            // set to an invalid value to force the user to update
            payload_type: 0xff,
            sequence_number: 0,
            timestamp: 0,
            ssrc: 0,
            extension: None,
            payload: None,
        }
    }

    /// Set the number of padding bytes to use for this packet
    pub fn padding(mut self, padding: u8) -> Self {
        self.padding = Some(padding);
        self
    }

    /// Add a Contribution Source for this packet
    pub fn add_csrc(mut self, csrc: u32) -> Self {
        self.csrcs.push(csrc);
        self
    }

    /// Set the marker bit for this packet
    pub fn marker(mut self, marker: bool) -> Self {
        self.marker = marker;
        self
    }

    /// Set the payload type for this packet
    pub fn payload_type(mut self, pt: u8) -> Self {
        self.payload_type = pt;
        self
    }

    /// Set the sequence number for this packet
    pub fn sequence_number(mut self, sequence: u16) -> Self {
        self.sequence_number = sequence;
        self
    }

    /// Set the RTP timestamp for this packet
    pub fn timestamp(mut self, timestamp: u32) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// Set the Sequence source for this packet
    pub fn ssrc(mut self, ssrc: u32) -> Self {
        self.ssrc = ssrc;
        self
    }

    /// Set the extension header for this packet
    pub fn extension(mut self, extension_id: u16, extension_data: &'a [u8]) -> Self {
        self.extension = Some((extension_id, extension_data));
        self
    }

    /// Set the payload data for this packet
    pub fn payload(mut self, payload: &'a [u8]) -> Self {
        self.payload = Some(payload);
        self
    }

    /// Calculate the size required for writing the packet.
    pub fn calculate_size(&self) -> Result<usize, RtpWriteError> {
        let payload_len = if let Some(payload) = self.payload {
            payload.len()
        } else {
            0
        };
        let extension_len = if let Some((_ext_id, ext_data)) = self.extension {
            if ext_data.len() > u16::MAX as usize {
                return Err(RtpWriteError::PacketTooLarge);
            }
            if ext_data.len() % 4 != 0 {
                return Err(RtpWriteError::ExtensionDataNotPadded);
            }
            4 + ext_data.len() / 4
        } else {
            0
        };
        let mut size = RtpPacket::MIN_RTP_PACKET_LEN;
        size += self.csrcs.len() * 4;
        size += extension_len;
        size += payload_len;
        if let Some(padding) = self.padding {
            size += padding as usize;
        }
        Ok(size)
    }

    /// Write this packet into `buf` without any validity checks.  Returns the number of bytes
    /// written.
    pub fn write_into_unchecked(self, buf: &mut [u8]) -> usize {
        let mut byte = 0x80; // rtp version 24
        if self.padding.is_some() {
            byte |= 0x20;
        }
        if self.extension.is_some() {
            byte |= 0x10;
        }
        byte |= (self.csrcs.len() as u8) & 0x0f;
        buf[0] = byte;

        let mut byte = self.payload_type & 0x7f;
        if self.marker {
            byte |= 0x80;
        }
        buf[1] = byte;

        buf[2] = (self.sequence_number >> 8) as u8;
        buf[3] = (self.sequence_number & 0xff) as u8;

        buf[4] = (self.timestamp >> 24) as u8;
        buf[5] = ((self.timestamp >> 16) & 0xff) as u8;
        buf[6] = ((self.timestamp >> 8) & 0xff) as u8;
        buf[7] = (self.timestamp & 0xff) as u8;

        buf[8] = (self.ssrc >> 24) as u8;
        buf[9] = ((self.ssrc >> 16) & 0xff) as u8;
        buf[10] = ((self.ssrc >> 8) & 0xff) as u8;
        buf[11] = (self.ssrc & 0xff) as u8;

        let mut write_i = 12;

        for csrc in self.csrcs {
            buf[write_i] = (csrc >> 24) as u8;
            buf[write_i + 1] = ((csrc >> 16) & 0xff) as u8;
            buf[write_i + 2] = ((csrc >> 8) & 0xff) as u8;
            buf[write_i + 3] = (csrc & 0xff) as u8;

            write_i += 4;
        }

        if let Some((ext_id, ext_data)) = self.extension {
            buf[write_i] = (ext_id >> 8) as u8;
            buf[write_i + 1] = (ext_id & 0xff) as u8;
            buf[write_i + 2] = (((ext_data.len() / 4) >> 8) & 0xff) as u8;
            buf[write_i + 3] = ((ext_data.len() / 4) & 0xff) as u8;
            write_i += 4;
            if !ext_data.is_empty() {
                buf[write_i..write_i + ext_data.len()].copy_from_slice(ext_data);
                write_i += ext_data.len();
            }
        }

        if let Some(payload) = self.payload {
            buf[write_i..write_i + payload.len()].copy_from_slice(payload);
            write_i += payload.len();
        }

        if let Some(padding) = self.padding {
            buf[write_i..write_i + padding as usize - 1].fill(0);
            buf[write_i + padding as usize - 1] = padding;
            write_i += padding as usize;
        }

        write_i
    }

    /// Write this packet into `buf`.  On success returns the number of bytes written or an
    /// `RtpWriteError` on failure.
    pub fn write_into(self, buf: &mut [u8]) -> Result<usize, RtpWriteError> {
        if self.payload_type > 0x7f {
            return Err(RtpWriteError::InvalidPayloadType(self.payload_type));
        }
        if self.csrcs.len() > Self::MAX_N_CSRCS {
            return Err(RtpWriteError::TooManyContributionSources(self.csrcs.len()));
        }

        if let Some(padding) = self.padding {
            if padding == 0 {
                return Err(RtpWriteError::InvalidPadding);
            }
        }

        let size = self.calculate_size()?;
        if size > buf.len() {
            return Err(RtpWriteError::OutputTooSmall(size));
        }

        Ok(self.write_into_unchecked(buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_rtp_default() {
        let mut data = [0; 128];
        let size = RtpPacketBuilder::new()
            .payload_type(96)
            .write_into(&mut data)
            .unwrap();
        let data = &data[..size];
        println!("{data:?}");
        let rtp = RtpPacket::parse(data).unwrap();
        assert_eq!(rtp.version(), 2);
        assert_eq!(rtp.padding(), None);
        assert_eq!(rtp.n_csrcs(), 0);
        assert!(!rtp.marker());
        assert_eq!(rtp.payload_type(), 96);
        assert_eq!(rtp.sequence_number(), 0x0);
        assert_eq!(rtp.timestamp(), 0x0);
        assert_eq!(rtp.ssrc(), 0x0);
        assert_eq!(rtp.csrc().count(), 0);
        assert_eq!(rtp.extension(), None);
        assert_eq!(rtp.payload(), &[]);
    }

    #[test]
    fn write_rtp_header() {
        let mut data = [0; 128];
        let size = RtpPacketBuilder::new()
            .payload_type(96)
            .marker(true)
            .sequence_number(0x0102)
            .timestamp(0x03040506)
            .ssrc(0x0708090a)
            .add_csrc(0x0b0c0d0e)
            .write_into(&mut data)
            .unwrap();
        let data = &data[..size];
        println!("{data:?}");
        let rtp = RtpPacket::parse(data).unwrap();
        assert_eq!(rtp.version(), 2);
        assert_eq!(rtp.padding(), None);
        assert_eq!(rtp.n_csrcs(), 1);
        assert!(rtp.marker());
        assert_eq!(rtp.payload_type(), 96);
        assert_eq!(rtp.sequence_number(), 0x0102);
        assert_eq!(rtp.timestamp(), 0x03040506);
        assert_eq!(rtp.ssrc(), 0x0708090a);
        let mut csrc = rtp.csrc();
        assert_eq!(csrc.next(), Some(0x0b0c0d0e));
        assert_eq!(csrc.next(), None);
        assert_eq!(rtp.extension(), None);
        assert_eq!(rtp.payload(), &[]);
    }

    #[test]
    fn write_rtp_header_multiple_csrcs() {
        let mut data = [0; 128];
        let size = RtpPacketBuilder::new()
            .payload_type(96)
            .add_csrc(0x01020304)
            .add_csrc(0x05060708)
            .write_into(&mut data)
            .unwrap();
        let data = &data[..size];
        println!("{data:?}");
        let rtp = RtpPacket::parse(data).unwrap();
        assert_eq!(rtp.n_csrcs(), 2);
        let mut csrc = rtp.csrc();
        assert_eq!(csrc.next(), Some(0x01020304));
        assert_eq!(csrc.next(), Some(0x05060708));
        assert_eq!(csrc.next(), None);
    }

    #[test]
    fn write_rtp_extension() {
        let mut data = [0; 128];
        let extension_data = [1, 2, 3, 4, 5, 6, 7, 8];
        let size = RtpPacketBuilder::new()
            .payload_type(96)
            .marker(true)
            .sequence_number(0x0102)
            .timestamp(0x03040506)
            .ssrc(0x0708090a)
            .add_csrc(0x0b0c0d0e)
            .extension(0x9876, &extension_data)
            .write_into(&mut data)
            .unwrap();
        let data = &data[..size];
        println!("{data:?}");
        let rtp = RtpPacket::parse(data).unwrap();
        assert_eq!(rtp.version(), 2);
        assert_eq!(rtp.padding(), None);
        assert_eq!(rtp.n_csrcs(), 1);
        assert!(rtp.marker());
        assert_eq!(rtp.payload_type(), 96);
        assert_eq!(rtp.sequence_number(), 0x0102);
        assert_eq!(rtp.timestamp(), 0x03040506);
        assert_eq!(rtp.ssrc(), 0x0708090a);
        let mut csrc = rtp.csrc();
        assert_eq!(csrc.next(), Some(0x0b0c0d0e));
        assert_eq!(csrc.next(), None);
        assert_eq!(rtp.extension(), Some((0x9876, extension_data.as_ref())));
        assert_eq!(rtp.payload(), &[]);
    }

    #[test]
    fn write_rtp_extension_payload_padding() {
        let mut data = [0; 128];
        let extension_data = [1, 2, 3, 4, 5, 6, 7, 8];
        let payload_data = [1, 2, 3, 4, 5, 6, 7, 8];
        let size = RtpPacketBuilder::new()
            .payload_type(96)
            .marker(true)
            .sequence_number(0x0102)
            .timestamp(0x03040506)
            .ssrc(0x0708090a)
            .add_csrc(0x0b0c0d0e)
            .extension(0x9876, &extension_data)
            .payload(&payload_data)
            .padding(7)
            .write_into(&mut data)
            .unwrap();
        let data = &data[..size];
        println!("{data:?}");
        let rtp = RtpPacket::parse(data).unwrap();
        assert_eq!(rtp.version(), 2);
        assert_eq!(rtp.padding(), Some(7));
        assert_eq!(rtp.n_csrcs(), 1);
        assert!(rtp.marker());
        assert_eq!(rtp.payload_type(), 96);
        assert_eq!(rtp.sequence_number(), 0x0102);
        assert_eq!(rtp.timestamp(), 0x03040506);
        assert_eq!(rtp.ssrc(), 0x0708090a);
        let mut csrc = rtp.csrc();
        assert_eq!(csrc.next(), Some(0x0b0c0d0e));
        assert_eq!(csrc.next(), None);
        assert_eq!(rtp.extension(), Some((0x9876, extension_data.as_ref())));
        assert_eq!(rtp.payload(), payload_data.as_ref());
    }

    #[test]
    fn write_rtp_invalid_padding() {
        let mut data = [0; 128];
        assert_eq!(
            RtpPacketBuilder::new()
                .payload_type(96)
                .padding(0)
                .write_into(&mut data),
            Err(RtpWriteError::InvalidPadding)
        );
    }

    #[test]
    fn write_rtp_unpadded_extension() {
        let mut data = [0; 128];
        assert_eq!(
            RtpPacketBuilder::new()
                .payload_type(96)
                .extension(0x9876, &[1])
                .write_into(&mut data),
            Err(RtpWriteError::ExtensionDataNotPadded)
        );
    }

    #[test]
    fn write_rtp_invalid_payload_type() {
        let mut data = [0; 128];
        assert_eq!(
            RtpPacketBuilder::new()
                .payload_type(0xFF)
                .write_into(&mut data),
            Err(RtpWriteError::InvalidPayloadType(0xFF))
        );
    }

    #[test]
    fn write_rtp_too_many_contributions() {
        let mut data = [0; 128];
        assert_eq!(
            RtpPacketBuilder::new()
                .payload_type(96)
                .add_csrc(1)
                .add_csrc(2)
                .add_csrc(3)
                .add_csrc(4)
                .add_csrc(5)
                .add_csrc(6)
                .add_csrc(7)
                .add_csrc(8)
                .add_csrc(9)
                .add_csrc(10)
                .add_csrc(11)
                .add_csrc(12)
                .add_csrc(13)
                .add_csrc(14)
                .add_csrc(15)
                .add_csrc(16)
                .write_into(&mut data),
            Err(RtpWriteError::TooManyContributionSources(16))
        );
    }

    #[test]
    fn write_rtp_extension_too_large() {
        let mut data = [0; u16::MAX as usize + 128];
        let extension_data = [0; u16::MAX as usize + 1];
        assert_eq!(
            RtpPacketBuilder::new()
                .payload_type(96)
                .extension(0x9876, &extension_data)
                .write_into(&mut data),
            Err(RtpWriteError::PacketTooLarge)
        );
    }

    #[test]
    fn write_rtp_output_too_short() {
        let mut data = [0; 11];
        assert_eq!(
            RtpPacketBuilder::new()
                .payload_type(96)
                .write_into(&mut data),
            Err(RtpWriteError::OutputTooSmall(12))
        );
    }

    #[test]
    fn write_rtp_output_too_short_with_csrc() {
        let mut data = [0; 15];
        assert_eq!(
            RtpPacketBuilder::new()
                .payload_type(96)
                .add_csrc(1)
                .write_into(&mut data),
            Err(RtpWriteError::OutputTooSmall(16))
        );
    }

    #[test]
    fn write_rtp_output_too_short_extension() {
        let mut data = [0; 15];
        assert_eq!(
            RtpPacketBuilder::new()
                .payload_type(96)
                .extension(0x9876, &[])
                .write_into(&mut data),
            Err(RtpWriteError::OutputTooSmall(16))
        );
    }

    #[test]
    fn write_rtp_output_too_short_padding() {
        let mut data = [0; 12];
        assert_eq!(
            RtpPacketBuilder::new()
                .payload_type(96)
                .padding(1)
                .write_into(&mut data),
            Err(RtpWriteError::OutputTooSmall(13))
        );
    }

    #[test]
    fn write_rtp_output_too_short_payload() {
        let mut data = [0; 12];
        assert_eq!(
            RtpPacketBuilder::new()
                .payload_type(96)
                .payload(&[1])
                .write_into(&mut data),
            Err(RtpWriteError::OutputTooSmall(13))
        );
    }
}
