// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::RtpPacket;

/// Errors produced when wrting a packet
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum RtpWriteError {
    /// Output buffer is not large enough to fit the resulting buffer.  The requested size is
    /// returned.
    #[error("Output buffer is not large enough to fit the resulting buffer. Requested size: {}", .0)]
    OutputTooSmall(usize),
    /// The payload type provided is not valid.
    #[error("Invalid payload type {}", .0)]
    InvalidPayloadType(u8),
    /// The requested packet is too large.
    #[error("Packet is too large")]
    PacketTooLarge,
    /// Too many Contribution Sources specified.  The number of requested Contribution sources is
    /// returned.
    #[error("Too many contribution sources: {}", .0)]
    TooManyContributionSources(usize),
    /// The extension data is not padded to a multiple of 4 bytes.
    #[error("Extension data is not padded to a multiple of 4")]
    ExtensionDataNotPadded,
    /// Padding value is invalid.
    #[error("Value used for padding is invalid")]
    InvalidPadding,
}

/// Struct for building a new RTP packet
#[derive(Clone, Debug)]
#[must_use = "The builder must be built to be used"]
pub struct RtpPacketBuilder<'a> {
    padding: Option<u8>,
    csrcs: smallvec::SmallVec<[u32; 15]>,
    marker: bool,
    payload_type: u8,
    sequence_number: u16,
    timestamp: u32,
    ssrc: u32,
    extension: Option<(u16, &'a [u8])>,
    payloads: smallvec::SmallVec<[&'a [u8]; 16]>,
}

impl<'a> Default for RtpPacketBuilder<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> RtpPacketBuilder<'a> {
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
            payloads: smallvec::smallvec![],
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

    /// Add a chunk of payload data for this packet.
    ///
    /// Can be called multiple times, in which case the payload data chunks will be
    /// concatenated when the final packet is created.
    pub fn payload(mut self, payload: &'a [u8]) -> Self {
        self.payloads.push(payload);
        self
    }

    /// Calculate the size required for writing the packet.
    pub fn calculate_size(&self) -> Result<usize, RtpWriteError> {
        let payload_len = self.payloads.iter().map(|p| p.len()).sum::<usize>();
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
        let mut byte = 0x80; // rtp version 2
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

        for payload in &self.payloads {
            let payload_len = payload.len();
            buf[write_i..write_i + payload_len].copy_from_slice(payload);
            write_i += payload_len;
        }

        if let Some(padding) = self.padding {
            buf[write_i..write_i + padding as usize - 1].fill(0);
            buf[write_i + padding as usize - 1] = padding;
            write_i += padding as usize;
        }

        write_i
    }

    fn write_preconditions(&self) -> Result<(), RtpWriteError> {
        if self.payload_type > 0x7f {
            return Err(RtpWriteError::InvalidPayloadType(self.payload_type));
        }
        if self.csrcs.len() > RtpPacket::MAX_N_CSRCS {
            return Err(RtpWriteError::TooManyContributionSources(self.csrcs.len()));
        }

        if let Some(padding) = self.padding {
            if padding == 0 {
                return Err(RtpWriteError::InvalidPadding);
            }
        }

        Ok(())
    }

    /// Write this packet into `buf`.  On success returns the number of bytes written or an
    /// `RtpWriteError` on failure.
    pub fn write_into(self, buf: &mut [u8]) -> Result<usize, RtpWriteError> {
        self.write_preconditions()?;

        let size = self.calculate_size()?;
        if size > buf.len() {
            return Err(RtpWriteError::OutputTooSmall(size));
        }

        Ok(self.write_into_unchecked(buf))
    }

    /// Write this packet into `buf` without any validity checks.  Returns the number of bytes
    /// written.
    pub fn write_unchecked(self, buf: &mut Vec<u8>) -> usize {
        let start_len = buf.len();

        let mut byte = 0x80; // rtp version 2
        if self.padding.is_some() {
            byte |= 0x20;
        }
        if self.extension.is_some() {
            byte |= 0x10;
        }
        byte |= (self.csrcs.len() as u8) & 0x0f;
        buf.push(byte);

        let mut byte = self.payload_type & 0x7f;
        if self.marker {
            byte |= 0x80;
        }
        buf.push(byte);

        buf.push((self.sequence_number >> 8) as u8);
        buf.push((self.sequence_number & 0xff) as u8);

        buf.push((self.timestamp >> 24) as u8);
        buf.push(((self.timestamp >> 16) & 0xff) as u8);
        buf.push(((self.timestamp >> 8) & 0xff) as u8);
        buf.push((self.timestamp & 0xff) as u8);

        buf.push((self.ssrc >> 24) as u8);
        buf.push(((self.ssrc >> 16) & 0xff) as u8);
        buf.push(((self.ssrc >> 8) & 0xff) as u8);
        buf.push((self.ssrc & 0xff) as u8);

        for csrc in self.csrcs {
            buf.push((csrc >> 24) as u8);
            buf.push(((csrc >> 16) & 0xff) as u8);
            buf.push(((csrc >> 8) & 0xff) as u8);
            buf.push((csrc & 0xff) as u8);
        }

        if let Some((ext_id, ext_data)) = self.extension {
            buf.push((ext_id >> 8) as u8);
            buf.push((ext_id & 0xff) as u8);
            buf.push((((ext_data.len() / 4) >> 8) & 0xff) as u8);
            buf.push(((ext_data.len() / 4) & 0xff) as u8);
            if !ext_data.is_empty() {
                buf.extend(ext_data);
            }
        }

        for &payload in &self.payloads {
            buf.extend(payload);
        }

        if let Some(padding) = self.padding {
            buf.extend(std::iter::repeat(0).take(padding as usize - 1));
            buf.push(padding);
        }

        buf.len() - start_len
    }

    /// Write the packet into `buf` appending to any data that already exists.
    /// Returns the number of bytes written.
    pub fn write(self, buf: &mut Vec<u8>) -> Result<usize, RtpWriteError> {
        self.write_preconditions()?;
        let len = self.calculate_size()?;

        buf.reserve(len);
        Ok(self.write_unchecked(buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_rtp_default() {
        let mut data = [0; 128];
        let builder = RtpPacketBuilder::new().payload_type(96);
        let size = builder.clone().write_into(&mut data).unwrap();
        let data = &data[..size];
        let mut buf = vec![];
        let size_owned = builder.write(&mut buf).unwrap();
        assert_eq!(size, size_owned);
        for data in [data, buf.as_ref()] {
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
    }

    #[test]
    fn write_rtp_header() {
        let mut data = [0; 128];
        let builder = RtpPacketBuilder::new()
            .payload_type(96)
            .marker(true)
            .sequence_number(0x0102)
            .timestamp(0x03040506)
            .ssrc(0x0708090a)
            .add_csrc(0x0b0c0d0e);
        let size = builder.clone().write_into(&mut data).unwrap();
        let data = &data[..size];
        let mut buf = vec![];
        let size_owned = builder.write(&mut buf).unwrap();
        assert_eq!(size, size_owned);
        for data in [data, buf.as_ref()] {
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
    }

    #[test]
    fn write_rtp_header_multiple_csrcs() {
        let mut data = [0; 128];
        let builder = RtpPacketBuilder::new()
            .payload_type(96)
            .add_csrc(0x01020304)
            .add_csrc(0x05060708);
        let size = builder.clone().write_into(&mut data).unwrap();
        let data = &data[..size];
        let mut buf = vec![];
        let size_owned = builder.write(&mut buf).unwrap();
        assert_eq!(size, size_owned);
        for data in [data, buf.as_ref()] {
            println!("{data:?}");
            let rtp = RtpPacket::parse(data).unwrap();
            assert_eq!(rtp.n_csrcs(), 2);
            let mut csrc = rtp.csrc();
            assert_eq!(csrc.next(), Some(0x01020304));
            assert_eq!(csrc.next(), Some(0x05060708));
            assert_eq!(csrc.next(), None);
        }
    }

    #[test]
    fn write_rtp_multiple_payloads() {
        let mut data = [0; 128];
        let payload_data = [1, 2, 3, 4, 5, 6, 7, 8];
        let more_payload_data = [9, 10, 11];
        let builder = RtpPacketBuilder::new()
            .payload_type(96)
            .payload(&payload_data)
            .payload(&more_payload_data)
            .payload(&more_payload_data[0..1]);
        let size = builder.clone().write_into(&mut data).unwrap();
        assert_eq!(size, 24);
        let data = &data[..size];
        let mut buf = vec![];
        let size_owned = builder.write(&mut buf).unwrap();
        assert_eq!(size, size_owned);
        for data in [data, buf.as_ref()] {
            println!("{data:?}");
            let rtp = RtpPacket::parse(data).unwrap();
            assert_eq!(rtp.version(), 2);
            assert_eq!(rtp.payload_type(), 96);
            assert_eq!(rtp.payload(), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 9]);
        }
    }

    #[test]
    fn write_rtp_extension() {
        let mut data = [0; 128];
        let extension_data = [1, 2, 3, 4, 5, 6, 7, 8];
        let builder = RtpPacketBuilder::new()
            .payload_type(96)
            .marker(true)
            .sequence_number(0x0102)
            .timestamp(0x03040506)
            .ssrc(0x0708090a)
            .add_csrc(0x0b0c0d0e)
            .extension(0x9876, &extension_data);
        let size = builder.clone().write_into(&mut data).unwrap();
        let data = &data[..size];
        let mut buf = vec![];
        let size_owned = builder.write(&mut buf).unwrap();
        assert_eq!(size, size_owned);
        for data in [data, buf.as_ref()] {
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
    }

    #[test]
    fn write_rtp_extension_payload_padding() {
        let mut data = [0; 128];
        let extension_data = [1, 2, 3, 4, 5, 6, 7, 8];
        let payload_data = [1, 2, 3, 4, 5, 6, 7, 8];
        let builder = RtpPacketBuilder::new()
            .payload_type(96)
            .marker(true)
            .sequence_number(0x0102)
            .timestamp(0x03040506)
            .ssrc(0x0708090a)
            .add_csrc(0x0b0c0d0e)
            .extension(0x9876, &extension_data)
            .payload(&payload_data)
            .padding(7);
        let size = builder.clone().write_into(&mut data).unwrap();
        let data = &data[..size];
        let mut buf = vec![];
        let size_owned = builder.write(&mut buf).unwrap();
        assert_eq!(size, size_owned);
        for data in [data, buf.as_ref()] {
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
    }

    #[test]
    fn write_rtp_invalid_padding() {
        let mut data = [0; 128];
        let builder = RtpPacketBuilder::new().payload_type(96).padding(0);
        assert_eq!(
            builder.clone().write_into(&mut data),
            Err(RtpWriteError::InvalidPadding)
        );
        let mut data = vec![];
        assert_eq!(builder.write(&mut data), Err(RtpWriteError::InvalidPadding));
    }

    #[test]
    fn write_rtp_unpadded_extension() {
        let mut data = [0; 128];
        let builder = RtpPacketBuilder::new()
            .payload_type(96)
            .extension(0x9876, &[1]);
        assert_eq!(
            builder.clone().write_into(&mut data),
            Err(RtpWriteError::ExtensionDataNotPadded)
        );
        let mut data = vec![];
        assert_eq!(
            builder.clone().write(&mut data),
            Err(RtpWriteError::ExtensionDataNotPadded)
        );
    }

    #[test]
    fn write_rtp_invalid_payload_type() {
        let mut data = [0; 128];
        let builder = RtpPacketBuilder::new().payload_type(0xFF);
        assert_eq!(
            builder.clone().write_into(&mut data),
            Err(RtpWriteError::InvalidPayloadType(0xFF))
        );
        let mut data = vec![];
        assert_eq!(
            builder.write(&mut data),
            Err(RtpWriteError::InvalidPayloadType(0xFF))
        );
    }

    #[test]
    fn write_rtp_too_many_contributions() {
        let mut data = [0; 128];
        let builder = RtpPacketBuilder::new()
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
            .add_csrc(16);
        assert_eq!(
            builder.clone().write_into(&mut data),
            Err(RtpWriteError::TooManyContributionSources(16))
        );
        let mut data = vec![];
        assert_eq!(
            builder.write(&mut data),
            Err(RtpWriteError::TooManyContributionSources(16))
        );
    }

    #[test]
    fn write_rtp_extension_too_large() {
        let mut data = [0; u16::MAX as usize + 128];
        let extension_data = [0; u16::MAX as usize + 1];
        let builder = RtpPacketBuilder::new()
            .payload_type(96)
            .extension(0x9876, &extension_data);
        assert_eq!(
            builder.clone().write_into(&mut data),
            Err(RtpWriteError::PacketTooLarge)
        );
        let mut data = vec![];
        assert_eq!(builder.write(&mut data), Err(RtpWriteError::PacketTooLarge));
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
