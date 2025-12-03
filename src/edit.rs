// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{RtpPacket, RtpParseError, RtpWriteError};

/// Mutable parsed RTP packet for editing of some fields.
#[derive(Debug)]
#[repr(transparent)]
pub struct RtpPacketMut<'a> {
    data: &'a mut [u8],
}

impl<'a> std::ops::Deref for RtpPacketMut<'a> {
    type Target = RtpPacket<'a>;

    fn deref(&self) -> &Self::Target {
        // SAFETY: RtpPacket and RtpPacketMut have the same contents and only differ in mut-ness
        unsafe { std::mem::transmute(self) }
    }
}

impl<'a> RtpPacketMut<'a> {
    /// The minimum number of bytes a RTP packet must be to be parsed correctly.
    pub const MIN_RTP_PACKET_LEN: usize = RtpPacket::MIN_RTP_PACKET_LEN;

    /// Parse a byte slice into an editable [`RtpPacketMut`].  The packet is first parsed using
    /// [`RtpPacket::parse`] and will fail if parsing fails.
    pub fn parse(data: &'a mut [u8]) -> Result<RtpPacketMut<'a>, RtpParseError> {
        let _packet = RtpPacket::parse(data)?;

        Ok(RtpPacketMut { data })
    }

    /// Change the marker bit of this packet.
    #[deprecated = "Use `set_marker_bit()` instead"]
    pub fn set_marker(&mut self, marker: bool) {
        self.set_marker_bit(marker);
    }

    /// Change the marker bit of this packet.
    pub fn set_marker_bit(&mut self, marker_bit: bool) {
        if marker_bit {
            self.data[1] |= 0x80;
        } else {
            self.data[1] &= 0x7f;
        }
    }

    /// Change the payload type of this packet.
    pub fn set_payload_type(&mut self, pt: u8) -> Result<(), RtpWriteError> {
        if pt > 0x7f {
            return Err(RtpWriteError::InvalidPayloadType(pt));
        }

        self.data[1] = (self.data[1] & 0x80) | pt;

        Ok(())
    }

    /// Change the sequence number of this packet.
    pub fn set_sequence_number(&mut self, sequence: u16) {
        self.data[2] = (sequence >> 8) as u8;
        self.data[3] = (sequence & 0xff) as u8;
    }

    /// Change the timestamp of this packet.
    pub fn set_timestamp(&mut self, timestamp: u32) {
        self.data[4] = (timestamp >> 24) as u8;
        self.data[5] = ((timestamp >> 16) & 0xff) as u8;
        self.data[6] = ((timestamp >> 8) & 0xff) as u8;
        self.data[7] = (timestamp & 0xff) as u8;
    }

    /// Change the SSRC of this packet.
    pub fn set_ssrc(&mut self, ssrc: u32) {
        self.data[8] = (ssrc >> 24) as u8;
        self.data[9] = ((ssrc >> 16) & 0xff) as u8;
        self.data[10] = ((ssrc >> 8) & 0xff) as u8;
        self.data[11] = (ssrc & 0xff) as u8;
    }

    /// Change the extension identifier of this packet.
    ///
    /// This has no effect if the packet does not contain any extension data.
    pub fn set_extension_id(&mut self, id: u16) {
        if self.extension_bit() {
            let offset = self.extension_offset();
            self.data[offset] = (id >> 8) as u8;
            self.data[offset + 1] = (id & 0xff) as u8;
        }
    }

    /// Returns a mutable reference to the extension data for this packet, if any.
    pub fn extension_mut(&mut self) -> Option<&mut [u8]> {
        if self.extension_bit() {
            let offset = self.extension_offset();
            let offset = offset + 4;
            let len = self.extension_len();
            Some(&mut self.data[offset..][..len])
        } else {
            None
        }
    }

    /// Returns a mutable reference to the payload data of this packet.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let offset = self.payload_offset();
        let pad = self.padding().unwrap_or_default() as usize;
        let data_len = self.data.len();
        &mut self.data[offset..data_len - pad]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edit_rtp_no_payload_no_extensions_no_csrc() {
        let mut data: [u8; 13] = [
            0x80, 0x60, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11,
        ];
        let mut rtp = RtpPacketMut::parse(data.as_mut_slice()).unwrap();
        assert_eq!(rtp.version(), 2);
        assert_eq!(rtp.padding(), None);
        assert_eq!(rtp.n_csrcs(), 0);
        assert!(!rtp.marker_bit());
        assert_eq!(rtp.payload_type(), 96);
        assert_eq!(rtp.sequence_number(), 0x0102);
        assert_eq!(rtp.timestamp(), 0x03040506);
        assert_eq!(rtp.ssrc(), 0x07080910);
        assert_eq!(rtp.csrc().count(), 0);
        assert_eq!(rtp.extension(), None);
        assert_eq!(rtp.payload(), &[0x11]);
        assert_eq!(rtp.payload_mut(), [0x11].as_mut_slice());
        rtp.set_marker_bit(true);
        assert!(rtp.marker_bit());
        rtp.set_payload_type(0x7F).unwrap();
        assert_eq!(rtp.payload_type(), 0x7F);
        rtp.set_sequence_number(0x9876);
        assert_eq!(rtp.sequence_number(), 0x9876);
        rtp.set_timestamp(0x19283746);
        assert_eq!(rtp.timestamp(), 0x19283746);
        rtp.set_ssrc(0x90807060);
        assert_eq!(rtp.ssrc(), 0x90807060);
    }

    #[test]
    fn edit_rtp_set_payload_out_of_range() {
        let mut data: [u8; 12] = [
            0x80, 0x60, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,
        ];
        let mut rtp = RtpPacketMut::parse(data.as_mut_slice()).unwrap();
        assert_eq!(
            rtp.set_payload_type(0xFF),
            Err(RtpWriteError::InvalidPayloadType(0xFF))
        );
        assert_eq!(
            rtp.set_payload_type(0x80),
            Err(RtpWriteError::InvalidPayloadType(0x80))
        );
    }

    #[test]
    fn edit_rtp_with_extension() {
        let mut data: [u8; 20] = [
            0x90, 0xE0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x00, 0x1, 0x0d, 0x0e, 0x0f, 0x10,
        ];
        let mut rtp = RtpPacketMut::parse(data.as_mut_slice()).unwrap();
        assert_eq!(rtp.version(), 2);
        assert_eq!(rtp.padding(), None);
        assert_eq!(rtp.n_csrcs(), 0);
        assert!(rtp.marker_bit());
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
        assert_eq!(rtp.payload_mut(), &mut []);

        rtp.set_marker_bit(false);
        assert!(!rtp.marker_bit());
        rtp.set_payload_type(0x7F).unwrap();
        assert_eq!(rtp.payload_type(), 0x7F);
        rtp.set_sequence_number(0x9876);
        assert_eq!(rtp.sequence_number(), 0x9876);
        rtp.set_timestamp(0x19283746);
        assert_eq!(rtp.timestamp(), 0x19283746);
        rtp.set_ssrc(0x90807060);
        assert_eq!(rtp.ssrc(), 0x90807060);
        rtp.set_extension_id(0x1234);
        assert_eq!(
            rtp.extension(),
            Some((0x1234, [0x0d, 0x0e, 0x0f, 0x10].as_ref()))
        );
        assert_eq!(
            rtp.extension_mut(),
            Some([0x0d, 0x0e, 0x0f, 0x10].as_mut_slice())
        );
    }

    #[test]
    fn edit_rtp_with_payload() {
        let mut data: [u8; 16] = [
            0x80, 0x60, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x0d, 0x0e,
        ];
        let mut rtp = RtpPacketMut::parse(data.as_mut_slice()).unwrap();
        assert_eq!(rtp.version(), 2);
        assert_eq!(rtp.padding(), None);
        assert_eq!(rtp.n_csrcs(), 0);
        assert!(!rtp.marker_bit());
        assert_eq!(rtp.payload_type(), 96);
        assert_eq!(rtp.sequence_number(), 0x0102);
        assert_eq!(rtp.timestamp(), 0x03040506);
        assert_eq!(rtp.ssrc(), 0x0708090a);
        assert_eq!(rtp.csrc().count(), 0);
        assert_eq!(rtp.extension(), None);
        assert_eq!(rtp.payload(), &[0x0b, 0x0c, 0x0d, 0x0e]);

        rtp.set_marker_bit(true);
        assert!(rtp.marker_bit());
        rtp.set_payload_type(0x00).unwrap();
        assert_eq!(rtp.payload_type(), 0x00);
        rtp.set_sequence_number(0x9876);
        assert_eq!(rtp.sequence_number(), 0x9876);
        rtp.set_timestamp(0x19283746);
        assert_eq!(rtp.timestamp(), 0x19283746);
        rtp.set_ssrc(0x90807060);
        assert_eq!(rtp.ssrc(), 0x90807060);
        rtp.set_extension_id(0x1234);
        assert_eq!(rtp.payload(), [0x0b, 0x0c, 0x0d, 0x0e].as_ref());
        assert_eq!(rtp.payload_mut(), [0x0b, 0x0c, 0x0d, 0x0e].as_mut_slice());
    }

    #[test]
    fn parse_rtp_with_padding() {
        let mut data: [u8; 16] = [
            0xa0, 0x60, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x0b, 0x0c,
            0x00, 0x02,
        ];
        let mut rtp = RtpPacketMut::parse(data.as_mut_slice()).unwrap();
        assert_eq!(rtp.version(), 2);
        assert_eq!(rtp.padding(), Some(2));
        assert_eq!(rtp.n_csrcs(), 0);
        assert!(!rtp.marker_bit());
        assert_eq!(rtp.payload_type(), 96);
        assert_eq!(rtp.sequence_number(), 0x1234);
        assert_eq!(rtp.timestamp(), 0x56789abc);
        assert_eq!(rtp.ssrc(), 0xdef01234);
        assert_eq!(rtp.csrc().count(), 0);
        assert_eq!(rtp.extension(), None);
        assert_eq!(rtp.payload(), &[0x0b, 0x0c]);
        assert_eq!(rtp.payload_len(), 2);

        rtp.set_marker_bit(true);
        assert!(rtp.marker_bit());
        rtp.set_payload_type(0x01).unwrap();
        assert_eq!(rtp.payload_type(), 0x01);
        rtp.set_sequence_number(0x9876);
        assert_eq!(rtp.sequence_number(), 0x9876);
        rtp.set_timestamp(0x19283746);
        assert_eq!(rtp.timestamp(), 0x19283746);
        rtp.set_ssrc(0x90807060);
        assert_eq!(rtp.ssrc(), 0x90807060);
        rtp.set_extension_id(0x1234);
        assert_eq!(rtp.payload(), &[0x0b, 0x0c]);
        assert_eq!(rtp.payload_mut(), &mut [0x0b, 0x0c]);
    }
}
