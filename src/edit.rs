// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{RtpPacket, RtpParseError, RtpWriteError};

/// Mutable parsed RTP packet for editing of some fields.
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
    pub fn set_marker(&mut self, marker: bool) {
        if marker {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edit_rtp_no_payload_no_extensions_no_csrc() {
        let mut data: [u8; 12] = [
            0x80, 0x60, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,
        ];
        let mut rtp = RtpPacketMut::parse(data.as_mut_slice()).unwrap();
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
        rtp.set_marker(true);
        assert!(rtp.marker());
        rtp.set_payload_type(12).unwrap();
        assert_eq!(rtp.payload_type(), 12);
        rtp.set_sequence_number(0x9876);
        assert_eq!(rtp.sequence_number(), 0x9876);
        rtp.set_timestamp(0x19283746);
        assert_eq!(rtp.timestamp(), 0x19283746);
        rtp.set_ssrc(0x90807060);
        assert_eq!(rtp.ssrc(), 0x90807060);
    }
}
