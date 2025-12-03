// SPDX-License-Identifier: MIT OR Apache-2.0

use std::marker::PhantomData;

use crate::RtpPacket;

/// Errors produced when wrting a packet
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
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

/// Struct for building a new RTP packet.
#[derive(Debug)]
#[must_use = "The builder must be built to be used"]
pub struct RtpPacketBuilder<P: PayloadLength, E: PayloadLength> {
    padding: Option<u8>,
    csrcs: smallvec::SmallVec<[u32; 15]>,
    marker_bit: bool,
    payload_type: u8,
    sequence_number: u16,
    timestamp: u32,
    ssrc: u32,
    extension: Option<(u16, E)>,
    payloads: smallvec::SmallVec<[P; 16]>,
}

impl<P: PayloadLength, E: PayloadLength> Default for RtpPacketBuilder<P, E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: PayloadLength, E: PayloadLength> RtpPacketBuilder<P, E> {
    /// Construct a new packet builder.
    pub fn new() -> RtpPacketBuilder<P, E> {
        Self {
            padding: None,
            csrcs: smallvec::smallvec![],
            marker_bit: false,
            // set to an invalid value to force the user to update
            payload_type: 0xff,
            sequence_number: 0,
            timestamp: 0,
            ssrc: 0,
            extension: None,
            payloads: smallvec::SmallVec::new(),
        }
    }

    /// Set the number of padding bytes to use for this packet.
    pub fn padding(mut self, padding: u8) -> Self {
        self.padding = Some(padding);
        self
    }

    /// Set 1. whether padding is used and 2. the number of padding bytes to use for this packet.
    pub fn maybe_padding(mut self, padding: Option<u8>) -> Self {
        self.padding = padding;
        self
    }

    /// Add a Contribution Source for this packet.
    pub fn add_csrc(mut self, csrc: u32) -> Self {
        self.csrcs.push(csrc);
        self
    }

    /// Clear any CSRCs configured for this packet.
    pub fn clear_csrcs(mut self) -> Self {
        self.csrcs.clear();
        self
    }

    /// Set the marker bit for this packet.
    #[deprecated = "Use `marker_bit()` instead"]
    pub fn marker(self, marker: bool) -> Self {
        self.marker_bit(marker)
    }

    /// Set the marker bit for this packet.
    pub fn marker_bit(mut self, marker_bit: bool) -> Self {
        self.marker_bit = marker_bit;
        self
    }

    /// Set the payload type for this packet.
    pub fn payload_type(mut self, pt: u8) -> Self {
        self.payload_type = pt;
        self
    }

    /// Set the sequence number for this packet.
    pub fn sequence_number(mut self, sequence: u16) -> Self {
        self.sequence_number = sequence;
        self
    }

    /// Set the RTP timestamp for this packet.
    pub fn timestamp(mut self, timestamp: u32) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// Set the Sequence source for this packet.
    pub fn ssrc(mut self, ssrc: u32) -> Self {
        self.ssrc = ssrc;
        self
    }

    /// Set the extension header for this packet.
    pub fn extension(mut self, extension_id: u16, extension_data: E) -> Self {
        self.extension = Some((extension_id, extension_data));
        self
    }

    /// Clear any extension data configured for this packet.
    pub fn clear_extension(mut self) -> Self {
        self.extension = None;
        self
    }

    /// Add a chunk of payload data for this packet.
    ///
    /// Can be called multiple times, in which case the payload data chunks will be
    /// concatenated when the final packet is created.
    pub fn payload(mut self, payload: P) -> Self {
        self.payloads.push(payload);
        self
    }

    /// Clear any payloads currently configured.
    pub fn clear_payloads(mut self) -> Self {
        self.payloads.clear();
        self
    }

    /// Calculate the size required for writing the packet.
    pub fn calculate_size(&self) -> Result<usize, RtpWriteError> {
        let payload_len = self.payloads.iter().map(|p| p.len()).sum::<usize>();
        let extension_len = if let Some((_ext_id, ext_data)) = self.extension.as_ref() {
            if ext_data.len() % 4 != 0 {
                return Err(RtpWriteError::ExtensionDataNotPadded);
            }
            if ext_data.len() > u16::MAX as usize {
                return Err(RtpWriteError::PacketTooLarge);
            }
            4 + ext_data.len()
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

    fn write_header_into(&self, buf: &mut [u8]) -> usize {
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
        if self.marker_bit {
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

        RtpPacket::MIN_RTP_PACKET_LEN
    }

    fn write_preconditions(&self) -> Result<usize, RtpWriteError> {
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

        self.calculate_size()
    }

    /// Write this packet using writer without any validity checks.
    pub fn write_unchecked<O>(
        &self,
        writer: &mut impl RtpPacketWriter<Payload = P, Extension = E, Output = O>,
    ) -> O {
        let mut hdr = [0; RtpPacket::MIN_RTP_PACKET_LEN];
        self.write_header_into(&mut hdr);
        writer.push(hdr.as_ref());

        for csrc in self.csrcs.iter() {
            writer.push(csrc.to_be_bytes().as_ref());
        }

        if let Some((ext_id, ext_data)) = self.extension.as_ref() {
            writer.push(ext_id.to_be_bytes().as_ref());
            writer.push(((ext_data.len() / 4) as u16).to_be_bytes().as_ref());
            writer.push_extension(ext_data);
        }

        for payload in self.payloads.iter() {
            writer.push_payload(payload);
        }

        if let Some(padding) = self.padding {
            writer.padding(padding);
        }

        writer.finish()
    }

    /// Write the packet using writer.
    pub fn write<O>(
        &self,
        writer: &mut impl RtpPacketWriter<Payload = P, Extension = E, Output = O>,
    ) -> Result<O, RtpWriteError> {
        let len = self.write_preconditions()?;
        if let Some(max_size) = writer.max_size() {
            if max_size < len {
                return Err(RtpWriteError::OutputTooSmall(len));
            }
        }

        writer.reserve(len);
        Ok(self.write_unchecked(writer))
    }
}

impl RtpPacketBuilder<&[u8], &[u8]> {
    /// Write this packet into `buf` without any validity checks.  Returns the number of bytes
    /// written.
    pub fn write_into_unchecked(&self, buf: &mut [u8]) -> usize {
        let mut writer = RtpPacketWriterMutSlice::new(buf);
        self.write_unchecked(&mut writer)
    }

    /// Write this packet into `buf`.  On success returns the number of bytes written or an
    /// `RtpWriteError` on failure.
    pub fn write_into(&self, buf: &mut [u8]) -> Result<usize, RtpWriteError> {
        let mut writer = RtpPacketWriterMutSlice::new(buf);
        self.write(&mut writer)
    }

    /// Write this packet into `buf` without any validity checks.  The data will be appended to the
    /// end of the provide Vec.
    pub fn write_into_vec_unchecked(&self, buf: &mut Vec<u8>) {
        let mut writer = RtpPacketWriterMutVec::new(buf);
        self.write_unchecked(&mut writer)
    }

    /// Write this packet into `buf`.  The data will be appended to the end of the provide Vec.
    pub fn write_into_vec(&self, buf: &mut Vec<u8>) -> Result<(), RtpWriteError> {
        let mut writer = RtpPacketWriterMutVec::new(buf);
        self.write(&mut writer)
    }

    /// Write this packet into a newly generated `Vec<u8>` without any validity checks.
    pub fn write_vec_unchecked(&self) -> Vec<u8> {
        let mut writer = RtpPacketWriterVec::default();
        self.write_unchecked(&mut writer)
    }

    /// Write this packet into a newly generated `Vec<u8>`.
    pub fn write_vec(&self) -> Result<Vec<u8>, RtpWriteError> {
        let mut writer = RtpPacketWriterVec::default();
        self.write(&mut writer)
    }
}

/// Trait to provide the length of a piece of data in bytes.
pub trait PayloadLength {
    /// The length of the data in bytes.
    fn len(&self) -> usize;
    /// Whether the data contains any bytes.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Trait to write an RTP packet into and/or from custom data types.
pub trait RtpPacketWriter {
    /// The type of the output.
    type Output;
    /// The type of the RTP payload to be stored in the output packet.
    type Payload: PayloadLength;
    /// The type of the RTP extension data to be stored in the output packet:was.
    type Extension: PayloadLength;

    /// Reserve a number of bytes in the output.  Multiple calls are possible and provide the
    /// entire size to reserve.
    fn reserve(&mut self, _size: usize) {}

    /// Return the maximum size of the output.  If the output data is not bound to a fixed size,
    /// `None` should be returned.
    fn max_size(&self) -> Option<usize> {
        None
    }

    /// Provides data to append to the output.  May be called multiple times per packet.
    fn push(&mut self, data: &[u8]);

    /// Provides the extension data to add to the output.  The extension should be written as-is
    /// without any transformations.
    fn push_extension(&mut self, extension_data: &Self::Extension);

    /// Provides the payload data to add to the output.  The payload should be written as-is
    /// without any transformations.
    fn push_payload(&mut self, payload: &Self::Payload);

    /// Provides any padding value the builder was constructed with.  The padding value specifies
    /// the number of bytes of zeroes of padding at the end to write.  The last byte of padding
    /// must be set to the padding count.  e.g.
    ///
    /// `[..., 0, 0, 0, 4]`
    fn padding(&mut self, size: u8);

    /// Finishes and returns the built RTP packet.  The implementation should reset internal state
    /// so that a new packet can be created after `finish` is called.
    fn finish(&mut self) -> Self::Output;
}

impl<T> PayloadLength for &[T] {
    fn len(&self) -> usize {
        (self as &[T]).len()
    }
}

impl<T> PayloadLength for Vec<T> {
    fn len(&self) -> usize {
        (self as &Vec<T>).len()
    }
}

impl<T, const N: usize> PayloadLength for [T; N] {
    fn len(&self) -> usize {
        self.as_slice().len()
    }
}

impl<T, const N: usize> PayloadLength for &[T; N] {
    fn len(&self) -> usize {
        self.as_slice().len()
    }
}

/// An implementation of a [`RtpPacketWriter`] that appends to a `Vec<u8>`.
#[derive(Default, Debug)]
pub struct RtpPacketWriterVec<'a, 'b> {
    output: Vec<u8>,
    padding: Option<u8>,
    phantom: PhantomData<(&'a [u8], &'b [u8])>,
}

impl<'a, 'b> RtpPacketWriter for RtpPacketWriterVec<'a, 'b> {
    type Output = Vec<u8>;
    type Payload = &'a [u8];
    type Extension = &'b [u8];

    fn reserve(&mut self, size: usize) {
        if self.output.len() < size {
            self.output.reserve(size - self.output.len());
        }
    }

    fn push(&mut self, data: &[u8]) {
        self.output.extend_from_slice(data)
    }

    fn push_extension(&mut self, extension_data: &Self::Extension) {
        self.push(extension_data)
    }

    fn push_payload(&mut self, data: &Self::Payload) {
        self.push(data)
    }

    fn padding(&mut self, size: u8) {
        self.padding = Some(size);
    }

    fn finish(&mut self) -> Self::Output {
        let mut ret = vec![];
        if let Some(padding) = self.padding.take() {
            self.output
                .resize(self.output.len() + padding as usize - 1, 0);
            self.output.push(padding);
        }
        std::mem::swap(&mut ret, &mut self.output);
        ret
    }
}

/// An implementation of a [`RtpPacketWriter`] that writes to a `&mut [u8]`.  Each packet will be
/// written starting at the beginning of the provided slice.
#[derive(Default, Debug)]
pub struct RtpPacketWriterMutSlice<'a, 'b, 'c> {
    output: &'a mut [u8],
    padding: Option<u8>,
    write_i: usize,
    phantom: PhantomData<(&'b [u8], &'c [u8])>,
}

impl<'a> RtpPacketWriterMutSlice<'a, '_, '_> {
    /// Construct a new [`RtpPacketWriterMutSlice`] from the provided slice.
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            output: buf,
            padding: None,
            write_i: 0,
            phantom: PhantomData,
        }
    }
}

impl std::ops::Deref for RtpPacketWriterMutSlice<'_, '_, '_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.output
    }
}

impl std::ops::DerefMut for RtpPacketWriterMutSlice<'_, '_, '_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.output
    }
}

impl<'b, 'c> RtpPacketWriter for RtpPacketWriterMutSlice<'_, 'b, 'c> {
    type Output = usize;
    type Payload = &'b [u8];
    type Extension = &'c [u8];

    fn max_size(&self) -> Option<usize> {
        Some(self.output.len())
    }

    fn push(&mut self, data: &[u8]) {
        self.output[self.write_i..self.write_i + data.len()].copy_from_slice(data);
        self.write_i += data.len();
    }

    fn push_extension(&mut self, extension_data: &Self::Extension) {
        self.push(extension_data)
    }

    fn push_payload(&mut self, data: &Self::Payload) {
        self.push(data)
    }

    fn padding(&mut self, size: u8) {
        self.padding = Some(size);
    }

    fn finish(&mut self) -> Self::Output {
        if let Some(padding) = self.padding.take() {
            debug_assert!(padding > 0);
            self.output[self.write_i..self.write_i + padding as usize - 1].fill(0);
            self.write_i += padding as usize;
            self.output[self.write_i - 1] = padding;
        }
        let ret = self.write_i;
        self.write_i = 0;
        ret
    }
}

/// An implementation of a [`RtpPacketWriter`] that writes to a `&mut Vec<u8>`.  Each packet
/// written will be appended to the provide `Vec<u8>`.  You can `clear()` the vec in between packets
/// to have each packet written from the beginning of the vec.
#[derive(Debug)]
pub struct RtpPacketWriterMutVec<'a, 'b, 'c> {
    output: &'a mut Vec<u8>,
    padding: Option<u8>,
    phantom: PhantomData<(&'b [u8], &'c [u8])>,
}

impl<'a> RtpPacketWriterMutVec<'a, '_, '_> {
    /// Construct a new [`RtpPacketWriterMutVec`] from a provided mutable `Vec<u8>`.
    pub fn new(buf: &'a mut Vec<u8>) -> Self {
        Self {
            output: buf,
            padding: None,
            phantom: PhantomData,
        }
    }
}

impl std::ops::Deref for RtpPacketWriterMutVec<'_, '_, '_> {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        self.output
    }
}

impl std::ops::DerefMut for RtpPacketWriterMutVec<'_, '_, '_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.output
    }
}

impl<'b, 'c> RtpPacketWriter for RtpPacketWriterMutVec<'_, 'b, 'c> {
    type Output = ();
    type Payload = &'b [u8];
    type Extension = &'c [u8];

    fn push(&mut self, data: &[u8]) {
        self.output.extend(data);
    }

    fn push_extension(&mut self, extension_data: &Self::Extension) {
        self.push(extension_data)
    }

    fn push_payload(&mut self, data: &Self::Payload) {
        self.push(data)
    }

    fn padding(&mut self, size: u8) {
        self.padding = Some(size);
    }

    fn finish(&mut self) -> Self::Output {
        if let Some(padding) = self.padding.take() {
            self.output
                .extend(std::iter::repeat(0).take(padding as usize - 1));
            self.output.push(padding);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_length() {
        let data = [3; 9];
        let data2: [u8; _] = [];
        assert!(PayloadLength::is_empty(&data2));
        assert!(!PayloadLength::is_empty(&data));
        assert_eq!(PayloadLength::len(&data), 9);
        assert_eq!(PayloadLength::len(&&data), 9);
        assert_eq!(PayloadLength::len(&data.as_slice()), 9);
        assert_eq!(PayloadLength::len(&data.to_vec()), 9);
    }

    #[test]
    fn write_rtp_default() {
        let mut data = [0; 128];
        let mut vec = vec![];
        let mut vec2 = vec![];
        let builder = RtpPacketBuilder::new().payload_type(96);
        let size = builder.write_into(&mut data).unwrap();
        let buf = builder.write_vec().unwrap();
        let buf2 = builder.write_vec_unchecked();
        assert_eq!(buf, buf2);
        builder.write_into_vec(&mut vec).unwrap();
        builder.write_into_vec_unchecked(&mut vec2);
        assert_eq!(vec, vec2);
        drop(builder);
        let data = &data[..size];
        assert_eq!(size, buf.len());
        assert_eq!(size, vec.len());
        for data in [data, buf.as_ref(), vec.as_ref()] {
            println!("{data:?}");
            let rtp = RtpPacket::parse(data).unwrap();
            assert_eq!(rtp.version(), 2);
            assert_eq!(rtp.padding(), None);
            assert_eq!(rtp.n_csrcs(), 0);
            assert!(!rtp.marker_bit());
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
        let mut vec = vec![];
        let mut vec2 = vec![];
        let builder = RtpPacketBuilder::new()
            .payload_type(96)
            .marker_bit(true)
            .sequence_number(0x0102)
            .timestamp(0x03040506)
            .ssrc(0x0708090a)
            .add_csrc(0x0b0c0d0e);
        let size = builder.write_into(&mut data).unwrap();
        let buf = builder.write_vec().unwrap();
        let buf2 = builder.write_vec_unchecked();
        assert_eq!(buf, buf2);
        builder.write_into_vec(&mut vec).unwrap();
        builder.write_into_vec_unchecked(&mut vec2);
        assert_eq!(vec, vec2);
        drop(builder);
        let data = &data[..size];
        assert_eq!(size, buf.len());
        assert_eq!(size, vec.len());
        for data in [data, buf.as_ref(), vec.as_ref()] {
            println!("{data:?}");
            let rtp = RtpPacket::parse(data).unwrap();
            assert_eq!(rtp.version(), 2);
            assert_eq!(rtp.padding(), None);
            assert_eq!(rtp.n_csrcs(), 1);
            assert!(rtp.marker_bit());
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
        let mut vec = vec![];
        let mut vec2 = vec![];
        let builder = RtpPacketBuilder::new()
            .payload_type(96)
            .add_csrc(0x01020304)
            .add_csrc(0x05060708);
        let size = builder.write_into(&mut data).unwrap();
        let size2 = builder.write_into_unchecked(&mut data);
        assert_eq!(size, size2);
        let buf = builder.write_vec().unwrap();
        let buf2 = builder.write_vec_unchecked();
        assert_eq!(buf, buf2);
        builder.write_into_vec(&mut vec).unwrap();
        builder.write_into_vec_unchecked(&mut vec2);
        assert_eq!(vec, vec2);
        drop(builder);
        let data = &data[..size];
        assert_eq!(size, buf.len());
        assert_eq!(size, vec.len());
        for data in [data, buf.as_ref(), vec.as_ref()] {
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
        let mut vec = vec![];
        let mut vec2 = vec![];
        let payload_data = [1, 2, 3, 4, 5, 6, 7, 8];
        let more_payload_data = [9, 10, 11];
        let builder = RtpPacketBuilder::new()
            .payload_type(96)
            .payload(payload_data.as_ref())
            .payload(more_payload_data.as_ref())
            .payload(more_payload_data[0..1].as_ref());
        let size = builder.write_into(&mut data).unwrap();
        assert_eq!(size, 24);
        let buf = builder.write_vec().unwrap();
        let buf2 = builder.write_vec_unchecked();
        assert_eq!(buf, buf2);
        builder.write_into_vec(&mut vec).unwrap();
        builder.write_into_vec_unchecked(&mut vec2);
        assert_eq!(vec, vec2);
        drop(builder);
        let data = &data[..size];
        assert_eq!(size, buf.len());
        assert_eq!(size, vec.len());
        for data in [data, buf.as_ref(), vec.as_ref()] {
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
        let mut vec = vec![];
        let mut vec2 = vec![];
        let extension_data = [1, 2, 3, 4, 5, 6, 7, 8];
        let builder = RtpPacketBuilder::new()
            .payload_type(96)
            .marker_bit(true)
            .sequence_number(0x0102)
            .timestamp(0x03040506)
            .ssrc(0x0708090a)
            .add_csrc(0x0b0c0d0e)
            .extension(0x9876, extension_data.as_ref());
        let size = builder.write_into(&mut data).unwrap();
        let buf = builder.write_vec().unwrap();
        let buf2 = builder.write_vec_unchecked();
        assert_eq!(buf, buf2);
        builder.write_into_vec(&mut vec).unwrap();
        builder.write_into_vec_unchecked(&mut vec2);
        assert_eq!(vec, vec2);
        drop(builder);
        let data = &data[..size];
        assert_eq!(size, buf.len());
        assert_eq!(size, vec.len());
        for data in [data, buf.as_ref(), vec.as_ref()] {
            println!("{data:?}");
            let rtp = RtpPacket::parse(data).unwrap();
            assert_eq!(rtp.version(), 2);
            assert_eq!(rtp.padding(), None);
            assert_eq!(rtp.n_csrcs(), 1);
            assert!(rtp.marker_bit());
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
    fn write_rtp_extension_clear() {
        let mut data = [0; 128];
        let mut vec = vec![];
        let mut vec2 = vec![];
        let extension_data = [1, 2, 3, 4, 5, 6, 7, 8];
        let builder = RtpPacketBuilder::new()
            .payload_type(96)
            .marker_bit(true)
            .sequence_number(0x0102)
            .timestamp(0x03040506)
            .ssrc(0x0708090a)
            .add_csrc(0x0b0c0d0e)
            .extension(0x9876, extension_data.as_ref())
            .clear_extension();
        let size = builder.write_into(&mut data).unwrap();
        let buf = builder.write_vec().unwrap();
        let buf2 = builder.write_vec_unchecked();
        assert_eq!(buf, buf2);
        builder.write_into_vec(&mut vec).unwrap();
        builder.write_into_vec_unchecked(&mut vec2);
        assert_eq!(vec, vec2);
        drop(builder);
        let data = &data[..size];
        assert_eq!(size, buf.len());
        assert_eq!(size, vec.len());
        for data in [data, buf.as_ref(), vec.as_ref()] {
            println!("{data:?}");
            let rtp = RtpPacket::parse(data).unwrap();
            assert_eq!(rtp.version(), 2);
            assert_eq!(rtp.padding(), None);
            assert_eq!(rtp.n_csrcs(), 1);
            assert!(rtp.marker_bit());
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
    fn write_rtp_extension_payload_padding() {
        let mut data = [0; 128];
        let mut vec = vec![];
        let mut vec2 = vec![];
        let extension_data = [1, 2, 3, 4, 5, 6, 7, 8];
        let payload_data = [1, 2, 3, 4, 5, 6, 7, 8];
        let builder = RtpPacketBuilder::new()
            .payload_type(96)
            .marker_bit(true)
            .sequence_number(0x0102)
            .timestamp(0x03040506)
            .ssrc(0x0708090a)
            .add_csrc(0x0b0c0d0e)
            .extension(0x9876, extension_data.as_ref())
            .payload(payload_data.as_ref())
            .padding(7);
        let size = builder.write_into(&mut data).unwrap();
        let buf = builder.write_vec().unwrap();
        let buf2 = builder.write_vec_unchecked();
        assert_eq!(buf, buf2);
        builder.write_into_vec(&mut vec).unwrap();
        builder.write_into_vec_unchecked(&mut vec2);
        assert_eq!(vec, vec2);
        drop(builder);
        let data = &data[..size];
        assert_eq!(size, buf.len());
        assert_eq!(size, vec.len());
        for data in [data, buf.as_ref(), vec.as_ref()] {
            println!("{data:?}");
            let rtp = RtpPacket::parse(data).unwrap();
            assert_eq!(rtp.version(), 2);
            assert_eq!(rtp.padding(), Some(7));
            assert_eq!(rtp.n_csrcs(), 1);
            assert!(rtp.marker_bit());
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
    fn write_rtp_extension_payload_maybe_padding() {
        let mut data = [0; 128];
        let mut vec = vec![];
        let mut vec2 = vec![];
        let builder = RtpPacketBuilder::new()
            .payload_type(96)
            .marker_bit(true)
            .sequence_number(0x0102)
            .timestamp(0x03040506)
            .ssrc(0x0708090a)
            .add_csrc(0x0b0c0d0e)
            .maybe_padding(Some(7));
        let size = builder.write_into(&mut data).unwrap();
        let buf = builder.write_vec().unwrap();
        let buf2 = builder.write_vec_unchecked();
        assert_eq!(buf, buf2);
        builder.write_into_vec(&mut vec).unwrap();
        builder.write_into_vec_unchecked(&mut vec2);
        assert_eq!(vec, vec2);
        drop(builder);
        let data = &data[..size];
        assert_eq!(size, buf.len());
        assert_eq!(size, vec.len());
        for data in [data, buf.as_ref(), vec.as_ref()] {
            println!("{data:?}");
            let rtp = RtpPacket::parse(data).unwrap();
            assert_eq!(rtp.version(), 2);
            assert_eq!(rtp.padding(), Some(7));
            assert_eq!(rtp.n_csrcs(), 1);
            assert!(rtp.marker_bit());
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
    fn write_rtp_invalid_padding() {
        let mut data = [0; 128];
        let mut vec = vec![];
        let builder = RtpPacketBuilder::new().payload_type(96).padding(0);
        assert_eq!(
            builder.write_into(&mut data),
            Err(RtpWriteError::InvalidPadding)
        );
        assert_eq!(builder.write_vec(), Err(RtpWriteError::InvalidPadding));
        assert_eq!(
            builder.write_into_vec(&mut vec),
            Err(RtpWriteError::InvalidPadding)
        );
    }

    #[test]
    fn write_rtp_unpadded_extension() {
        let mut data = [0; 128];
        let mut vec = vec![];
        let builder = RtpPacketBuilder::new()
            .payload_type(96)
            .extension(0x9876, [1].as_ref());
        assert_eq!(
            builder.write_into(&mut data),
            Err(RtpWriteError::ExtensionDataNotPadded)
        );
        assert_eq!(
            builder.write_vec(),
            Err(RtpWriteError::ExtensionDataNotPadded)
        );
        assert_eq!(
            builder.write_into_vec(&mut vec),
            Err(RtpWriteError::ExtensionDataNotPadded)
        );
    }

    #[test]
    fn write_rtp_invalid_payload_type() {
        let mut data = [0; 128];
        let mut vec = vec![];
        let builder = RtpPacketBuilder::new().payload_type(0xFF);
        assert_eq!(
            builder.write_into(&mut data),
            Err(RtpWriteError::InvalidPayloadType(0xFF))
        );
        assert_eq!(
            builder.write_vec(),
            Err(RtpWriteError::InvalidPayloadType(0xFF))
        );
        assert_eq!(
            builder.write_into_vec(&mut vec),
            Err(RtpWriteError::InvalidPayloadType(0xFF))
        );
    }

    #[test]
    fn write_rtp_too_many_contributions() {
        let mut data = [0; 128];
        let mut vec = vec![];
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
            builder.write_into(&mut data),
            Err(RtpWriteError::TooManyContributionSources(16))
        );
        assert_eq!(
            builder.write_vec(),
            Err(RtpWriteError::TooManyContributionSources(16))
        );
        assert_eq!(
            builder.write_into_vec(&mut vec),
            Err(RtpWriteError::TooManyContributionSources(16))
        );
    }

    #[test]
    fn write_rtp_extension_too_large() {
        let mut data = [0; u16::MAX as usize + 128];
        let mut vec = vec![];
        let extension_data = [0; u16::MAX as usize + 1];
        let builder = RtpPacketBuilder::new()
            .payload_type(96)
            .extension(0x9876, extension_data.as_ref());
        assert_eq!(
            builder.write_into(&mut data),
            Err(RtpWriteError::PacketTooLarge)
        );
        assert_eq!(builder.write_vec(), Err(RtpWriteError::PacketTooLarge));
        assert_eq!(
            builder.write_into_vec(&mut vec),
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
                .extension(0x9876, [].as_ref())
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
                .payload([1].as_ref())
                .write_into(&mut data),
            Err(RtpWriteError::OutputTooSmall(13))
        );
    }

    #[derive(Debug)]
    struct TestPayload(Vec<u8>);

    impl PayloadLength for TestPayload {
        fn len(&self) -> usize {
            self.0.len()
        }
    }

    #[derive(Default, Debug)]
    struct TestRtpWriterCustomPayload {
        output: Option<Vec<u8>>,
        padding: Option<u8>,
        max_size: usize,
    }

    impl RtpPacketWriter for TestRtpWriterCustomPayload {
        type Output = Vec<u8>;
        type Payload = TestPayload;
        type Extension = TestPayload;

        fn reserve(&mut self, size: usize) {
            if let Some(output) = self.output.as_mut() {
                if output.len() < size {
                    output.reserve(size - output.len());
                }
            } else {
                self.output = Some(Vec::with_capacity(size));
            }
        }

        fn push(&mut self, data: &[u8]) {
            let p = self
                .output
                .get_or_insert_with(|| Vec::with_capacity(data.len()));
            println!(
                "push {} bytes at offset {}, max_size {}",
                data.len(),
                p.len(),
                self.max_size
            );
            assert!(p.len() + data.len() <= self.max_size);
            p.extend_from_slice(data)
        }

        fn push_payload(&mut self, payload: &Self::Payload) {
            self.push(&payload.0)
        }

        fn push_extension(&mut self, extension_data: &Self::Extension) {
            self.push(&extension_data.0)
        }

        fn padding(&mut self, size: u8) {
            self.padding = Some(size);
        }

        fn finish(&mut self) -> Self::Output {
            self.output
                .take()
                .map(|mut output| {
                    if let Some(padding) = self.padding.take() {
                        output.extend(std::iter::repeat(0).take(padding as usize - 1));
                        output.push(padding);
                    }
                    output
                })
                .unwrap_or_default()
        }
    }

    #[test]
    fn write_rtp_custom_payload() {
        let extension_data = TestPayload(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let payload_data = TestPayload(vec![11, 12, 13, 14, 15, 16, 17, 18]);
        let builder = RtpPacketBuilder::new()
            .payload_type(96)
            .marker_bit(true)
            .sequence_number(0x0102)
            .timestamp(0x03040506)
            .ssrc(0x0708090a)
            .add_csrc(0x0b0c0d0e)
            .extension(0x9876, TestPayload(extension_data.0.clone()))
            .payload(TestPayload(payload_data.0.clone()))
            .padding(1);
        let max_size = builder.calculate_size().unwrap();
        let mut writer = TestRtpWriterCustomPayload {
            max_size,
            ..Default::default()
        };
        let buf = builder.write(&mut writer).unwrap();
        drop(builder);
        let data = buf.as_ref();
        println!("{data:?}");
        let rtp = RtpPacket::parse(data).unwrap();
        assert_eq!(rtp.version(), 2);
        assert_eq!(rtp.padding(), Some(1));
        assert_eq!(rtp.n_csrcs(), 1);
        assert!(rtp.marker_bit());
        assert_eq!(rtp.payload_type(), 96);
        assert_eq!(rtp.sequence_number(), 0x0102);
        assert_eq!(rtp.timestamp(), 0x03040506);
        assert_eq!(rtp.ssrc(), 0x0708090a);
        let mut csrc = rtp.csrc();
        assert_eq!(csrc.next(), Some(0x0b0c0d0e));
        assert_eq!(csrc.next(), None);
        let (ext_id, ext_data) = rtp.extension().unwrap();
        assert_eq!(ext_id, 0x9876);
        assert_eq!(ext_data, extension_data.0);
        assert_eq!(rtp.payload(), payload_data.0);
    }

    #[test]
    fn write_rtp_vec_with_clear() {
        let mut vec = vec![];
        let payload_data = [1, 2, 3, 4, 5, 6, 7, 8];
        let builder = RtpPacketBuilder::new()
            .payload_type(96)
            .payload(payload_data.as_ref());
        let mut writer = RtpPacketWriterMutVec::new(&mut vec);
        builder.write(&mut writer).unwrap();
        assert_eq!(writer.len(), 20);
        let data = writer.as_ref();
        println!("{data:?}");
        let rtp = RtpPacket::parse(data).unwrap();
        assert_eq!(rtp.version(), 2);
        assert_eq!(rtp.payload_type(), 96);
        assert_eq!(rtp.payload(), payload_data);
        writer.clear();
        let payload2 = [9, 10, 11];
        let builder = builder.clear_payloads().payload(payload2.as_ref());
        builder.write(&mut writer).unwrap();
        assert_eq!(writer.len(), 15);
        let data = writer.as_ref();
        println!("{data:?}");
        let rtp = RtpPacket::parse(data).unwrap();
        assert_eq!(rtp.version(), 2);
        assert_eq!(rtp.payload_type(), 96);
        assert_eq!(rtp.payload(), payload2);
    }
}
