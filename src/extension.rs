// SPDX-License-Identifier: MIT OR Apache-2.0

//! # RTP Header extensions
//!
//! An implementation of parsing, writing, and editing RTP header extensions as specified in [RFC 8285]
//!
//! [RFC 8285]: https://tools.ietf.org/html/rfc8285

use crate::{builder::RtpPacketWriter, RtpParseError};

mod mid;
pub(crate) mod one;
pub(crate) mod two;

pub use mid::Mid;

/// Extension trait for parsing a byte sequence into a concrete extension block.
pub trait RtpExtensionsBlock<'a> {
    /// Parse the provided extension id and bytes into a concrete type.
    ///
    /// The ID is 'defined by the RTP profile'.
    fn parse(id: u16, data: &'a [u8]) -> Result<Self, RtpParseError>
    where
        Self: core::marker::Sized;
}

/// Serialize an extension block (container format) back to wire bytes.
pub trait RtpExtensionsBlockWrite {
    /// The profile-defined extension ID for this block format.
    fn extension_id(&self) -> u16;

    /// The number of bytes used by this extension not including the 4 byte extension header.
    fn byte_len(&self) -> usize;

    /// Write the extension data using the writer.
    fn write<P, O>(&self, writer: &mut impl RtpPacketWriter<Payload = P, Output = O>);
}

/// An unparsed RTP extension block as stored in a RTP packet.
#[derive(Debug, PartialEq, Eq)]
pub struct ExtensionBlock<'a> {
    ext_id: u16,
    data: &'a [u8],
}

impl<'a> ExtensionBlock<'a> {
    /// The extension data.
    pub fn data(&self) -> &[u8] {
        self.data
    }

    /// Try to parse this extension data as a more concrete implementation.
    pub fn try_as<E: RtpExtensionsBlock<'a>>(&self) -> Result<E, RtpParseError> {
        E::parse(self.ext_id, self.data)
    }
}

impl<'a> RtpExtensionsBlock<'a> for ExtensionBlock<'a> {
    fn parse(id: u16, data: &'a [u8]) -> Result<Self, RtpParseError>
    where
        Self: core::marker::Sized,
    {
        Ok(Self { ext_id: id, data })
    }
}

impl RtpExtensionsBlockWrite for ExtensionBlock<'_> {
    fn extension_id(&self) -> u16 {
        self.ext_id
    }
    fn write<P, O>(&self, writer: &mut impl RtpPacketWriter<Payload = P, Output = O>) {
        writer.push(self.data);
    }

    fn byte_len(&self) -> usize {
        self.data.len()
    }
}

/// Errors produced when adding an extension
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RtpExtensionWriteError {
    /// The extension ID is not within the allowed range.
    #[error("Extension Id ({}) is not within the allowd range[{}, {}]", .id, .range.start, .range.end)]
    IdOutOfRange {
        /// ID that is out of range.
        id: usize,
        /// Allowed range.
        range: core::ops::Range<usize>,
    },
    /// The extension length is not within the allowed range.
    #[error("Extension length ({}) is not within the allowd range[{}, {}]", .len, .range.start, .range.end)]
    LengthOutOfRange {
        /// Length that is out of range.
        len: usize,
        /// Allowed range.
        range: core::ops::Range<usize>,
    },
}

/// Extension trait for parsing a byte sequence into a concrete extension.
pub trait RtpExtension<'a> {
    /// The unique URI for this extension implementation.
    const URI: &'static str;

    /// Parse the provided network bytes into a concrete extension.
    fn parse(data: &'a [u8]) -> Result<Self, RtpParseError>
    where
        Self: core::marker::Sized;
}

/// Serialize an individual sub-extension into network bytes.
pub trait RtpExtensionWrite: core::fmt::Debug {
    /// The unique URI identifying this extension type.
    fn uri(&self) -> &str;

    /// The number of bytes used by this extension not including any headers.
    fn byte_len(&self) -> usize;

    /// Write the extension data into the provided bytes.
    fn write_into(&self, bytes: &mut [u8]) -> usize;
}
