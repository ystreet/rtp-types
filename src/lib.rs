// SPDX-License-Identifier: MIT OR Apache-2.0

#![deny(missing_debug_implementations)]
#![deny(missing_docs)]

//! # rtp-types
//!
//! An implementation of parsing, writing, and editing RTP packets as specified in [RFC 3550]
//!
//! [RFC 3550]: https://tools.ietf.org/html/rfc3550

mod builder;
mod edit;
pub mod extension;
mod packet;

pub use builder::{
    RtpPacketBuilder, RtpPacketWriterMutSlice, RtpPacketWriterMutVec, RtpPacketWriterVec,
    RtpWriteError,
};
pub use edit::RtpPacketMut;
pub use extension::one::{RtpSingleByteExtension, RtpSingleByteExtensionBuilder};
pub use extension::two::{RtpTwoByteExtension, RtpTwoByteExtensionBuilder};
pub use extension::{RtpExtension, RtpExtensionWrite, RtpExtensionsBlock, RtpExtensionsBlockWrite};
pub use packet::{RtpPacket, RtpParseError};

/// Prelude module for defined/implementable traits
pub mod prelude {
    pub use crate::builder::{PayloadLength, RtpPacketWriter};
    pub use crate::extension::{
        RtpExtension, RtpExtensionWrite, RtpExtensionsBlock, RtpExtensionsBlockWrite,
    };
}
