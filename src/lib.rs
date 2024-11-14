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
mod packet;

pub use builder::{
    RtpPacketBuilder, RtpPacketWriterMutSlice, RtpPacketWriterMutVec, RtpPacketWriterVec,
    RtpWriteError,
};
pub use edit::RtpPacketMut;
pub use packet::{RtpPacket, RtpParseError};

/// Prelude module for defined/implementable traits
pub mod prelude {
    pub use crate::builder::{PayloadLength, RtpPacketWriter};
}
