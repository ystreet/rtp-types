// SPDX-License-Identifier: MIT OR Apache-2.0

#![deny(missing_debug_implementations)]

mod builder;
mod edit;
mod packet;

pub use builder::{
    RtpPacketBuilder, RtpPacketWriterMutSlice, RtpPacketWriterMutVec, RtpPacketWriterVec,
    RtpWriteError,
};
pub use edit::RtpPacketMut;
pub use packet::{RtpPacket, RtpParseError};

pub mod prelude {
    pub use crate::builder::{PayloadLength, RtpPacketWriter};
}
