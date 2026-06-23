// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{RtpExtension, RtpExtensionWrite, RtpParseError};

/// The Media Idenficiation tag as specified in [RFC 8843]
///
/// An implementation of parsing, writing, and editing The BUNDLE Media Identification tag as specified in [RFC 8843]
///
/// [RFC 8843]: https://tools.ietf.org/html/rfc8843
#[derive(Debug, Clone)]
pub struct Mid {
    mid: String,
}

impl Mid {
    /// Create a new Media Identification tag
    pub fn new(mid: String) -> Self {
        Self { mid }
    }

    /// The Media Identification tag.
    pub fn mid(&self) -> &str {
        &self.mid
    }
}

impl RtpExtension<'_> for Mid {
    const URI: &'static str = "urn:ietf:params:rtp-hdrext:sdes:mid";

    fn parse(data: &'_ [u8]) -> Result<Self, RtpParseError>
    where
        Self: core::marker::Sized,
    {
        let mid = core::str::from_utf8(data).map_err(|_| RtpParseError::InvalidData)?;
        Ok(Self {
            mid: mid.to_string(),
        })
    }
}

impl RtpExtensionWrite for Mid {
    fn uri(&self) -> &str {
        "urn:ietf:params:rtp-hdrext:sdes:mid"
    }

    fn byte_len(&self) -> usize {
        self.mid.len()
    }

    fn write_into(&self, bytes: &mut [u8]) -> usize {
        let len = self.byte_len();
        bytes[..len].copy_from_slice(self.mid.as_bytes());
        len
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid() {
        let data = [0x20];
        let ext = Mid::parse(&data).unwrap();
        assert_eq!(ext.mid(), " ");
        let mut new_data = [0; 16];
        assert_eq!(ext.write_into(&mut new_data), 1);
        assert_eq!(&new_data[..1], &data);
    }

    #[test]
    fn write() {
        let ext = Mid::new("a".to_string());
        assert_eq!(ext.mid(), "a");
        let mut new_data = [0; 16];
        assert_eq!(ext.write_into(&mut new_data), 1);
        assert_eq!(&new_data[..1], b"a");
    }
}
