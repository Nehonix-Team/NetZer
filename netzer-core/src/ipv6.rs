use crate::error::ParseError;
use std::fmt;

pub const IPV6_HEADER_LEN: usize = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Address(pub [u8; 16]);

impl fmt::Display for Ipv6Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3],
            self.0[4], self.0[5], self.0[6], self.0[7],
            self.0[8], self.0[9], self.0[10], self.0[11],
            self.0[12], self.0[13], self.0[14], self.0[15]
        )
    }
}

pub struct Ipv6Header<'a> {
    buffer: &'a [u8],
}

impl<'a> Ipv6Header<'a> {
    pub fn parse(buffer: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        if buffer.len() < IPV6_HEADER_LEN {
            return Err(ParseError::BufferTooShort);
        }

        let header = Self {
            buffer: &buffer[..IPV6_HEADER_LEN],
        };
        let payload = &buffer[IPV6_HEADER_LEN..];

        Ok((header, payload))
    }

    pub fn source(&self) -> Ipv6Address {
        let mut ip = [0u8; 16];
        ip.copy_from_slice(&self.buffer[8..24]);
        Ipv6Address(ip)
    }

    pub fn destination(&self) -> Ipv6Address {
        let mut ip = [0u8; 16];
        ip.copy_from_slice(&self.buffer[24..40]);
        Ipv6Address(ip)
    }

    pub fn next_header(&self) -> u8 {
        self.buffer[6]
    }
}
