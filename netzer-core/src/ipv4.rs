use crate::error::ParseError;
use std::fmt;

pub const IPV4_HEADER_MIN_LEN: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Address(pub [u8; 4]);

impl fmt::Display for Ipv4Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

pub struct Ipv4Header<'a> {
    buffer: &'a [u8],
}

impl<'a> Ipv4Header<'a> {
    pub fn parse(buffer: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        if buffer.len() < IPV4_HEADER_MIN_LEN {
            return Err(ParseError::BufferTooShort);
        }
        
        // IHL (Internet Header Length) is the lower 4 bits of the first byte
        let ihl = (buffer[0] & 0x0F) as usize;
        let header_len = ihl * 4;
        
        if buffer.len() < header_len || header_len < IPV4_HEADER_MIN_LEN {
            return Err(ParseError::InvalidFormat);
        }
        
        let header = Self {
            buffer: &buffer[..header_len],
        };
        let payload = &buffer[header_len..];
        
        Ok((header, payload))
    }

    pub fn source(&self) -> Ipv4Address {
        let mut ip = [0u8; 4];
        ip.copy_from_slice(&self.buffer[12..16]);
        Ipv4Address(ip)
    }

    pub fn destination(&self) -> Ipv4Address {
        let mut ip = [0u8; 4];
        ip.copy_from_slice(&self.buffer[16..20]);
        Ipv4Address(ip)
    }

    pub fn protocol(&self) -> u8 {
        self.buffer[9] // IPv4 Protocol field is at offset 9
    }
}
