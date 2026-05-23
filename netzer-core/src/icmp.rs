use crate::error::ParseError;

pub const ICMP_HEADER_LEN: usize = 8;

pub struct IcmpHeader<'a> {
    buffer: &'a [u8],
}

impl<'a> IcmpHeader<'a> {
    pub fn parse(buffer: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        if buffer.len() < ICMP_HEADER_LEN {
            return Err(ParseError::BufferTooShort);
        }

        let header = Self {
            buffer: &buffer[..ICMP_HEADER_LEN],
        };
        let payload = &buffer[ICMP_HEADER_LEN..];

        Ok((header, payload))
    }

    pub fn icmp_type(&self) -> u8 {
        self.buffer[0]
    }

    pub fn code(&self) -> u8 {
        self.buffer[1]
    }
}
