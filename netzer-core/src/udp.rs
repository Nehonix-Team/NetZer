use crate::error::ParseError;

pub const UDP_HEADER_LEN: usize = 8;

pub struct UdpHeader<'a> {
    buffer: &'a [u8],
}

impl<'a> UdpHeader<'a> {
    pub fn parse(buffer: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        if buffer.len() < UDP_HEADER_LEN {
            return Err(ParseError::BufferTooShort);
        }
        
        let header = Self {
            buffer: &buffer[..UDP_HEADER_LEN],
        };
        let payload = &buffer[UDP_HEADER_LEN..];
        
        Ok((header, payload))
    }

    pub fn source_port(&self) -> u16 {
        let mut bytes = [0u8; 2];
        bytes.copy_from_slice(&self.buffer[0..2]);
        u16::from_be_bytes(bytes)
    }

    pub fn destination_port(&self) -> u16 {
        let mut bytes = [0u8; 2];
        bytes.copy_from_slice(&self.buffer[2..4]);
        u16::from_be_bytes(bytes)
    }
}
