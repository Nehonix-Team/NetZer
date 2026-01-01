use crate::error::ParseError;

pub const TCP_HEADER_MIN_LEN: usize = 20;

pub struct TcpHeader<'a> {
    buffer: &'a [u8],
}

impl<'a> TcpHeader<'a> {
    pub fn parse(buffer: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        if buffer.len() < TCP_HEADER_MIN_LEN {
            return Err(ParseError::BufferTooShort);
        }
        
        // Data offset is the upper 4 bits of byte 12
        let data_offset = (buffer[12] >> 4) as usize;
        let header_len = data_offset * 4;
        
        if buffer.len() < header_len || header_len < TCP_HEADER_MIN_LEN {
            return Err(ParseError::InvalidFormat);
        }
        
        let header = Self {
            buffer: &buffer[..header_len],
        };
        let payload = &buffer[header_len..];
        
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
