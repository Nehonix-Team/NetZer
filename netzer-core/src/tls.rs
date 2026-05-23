use crate::error::ParseError;

pub struct TlsClientHello<'a> {
    pub sni: &'a str,
}

impl<'a> TlsClientHello<'a> {
    pub fn parse(buffer: &'a [u8]) -> Result<Self, ParseError> {
        // Minimum TLS record size
        if buffer.len() < 5 {
            return Err(ParseError::BufferTooShort);
        }

        // Content Type: Handshake (22)
        if buffer[0] != 22 {
            return Err(ParseError::InvalidFormat);
        }

        // Check TLS record length
        let record_len = ((buffer[3] as usize) << 8) | (buffer[4] as usize);
        if buffer.len() < 5 + record_len {
            return Err(ParseError::BufferTooShort);
        }

        let mut offset = 5;

        // Handshake Type: ClientHello (1)
        if buffer[offset] != 1 {
            return Err(ParseError::InvalidFormat);
        }
        
        // Handshake Length (3 bytes)
        offset += 4;
        
        // Client Version (2 bytes)
        offset += 2;
        
        // Random (32 bytes)
        offset += 32;
        
        if offset >= buffer.len() {
            return Err(ParseError::BufferTooShort);
        }
        
        // Session ID length
        let session_id_len = buffer[offset] as usize;
        offset += 1 + session_id_len;
        
        if offset + 2 > buffer.len() {
            return Err(ParseError::BufferTooShort);
        }
        
        // Cipher Suites length
        let cipher_suites_len = ((buffer[offset] as usize) << 8) | (buffer[offset+1] as usize);
        offset += 2 + cipher_suites_len;
        
        if offset + 1 > buffer.len() {
            return Err(ParseError::BufferTooShort);
        }
        
        // Compression Methods length
        let compression_methods_len = buffer[offset] as usize;
        offset += 1 + compression_methods_len;
        
        if offset + 2 > buffer.len() {
            return Err(ParseError::InvalidFormat); // Extensions are optional
        }
        
        // Extensions length
        let extensions_len = ((buffer[offset] as usize) << 8) | (buffer[offset+1] as usize);
        offset += 2;
        
        let extensions_end = offset + extensions_len;
        if extensions_end > buffer.len() {
            return Err(ParseError::BufferTooShort);
        }
        
        // Parse Extensions to find SNI (Type 0)
        while offset + 4 <= extensions_end {
            let ext_type = ((buffer[offset] as usize) << 8) | (buffer[offset+1] as usize);
            let ext_len = ((buffer[offset+2] as usize) << 8) | (buffer[offset+3] as usize);
            offset += 4;
            
            if offset + ext_len > extensions_end {
                return Err(ParseError::BufferTooShort);
            }
            
            if ext_type == 0 { // SNI
                // SNI List Length (2 bytes)
                if ext_len < 2 {
                    return Err(ParseError::InvalidFormat);
                }
                let mut sni_offset = offset + 2;
                let sni_end = offset + ext_len;
                
                while sni_offset + 3 <= sni_end {
                    let name_type = buffer[sni_offset];
                    let name_len = ((buffer[sni_offset+1] as usize) << 8) | (buffer[sni_offset+2] as usize);
                    sni_offset += 3;
                    
                    if sni_offset + name_len > sni_end {
                        return Err(ParseError::BufferTooShort);
                    }
                    
                    if name_type == 0 { // Host_name
                        let hostname_bytes = &buffer[sni_offset..sni_offset+name_len];
                        if let Ok(hostname) = std::str::from_utf8(hostname_bytes) {
                            return Ok(Self { sni: hostname });
                        } else {
                            return Err(ParseError::InvalidFormat);
                        }
                    }
                    sni_offset += name_len;
                }
            }
            
            offset += ext_len;
        }
        
        Err(ParseError::InvalidFormat) // SNI not found
    }
}
