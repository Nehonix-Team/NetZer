use crate::error::ParseError;

pub struct DnsQuery {
    pub domain_name: String,
}

impl DnsQuery {
    pub fn parse(buffer: &[u8]) -> Result<Self, ParseError> {
        if buffer.len() < 12 {
            return Err(ParseError::BufferTooShort);
        }
        
        // Ensure it is a query (QR bit = 0)
        if (buffer[2] & 0x80) != 0 {
            return Err(ParseError::InvalidFormat); // It's a response
        }
        
        // Extract number of questions
        let mut qdcount_bytes = [0u8; 2];
        qdcount_bytes.copy_from_slice(&buffer[4..6]);
        let qdcount = u16::from_be_bytes(qdcount_bytes);
        
        if qdcount == 0 {
            return Err(ParseError::InvalidFormat);
        }
        
        let mut offset = 12; // Skip DNS header
        let mut domain = String::new();
        
        // Parse the first question QNAME
        while offset < buffer.len() {
            let length = buffer[offset] as usize;
            if length == 0 {
                break; // End of QNAME
            }
            
            // Pointer? (Not supported in this basic simple parser)
            if (length & 0xC0) == 0xC0 {
                return Err(ParseError::InvalidFormat);
            }
            
            offset += 1;
            if offset + length >= buffer.len() {
                return Err(ParseError::BufferTooShort);
            }
            
            if !domain.is_empty() {
                domain.push('.');
            }
            
            let label = std::str::from_utf8(&buffer[offset..offset+length]).map_err(|_| ParseError::InvalidFormat)?;
            domain.push_str(label);
            
            offset += length;
        }
        
        if domain.is_empty() {
            return Err(ParseError::InvalidFormat);
        }
        
        Ok(Self {
            domain_name: domain,
        })
    }
}
