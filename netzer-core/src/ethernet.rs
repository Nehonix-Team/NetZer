use crate::error::ParseError;
use crate::mac::MacAddress;

pub const ETHERNET_HEADER_LEN: usize = 14;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtherType {
    Ipv4,
    Ipv6,
    Arp,
    Other(u16),
}

impl From<u16> for EtherType {
    fn from(val: u16) -> Self {
        match val {
            0x0800 => EtherType::Ipv4,
            0x0806 => EtherType::Arp,
            0x86DD => EtherType::Ipv6,
            other => EtherType::Other(other),
        }
    }
}

pub struct EthernetFrame<'a> {
    buffer: &'a [u8],
}

impl<'a> EthernetFrame<'a> {
    /// Parses an Ethernet II frame from a byte slice.
    /// Returns the parsed frame and a slice containing the remaining payload.
    pub fn parse(buffer: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        if buffer.len() < ETHERNET_HEADER_LEN {
            return Err(ParseError::BufferTooShort);
        }
        
        let frame = Self {
            buffer: &buffer[..ETHERNET_HEADER_LEN],
        };
        
        let payload = &buffer[ETHERNET_HEADER_LEN..];
        
        Ok((frame, payload))
    }

    pub fn destination(&self) -> MacAddress {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&self.buffer[0..6]);
        MacAddress(mac)
    }

    pub fn source(&self) -> MacAddress {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&self.buffer[6..12]);
        MacAddress(mac)
    }

    pub fn ethertype(&self) -> EtherType {
        let mut bytes = [0u8; 2];
        bytes.copy_from_slice(&self.buffer[12..14]);
        EtherType::from(u16::from_be_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethernet_parse_success() {
        // Dummy Ethernet frame (14 bytes) + 4 bytes payload
        // Dest MAC: 00:11:22:33:44:55
        // Src MAC:  aa:bb:cc:dd:ee:ff
        // EtherType: 0x0800 (IPv4)
        // Payload: 0xde, 0xad, 0xbe, 0xef
        let data: [u8; 18] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0x08, 0x00,
            0xde, 0xad, 0xbe, 0xef,
        ];

        let (frame, payload) = EthernetFrame::parse(&data).expect("Parsing failed");
        
        assert_eq!(frame.destination(), MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
        assert_eq!(frame.source(), MacAddress([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
        assert_eq!(frame.ethertype(), EtherType::Ipv4);
        assert_eq!(payload, &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_ethernet_parse_too_short() {
        let data: [u8; 10] = [0; 10]; // Too short for a 14-byte header
        let result = EthernetFrame::parse(&data);
        assert_eq!(result.err(), Some(ParseError::BufferTooShort));
    }
}
