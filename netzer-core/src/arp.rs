use crate::error::ParseError;
use crate::mac::MacAddress;
use crate::ipv4::Ipv4Address;

pub const ARP_HEADER_LEN: usize = 28;

pub struct ArpPacket<'a> {
    buffer: &'a [u8],
}

impl<'a> ArpPacket<'a> {
    pub fn parse(buffer: &'a [u8]) -> Result<Self, ParseError> {
        if buffer.len() < ARP_HEADER_LEN {
            return Err(ParseError::BufferTooShort);
        }
        Ok(Self {
            buffer: &buffer[..ARP_HEADER_LEN],
        })
    }

    pub fn hardware_type(&self) -> u16 {
        let mut bytes = [0u8; 2];
        bytes.copy_from_slice(&self.buffer[0..2]);
        u16::from_be_bytes(bytes)
    }

    pub fn protocol_type(&self) -> u16 {
        let mut bytes = [0u8; 2];
        bytes.copy_from_slice(&self.buffer[2..4]);
        u16::from_be_bytes(bytes)
    }

    pub fn opcode(&self) -> u16 {
        let mut bytes = [0u8; 2];
        bytes.copy_from_slice(&self.buffer[6..8]);
        u16::from_be_bytes(bytes)
    }

    pub fn sender_mac(&self) -> MacAddress {
        let mut bytes = [0u8; 6];
        bytes.copy_from_slice(&self.buffer[8..14]);
        MacAddress(bytes)
    }

    pub fn sender_ip(&self) -> Ipv4Address {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&self.buffer[14..18]);
        Ipv4Address(bytes)
    }

    pub fn target_mac(&self) -> MacAddress {
        let mut bytes = [0u8; 6];
        bytes.copy_from_slice(&self.buffer[18..24]);
        MacAddress(bytes)
    }

    pub fn target_ip(&self) -> Ipv4Address {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&self.buffer[24..28]);
        Ipv4Address(bytes)
    }
}
