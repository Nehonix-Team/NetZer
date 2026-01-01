use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddress(pub [u8; 6]);

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_display() {
        let mac = MacAddress([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]);
        assert_eq!(mac.to_string(), "00:1a:2b:3c:4d:5e");
    }
}
