/// Formats a raw byte slice into a Wireshark/hexdump-style two-column output.
///
/// Output format per line (16 bytes per row):
///   OFFSET  HEX COLUMNS (8+8)  ASCII
///   0000  45 00 00 3c 1c 46 40 00  40 06 b1 e6 c0 a8 01 0a  E..<.F@.@.......
pub fn hexdump(data: &[u8]) -> String {
    let mut output = String::new();
    let mut offset = 0usize;

    for chunk in data.chunks(16) {
        // Offset column
        output.push_str(&format!("  {:04x}  ", offset));

        // Hex columns (two groups of 8, separated by an extra space)
        for (i, byte) in chunk.iter().enumerate() {
            if i == 8 {
                output.push(' ');
            }
            output.push_str(&format!("{:02x} ", byte));
        }

        // Pad if the last line is short
        let missing = 16 - chunk.len();
        for i in 0..missing {
            if chunk.len() + i == 8 {
                output.push(' ');
            }
            output.push_str("   ");
        }

        // ASCII column
        output.push(' ');
        for byte in chunk.iter() {
            let c = *byte as char;
            if c.is_ascii_graphic() || c == ' ' {
                output.push(c);
            } else {
                output.push('.');
            }
        }

        output.push('\n');
        offset += chunk.len();
    }

    output
}
