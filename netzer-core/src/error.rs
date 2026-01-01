#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    BufferTooShort,
    InvalidFormat,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::BufferTooShort => write!(f, "buffer is too short to parse the header"),
            ParseError::InvalidFormat => write!(f, "invalid header format"),
        }
    }
}

impl std::error::Error for ParseError {}
