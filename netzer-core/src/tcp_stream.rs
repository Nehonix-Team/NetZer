use std::collections::HashMap;

/// Unique key identifying a TCP connection (bidirectional-aware).
/// We always put the smaller (ip, port) first so that both directions
/// of a connection share the same key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StreamKey {
    pub client_ip: String,
    pub client_port: u16,
    pub server_ip: String,
    pub server_port: u16,
}

impl StreamKey {
    pub fn new(src_ip: &str, src_port: u16, dst_ip: &str, dst_port: u16) -> Self {
        let a = (src_ip, src_port);
        let b = (dst_ip, dst_port);
        if (src_ip, src_port) < (dst_ip, dst_port) {
            Self {
                client_ip: a.0.to_string(),
                client_port: a.1,
                server_ip: b.0.to_string(),
                server_port: b.1,
            }
        } else {
            Self {
                client_ip: b.0.to_string(),
                client_port: b.1,
                server_ip: a.0.to_string(),
                server_port: a.1,
            }
        }
    }
}

/// Holds the accumulated payload bytes of an ongoing TCP session.
pub struct TcpStream {
    pub key: StreamKey,
    /// All accumulated payload bytes so far (best-effort, no strict reordering).
    pub data: Vec<u8>,
    pub packet_count: usize,
}

impl TcpStream {
    fn new(key: StreamKey) -> Self {
        Self {
            key,
            data: Vec::new(),
            packet_count: 0,
        }
    }
}

/// Tracks all active TCP streams and reassembles their payloads.
pub struct TcpStreamTracker {
    streams: HashMap<StreamKey, TcpStream>,
    /// Maximum number of bytes accumulated per stream before flushing to display.
    flush_threshold: usize,
}

impl TcpStreamTracker {
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
            flush_threshold: 4096,
        }
    }

    /// Feed a new TCP payload segment into the tracker.
    /// Returns Some(flushed_data) if a stream has accumulated enough data to display,
    /// or if an HTTP response/request boundary is detected.
    pub fn feed(
        &mut self,
        src_ip: &str,
        src_port: u16,
        dst_ip: &str,
        dst_port: u16,
        payload: &[u8],
    ) -> Option<(StreamKey, Vec<u8>)> {
        if payload.is_empty() {
            return None;
        }

        let key = StreamKey::new(src_ip, src_port, dst_ip, dst_port);
        let stream = self.streams.entry(key.clone()).or_insert_with(|| TcpStream::new(key.clone()));

        stream.data.extend_from_slice(payload);
        stream.packet_count += 1;

        // Detect HTTP boundary to trigger a display
        let is_http_request = stream.data.starts_with(b"GET ")
            || stream.data.starts_with(b"POST ")
            || stream.data.starts_with(b"PUT ")
            || stream.data.starts_with(b"DELETE ")
            || stream.data.starts_with(b"HTTP/");

        let should_flush = stream.data.len() >= self.flush_threshold
            || (is_http_request && stream.data.contains(&b'\n'));

        if should_flush {
            let flushed_data = stream.data.clone();
            stream.data.clear();
            stream.packet_count = 0;
            return Some((key, flushed_data));
        }

        None
    }

    /// Remove all streams — useful when the user sends Ctrl+C.
    pub fn clear(&mut self) {
        self.streams.clear();
    }
}

impl Default for TcpStreamTracker {
    fn default() -> Self {
        Self::new()
    }
}
