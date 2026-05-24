use std::net::{TcpListener, TcpStream};
use std::io::{Write, Read};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{channel, Sender};
use std::thread;

pub mod assets;

// --- Built-in SHA-1 implementation ---
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;

    let mut bytes = data.to_vec();
    let original_len_bits = (data.len() as u64) * 8;
    bytes.push(0x80);
    while (bytes.len() * 8) % 512 != 448 {
        bytes.push(0x00);
    }
    bytes.extend_from_slice(&original_len_bits.to_be_bytes());

    for chunk in bytes.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };

            let temp = a.rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

// --- Built-in Base64 implementation ---
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    let mut i = 0;
    while i < data.len() {
        let chunk = &data[i..std::cmp::min(i + 3, data.len())];
        let mut b = 0u32;
        for &val in chunk {
            b = (b << 8) | (val as u32);
        }
        if chunk.len() == 3 {
            result.push(ALPHABET[((b >> 18) & 0x3f) as usize] as char);
            result.push(ALPHABET[((b >> 12) & 0x3f) as usize] as char);
            result.push(ALPHABET[((b >> 6) & 0x3f) as usize] as char);
            result.push(ALPHABET[(b & 0x3f) as usize] as char);
        } else if chunk.len() == 2 {
            b <<= 2;
            result.push(ALPHABET[((b >> 12) & 0x3f) as usize] as char);
            result.push(ALPHABET[((b >> 6) & 0x3f) as usize] as char);
            result.push(ALPHABET[(b & 0x3f) as usize] as char);
            result.push('=');
        } else if chunk.len() == 1 {
            b <<= 4;
            result.push(ALPHABET[((b >> 6) & 0x3f) as usize] as char);
            result.push(ALPHABET[(b & 0x3f) as usize] as char);
            result.push('=');
            result.push('=');
        }
        i += 3;
    }
    result
}

// --- WebSocket Frame Encoder ---
fn encode_ws_text_frame(payload: &str) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.push(0x81); // FIN = 1, Opcode = 1 (text frame)
    let len = payload.len();
    if len <= 125 {
        frame.push(len as u8);
    } else if len <= 65535 {
        frame.push(126);
        frame.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        frame.push(127);
        frame.extend_from_slice(&(len as u64).to_be_bytes());
    }
    frame.extend_from_slice(payload.as_bytes());
    frame
}

pub struct WebServer {
    clients: Arc<Mutex<Vec<TcpStream>>>,
    port: u16,
    tx: Sender<String>,
    interface: String,
}

impl WebServer {
    pub fn new(port: u16, interface: &str) -> Self {
        let (tx, rx) = channel::<String>();
        let clients = Arc::new(Mutex::new(Vec::<TcpStream>::new()));
        
        // Spawn the broadcaster thread to prevent blocking the packet capture loop
        let clients_clone = clients.clone();
        thread::spawn(move || {
            while let Ok(msg) = rx.recv() {
                let mut cls = clients_clone.lock().unwrap();
                let mut to_remove = Vec::new();
                
                // Encode the JSON message as a WebSocket text frame
                let ws_frame = encode_ws_text_frame(&msg);

                for (idx, client) in cls.iter_mut().enumerate() {
                    if let Err(_) = client.write_all(&ws_frame).and_then(|_| client.flush()) {
                        to_remove.push(idx);
                    }
                }

                // Remove disconnected clients in reverse order
                for idx in to_remove.into_iter().rev() {
                    cls.remove(idx);
                }
            }
        });

        Self {
            clients,
            port,
            tx,
            interface: interface.to_string(),
        }
    }

    pub fn start(&self) {
        let clients = self.clients.clone();
        let port = self.port;
        let interface = self.interface.clone();
        
        thread::spawn(move || {
            let listener = match TcpListener::bind(format!("127.0.0.1:{}", port)) {
                Ok(l) => {
                    println!(" [SYSTEM] Web OSINT Server started on http://127.0.0.1:{}", port);
                    l
                }
                Err(e) => {
                    eprintln!(" [SYSTEM] Failed to bind Web OSINT Server to port {}: {}", port, e);
                    return;
                }
            };

            for stream in listener.incoming() {
                match stream {
                    Ok(mut stream) => {
                        let clients_clone = clients.clone();
                        let interface_clone = interface.clone();
                        
                        thread::spawn(move || {
                            let mut buf = [0u8; 2048];
                            if let Ok(n) = stream.read(&mut buf) {
                                let request = String::from_utf8_lossy(&buf[..n]);
                                if request.starts_with("GET / ") || request.starts_with("GET /index.html ") {
                                    let html = assets::INDEX_HTML;
                                    let response = format!(
                                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                        html.len(),
                                        html
                                    );
                                    let _ = stream.write_all(response.as_bytes());
                                    let _ = stream.flush();
                                } else if request.starts_with("GET /ws ") {
                                    // Parse WebSocket key
                                    let mut ws_key = None;
                                    for line in request.lines() {
                                        if line.to_lowercase().starts_with("sec-websocket-key:") {
                                            ws_key = Some(line["sec-websocket-key:".len()..].trim().to_string());
                                            break;
                                        }
                                    }

                                    if let Some(key) = ws_key {
                                        // Compute handshake accept key
                                        let concat = format!("{}258EAFA5-E914-47DA-95CA-C5AB0DC85B11", key);
                                        let hashed = sha1(concat.as_bytes());
                                        let accept = base64_encode(&hashed);

                                        let response = format!(
                                            "HTTP/1.1 101 Switching Protocols\r\n\
                                             Upgrade: websocket\r\n\
                                             Connection: Upgrade\r\n\
                                             Sec-WebSocket-Accept: {}\r\n\r\n",
                                            accept
                                        );

                                        let _ = stream.set_write_timeout(Some(std::time::Duration::from_millis(100)));
                                        if stream.write_all(response.as_bytes()).is_ok() && stream.flush().is_ok() {
                                            // Send initial system info frame
                                            let sys_info = format!("{{\"type\":\"system\",\"interface\":\"{}\"}}", interface_clone);
                                            let ws_frame = encode_ws_text_frame(&sys_info);
                                            let _ = stream.write_all(&ws_frame).and_then(|_| stream.flush());

                                            let mut cls = clients_clone.lock().unwrap();
                                            cls.push(stream);
                                        }
                                    } else {
                                        let response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                                        let _ = stream.write_all(response.as_bytes());
                                    }
                                } else {
                                    let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                                    let _ = stream.write_all(response.as_bytes());
                                }
                            }
                        });
                    }
                    Err(_) => {}
                }
            }
        });
    }

    pub fn broadcast(&self, json_msg: &str) {
        let _ = self.tx.send(json_msg.to_string());
    }
}
