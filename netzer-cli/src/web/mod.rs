use std::net::{TcpListener, TcpStream};
use std::io::{Write, Read};
use std::sync::{Arc, Mutex};
use std::thread;

pub mod assets;

pub struct WebServer {
    clients: Arc<Mutex<Vec<TcpStream>>>,
    port: u16,
}

impl WebServer {
    pub fn new(port: u16) -> Self {
        Self {
            clients: Arc::new(Mutex::new(Vec::new())),
            port,
        }
    }

    pub fn start(&self) {
        let clients = self.clients.clone();
        let port = self.port;
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
                        thread::spawn(move || {
                            let mut buf = [0u8; 1024];
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
                                } else if request.starts_with("GET /events ") {
                                    let response = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\nAccess-Control-Allow-Origin: *\r\n\r\n";
                                    let _ = stream.set_write_timeout(Some(std::time::Duration::from_millis(200)));
                                    if stream.write_all(response.as_bytes()).is_ok() && stream.flush().is_ok() {
                                        let mut cls = clients_clone.lock().unwrap();
                                        cls.push(stream);
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
        let mut clients = self.clients.lock().unwrap();
        let mut to_remove = Vec::new();

        let sse_data = format!("data: {}\n\n", json_msg);
        let bytes = sse_data.as_bytes();

        for (idx, client) in clients.iter_mut().enumerate() {
            if let Err(_) = client.write_all(bytes).and_then(|_| client.flush()) {
                to_remove.push(idx);
            }
        }

        // Remove disconnected clients in reverse order
        for idx in to_remove.into_iter().rev() {
            clients.remove(idx);
        }
    }
}
