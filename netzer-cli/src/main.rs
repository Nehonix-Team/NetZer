#![allow(unused_assignments)]
pub mod web;

use clap::Parser;
use netzer_core::ethernet::{EthernetFrame, EtherType};
use netzer_core::hexdump::hexdump;
use netzer_core::ipv4::Ipv4Header;
use netzer_core::ipv6::Ipv6Header;
use netzer_core::arp::ArpPacket;
use netzer_core::icmp::IcmpHeader;
use netzer_core::tcp::TcpHeader;
use netzer_core::udp::UdpHeader;
use netzer_core::dns::DnsQuery;
use netzer_core::tls::TlsClientHello;
use netzer_core::tcp_stream::TcpStreamTracker;
use netzer_socket::socket::{RawSocket, RingSocket};
use web::WebServer;
use std::process;
use std::fs::File;
use std::io::Write;
use std::time::SystemTime;
use colored::{ColoredString, Colorize};
use chrono::Local;

#[derive(Parser, Debug)]
#[command(author, version, about = "A high-performance, zero-copy network packet analyzer for Linux")]
struct Args {
    /// Network interface to capture on (e.g., eth0, wlan0, lo)
    #[arg(short, long)]
    interface: String,

    /// Filter packets by port (BPF kernel filter)
    #[arg(long)]
    filter_port: Option<u16>,

    /// Filter packets by protocol: tcp, udp, icmp, arp (BPF kernel filter)
    #[arg(long)]
    filter_proto: Option<String>,

    /// Export raw captured packets to a PCAP file
    #[arg(long)]
    export_pcap: Option<String>,

    /// Export parsed packet metadata to a JSON lines file
    #[arg(long)]
    export_json: Option<String>,

    /// Print a full hex/ASCII dump of each captured packet
    #[arg(long, default_value_t = false)]
    hexdump: bool,

    /// Reassemble TCP streams and display HTTP sessions when detected
    #[arg(long, default_value_t = false)]
    follow_streams: bool,

    /// Use TPACKET_V3 ring buffer (mmap) instead of recv() for high-throughput capture
    #[arg(long, default_value_t = false)]
    ring_buffer: bool,

    /// Start the Web OSINT local server for live packet monitoring
    #[arg(long, default_value_t = false)]
    serve: bool,

    /// Port for the Web OSINT server
    #[arg(long, default_value_t = 7070)]
    port: u16,
}

struct PcapWriter {
    file: File,
}

impl PcapWriter {
    fn create(path: &str) -> std::io::Result<Self> {
        let mut file = File::create(path)?;
        
        let mut header = [0u8; 24];
        header[0..4].copy_from_slice(&0xa1b2c3d4u32.to_ne_bytes());
        header[4..6].copy_from_slice(&2u16.to_ne_bytes());
        header[6..8].copy_from_slice(&4u16.to_ne_bytes());
        header[16..20].copy_from_slice(&65535u32.to_ne_bytes());
        header[20..24].copy_from_slice(&1u32.to_ne_bytes()); // Ethernet
        
        file.write_all(&header)?;
        Ok(Self { file })
    }

    fn write_packet(&mut self, data: &[u8]) -> std::io::Result<()> {
        let duration = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::from_secs(0));
            
        let sec = duration.as_secs() as u32;
        let usec = duration.subsec_micros() as u32;
        let len = data.len() as u32;
        
        let mut header = [0u8; 16];
        header[0..4].copy_from_slice(&sec.to_ne_bytes());
        header[4..8].copy_from_slice(&usec.to_ne_bytes());
        header[8..12].copy_from_slice(&len.to_ne_bytes());
        header[12..16].copy_from_slice(&len.to_ne_bytes());
        
        self.file.write_all(&header)?;
        self.file.write_all(data)?;
        Ok(())
    }
}

struct JsonWriter {
    file: File,
}

impl JsonWriter {
    fn create(path: &str) -> std::io::Result<Self> {
        let file = File::create(path)?;
        Ok(Self { file })
    }

    fn write_packet(
        &mut self,
        time_str: &str,
        proto: &str,
        src: &str,
        dst: &str,
        info: &str,
        size: usize,
    ) -> std::io::Result<()> {
        let line = format!(
            "{{\"timestamp\":\"{}\",\"proto\":\"{}\",\"src\":\"{}\",\"dst\":\"{}\",\"info\":\"{}\",\"size\":{}}}\n",
            escape_json(time_str),
            escape_json(proto),
            escape_json(src),
            escape_json(dst),
            escape_json(info),
            size
        );
        self.file.write_all(line.as_bytes())?;
        Ok(())
    }
}

fn print_banner(interface: &str) {
    let banner = r#"
    ███╗   ██╗███████╗████████╗███████╗███████╗██████╗ 
    ████╗  ██║██╔════╝╚══██╔══╝╚══███╔╝██╔════╝██╔══██╗
    ██╔██╗ ██║█████╗     ██║     ███╔╝ █████╗  ██████╔╝
    ██║╚██╗██║██╔══╝     ██║    ███╔╝  ██╔══╝  ██╔══██╗
    ██║ ╚████║███████╗   ██║   ███████╗███████╗██║  ██║
    ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝
    "#;
    println!("{}", banner.bright_cyan().bold());
    println!("{}", "========================================================================================================================".bright_black());
    println!("  {} {}", "v0.1.0-alpha".bright_green(), "| High-Performance Zero-Copy Network Analyzer".italic());
    println!("  {} {}", "Listening on:".bold(), interface.bright_yellow());
    println!("{}", "========================================================================================================================".bright_black());
    println!(
        " {} │ {} │ {} │ {} │ {} │ {}",
        format!("{:<14}", "TIMESTAMP").bright_black().bold(),
        format!("{:<5}", "PROTO").bright_black().bold(),
        format!("{:<21}", "SOURCE").bright_black().bold(),
        format!("{:<21}", "DESTINATION").bright_black().bold(),
        format!("{:<35}", "INFO / DOMAIN").bright_black().bold(),
        format!("{:<6}", "SIZE").bright_black().bold()
    );
    println!("{}", "────────────────┼───────┼───────────────────────┼───────────────────────┼─────────────────────────────────────┼────────".bright_black());
}

fn truncate(s: &str, max_chars: usize) -> String {
    match s.char_indices().nth(max_chars) {
        None => s.to_string(),
        Some((idx, _)) => format!("{}...", &s[..idx - 3]),
    }
}

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn print_packet_line(
    time_str: &str,
    proto: ColoredString,
    src: &str,
    dst: &str,
    info: &str,
    size: usize,
) {
    let time_colored = format!("{:<14}", time_str).bright_black();
    let src_colored = format!("{:<21}", src).bright_green();
    let dst_colored = format!("{:<21}", dst).bright_red();
    let size_colored = format!("{:<6}", format!("{} B", size)).bright_yellow();

    println!(
        " {} │ {} │ {} │ {} │ {} │ {}",
        time_colored, proto, src_colored, dst_colored, info, size_colored
    );
}

fn to_hex_string(bytes: &[u8]) -> String {
    let limit = std::cmp::min(bytes.len(), 256);
    let mut s = String::with_capacity(limit * 2);
    for &b in &bytes[..limit] {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn handle_tcp(
    src_ip: &str,
    dst_ip: &str,
    payload: &[u8],
    time_str: &str,
    size: usize,
    json_writer: &mut Option<JsonWriter>,
    web_server: &Option<WebServer>,
    raw_hex: &str,
) {
    let (tcp_header, tcp_payload) = match TcpHeader::parse(payload) {
        Ok(res) => res,
        Err(_) => return,
    };
    
    let src_port = tcp_header.source_port();
    let dst_port = tcp_header.destination_port();
    let src = format!("{}:{}", src_ip, src_port);
    let dst = format!("{}:{}", dst_ip, dst_port);
    
    let mut domain_buf;
    let mut info_raw = "[ENCRYPTED]";
    let mut is_tls = false;
    let mut is_http = false;
    
    if dst_port == 443 {
        if let Ok(tls) = TlsClientHello::parse(tcp_payload) {
            domain_buf = truncate(tls.sni, 35);
            info_raw = &domain_buf;
            is_tls = true;
        } else {
            domain_buf = String::new();
        }
    } else {
        domain_buf = String::new();
        if src_port == 80 || dst_port == 80 || src_port == 8080 || dst_port == 8080 {
            let payload_str = String::from_utf8_lossy(tcp_payload);
            if let Some(first_line) = payload_str.lines().next() {
                let trimmed = first_line.trim();
                if trimmed.starts_with("GET ") || trimmed.starts_with("POST ") || trimmed.starts_with("PUT ") || trimmed.starts_with("DELETE ") || trimmed.starts_with("PATCH ") || trimmed.starts_with("OPTIONS ") || trimmed.starts_with("HEAD ") {
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() >= 2 {
                        domain_buf = format!("{} {}", parts[0], parts[1]);
                        info_raw = &domain_buf;
                        is_http = true;
                    } else {
                        info_raw = "[HTTP Request]";
                        is_http = true;
                    }
                } else if trimmed.starts_with("HTTP/") {
                    let parts: Vec<&str> = trimmed.splitn(3, ' ').collect();
                    if parts.len() >= 2 {
                        domain_buf = parts[1..].join(" ");
                        info_raw = &domain_buf;
                        is_http = true;
                    } else {
                        info_raw = "[HTTP Response]";
                        is_http = true;
                    }
                } else {
                    info_raw = "[HTTP]";
                    is_http = true;
                }
            } else {
                info_raw = "[HTTP]";
                is_http = true;
            }
        }
    }
    
    // UI Printing
    let proto_colored = if is_tls {
        format!("{:<5}", "TLS").bright_magenta().bold()
    } else if is_http {
        format!("{:<5}", "HTTP").bright_green().bold()
    } else {
        format!("{:<5}", "TCP").bright_cyan().bold()
    };
    
    let info_colored = if info_raw == "[ENCRYPTED]" {
        format!("{:<35}", info_raw).bright_black().to_string()
    } else if is_http {
        format!("{:<35}", info_raw).bright_green().to_string()
    } else {
        format!("{:<35}", info_raw).bright_magenta().bold().to_string()
    };
    
    print_packet_line(time_str, proto_colored, &src, &dst, &info_colored, size);
    
    // JSON Logging
    if let Some(writer) = json_writer {
        let proto_log = if is_tls { "TLS" } else if is_http { "HTTP" } else { "TCP" };
        let _ = writer.write_packet(time_str, proto_log, &src, &dst, info_raw, size);
    }

    // Web OSINT Server Broadcast
    if let Some(server) = web_server {
        let proto_name = if is_tls { 
            "TLS" 
        } else if is_http {
            "HTTP"
        } else { 
            "TCP" 
        };
        let msg = format!(
            "{{\"timestamp\":\"{}\",\"proto\":\"{}\",\"src\":\"{}\",\"dst\":\"{}\",\"info\":\"{}\",\"size\":{},\"payload\":\"{}\"}}",
            escape_json(time_str),
            escape_json(proto_name),
            escape_json(&src),
            escape_json(&dst),
            escape_json(info_raw),
            size,
            raw_hex
        );
        server.broadcast(&msg);
    }
}

fn handle_udp(
    src_ip: &str,
    dst_ip: &str,
    payload: &[u8],
    time_str: &str,
    size: usize,
    json_writer: &mut Option<JsonWriter>,
    web_server: &Option<WebServer>,
    raw_hex: &str,
) {
    let (udp_header, udp_payload) = match UdpHeader::parse(payload) {
        Ok(res) => res,
        Err(_) => return,
    };
    
    let src_port = udp_header.source_port();
    let dst_port = udp_header.destination_port();
    let src = format!("{}:{}", src_ip, src_port);
    let dst = format!("{}:{}", dst_ip, dst_port);
    
    let dns_buf;
    let mut info_raw = "-";
    let mut is_dns = false;
    
    if dst_port == 53 || src_port == 53 {
        is_dns = true;
        if let Ok(dns) = DnsQuery::parse(udp_payload) {
            dns_buf = format!("DNS: {}", truncate(&dns.domain_name, 30));
            info_raw = &dns_buf;
        } else {
            dns_buf = String::new();
            info_raw = "DNS";
        }
    } else {
        dns_buf = String::new();
    }
    
    // UI Printing
    let proto_colored = format!("{:<5}", "UDP").bright_blue().bold();
    let info_colored = if is_dns {
        format!("{:<35}", info_raw).bright_yellow().bold().to_string()
    } else {
        format!("{:<35}", info_raw).bright_black().to_string()
    };
    
    print_packet_line(time_str, proto_colored, &src, &dst, &info_colored, size);
    
    // JSON Logging
    if let Some(writer) = json_writer {
        let _ = writer.write_packet(time_str, "UDP", &src, &dst, info_raw, size);
    }

    // Web OSINT Server Broadcast
    if let Some(server) = web_server {
        let proto_name = if is_dns { "DNS" } else { "UDP" };
        let msg = format!(
            "{{\"timestamp\":\"{}\",\"proto\":\"{}\",\"src\":\"{}\",\"dst\":\"{}\",\"info\":\"{}\",\"size\":{},\"payload\":\"{}\"}}",
            escape_json(time_str),
            escape_json(proto_name),
            escape_json(&src),
            escape_json(&dst),
            escape_json(info_raw),
            size,
            raw_hex
        );
        server.broadcast(&msg);
    }
}

fn handle_icmp(
    src_ip: &str,
    dst_ip: &str,
    payload: &[u8],
    time_str: &str,
    size: usize,
    json_writer: &mut Option<JsonWriter>,
    web_server: &Option<WebServer>,
    raw_hex: &str,
) {
    let (icmp_header, _) = match IcmpHeader::parse(payload) {
        Ok(res) => res,
        Err(_) => return,
    };
    
    let info_raw = match icmp_header.icmp_type() {
        0 => "Echo Reply (0)".to_string(),
        3 => format!("Dest Unreachable ({})", icmp_header.code()),
        8 => "Echo Request (8)".to_string(),
        11 => "Time Exceeded".to_string(),
        t => format!("Type {}", t),
    };
    
    // UI Printing
    let proto_colored = format!("{:<5}", "ICMP").bright_red().bold();
    let info_colored = format!("{:<35}", info_raw).bright_red().to_string();
    
    print_packet_line(time_str, proto_colored, src_ip, dst_ip, &info_colored, size);
    
    // JSON Logging
    if let Some(writer) = json_writer {
        let _ = writer.write_packet(time_str, "ICMP", src_ip, dst_ip, &info_raw, size);
    }

    // Web OSINT Server Broadcast
    if let Some(server) = web_server {
        let msg = format!(
            "{{\"timestamp\":\"{}\",\"proto\":\"ICMP\",\"src\":\"{}\",\"dst\":\"{}\",\"info\":\"{}\",\"size\":{},\"payload\":\"{}\"}}",
            escape_json(time_str),
            escape_json(src_ip),
            escape_json(dst_ip),
            escape_json(&info_raw),
            size,
            raw_hex
        );
        server.broadcast(&msg);
    }
}

fn handle_icmpv6(
    src_ip: &str,
    dst_ip: &str,
    payload: &[u8],
    time_str: &str,
    size: usize,
    json_writer: &mut Option<JsonWriter>,
    web_server: &Option<WebServer>,
    raw_hex: &str,
) {
    let (icmp_header, _) = match IcmpHeader::parse(payload) {
        Ok(res) => res,
        Err(_) => return,
    };
    
    let info_raw = match icmp_header.icmp_type() {
        1 => "Dest Unreachable".to_string(),
        2 => "Packet Too Big".to_string(),
        3 => "Time Exceeded".to_string(),
        128 => "Echo Request (Ping)".to_string(),
        129 => "Echo Reply (Ping)".to_string(),
        133 => "Router Solicitation".to_string(),
        134 => "Router Advertisement".to_string(),
        135 => "Neighbor Solicitation".to_string(),
        136 => "Neighbor Advertisement".to_string(),
        t => format!("Type {}", t),
    };
    
    // UI Printing
    let proto_colored = format!("{:<5}", "ICMP6").bright_red().bold();
    let info_colored = format!("{:<35}", info_raw).bright_red().to_string();
    
    print_packet_line(time_str, proto_colored, src_ip, dst_ip, &info_colored, size);
    
    // JSON Logging
    if let Some(writer) = json_writer {
        let _ = writer.write_packet(time_str, "ICMPv6", src_ip, dst_ip, &info_raw, size);
    }

    // Web OSINT Server Broadcast
    if let Some(server) = web_server {
        let msg = format!(
            "{{\"timestamp\":\"{}\",\"proto\":\"ICMP6\",\"src\":\"{}\",\"dst\":\"{}\",\"info\":\"{}\",\"size\":{},\"payload\":\"{}\"}}",
            escape_json(time_str),
            escape_json(src_ip),
            escape_json(dst_ip),
            escape_json(&info_raw),
            size,
            raw_hex
        );
        server.broadcast(&msg);
    }
}

fn handle_arp(
    payload: &[u8],
    time_str: &str,
    size: usize,
    json_writer: &mut Option<JsonWriter>,
    web_server: &Option<WebServer>,
    raw_hex: &str,
) {
    let arp = match ArpPacket::parse(payload) {
        Ok(res) => res,
        Err(_) => return,
    };
    
    let opcode = arp.opcode();
    let info_raw = match opcode {
        1 => format!("Who has {}? Tell {}", arp.target_ip(), arp.sender_ip()),
        2 => format!("{} is at {}", arp.sender_ip(), arp.sender_mac()),
        op => format!("Opcode {}", op),
    };
    
    let src = format!("{}", arp.sender_mac());
    let dst = format!("{}", arp.target_mac());
    
    // UI Printing
    let proto_colored = format!("{:<5}", "ARP").bright_yellow().bold();
    let info_colored = format!("{:<35}", truncate(&info_raw, 35)).bright_yellow().to_string();
    
    print_packet_line(time_str, proto_colored, &src, &dst, &info_colored, size);
    
    // JSON Logging
    if let Some(writer) = json_writer {
        let _ = writer.write_packet(time_str, "ARP", &src, &dst, &info_raw, size);
    }

    // Web OSINT Server Broadcast
    if let Some(server) = web_server {
        let msg = format!(
            "{{\"timestamp\":\"{}\",\"proto\":\"ARP\",\"src\":\"{}\",\"dst\":\"{}\",\"info\":\"{}\",\"size\":{},\"payload\":\"{}\"}}",
            escape_json(time_str),
            escape_json(&src),
            escape_json(&dst),
            escape_json(&info_raw),
            size,
            raw_hex
        );
        server.broadcast(&msg);
    }
}

fn print_status_line(label: &str, value: &str) {
    println!(" [SYSTEM] {}: {}", label, value.bright_green());
    println!("{}", "────────────────┼───────┼───────────────────────┼───────────────────────┼─────────────────────────────────────┼────────".bright_black());
}

fn process_packet(
    packet_data: &[u8],
    size: usize,
    pcap_writer: &mut Option<PcapWriter>,
    json_writer: &mut Option<JsonWriter>,
    stream_tracker: &mut Option<TcpStreamTracker>,
    show_hexdump: bool,
    web_server: &Option<WebServer>,
) {
    // Write raw frame to PCAP if enabled
    if let Some(writer) = pcap_writer {
        let _ = writer.write_packet(packet_data);
    }

    // Hex/ASCII dump before protocol analysis
    if show_hexdump {
        let dump = hexdump(packet_data);
        println!("{}", dump.bright_black());
    }

    let (eth_frame, payload) = match EthernetFrame::parse(packet_data) {
        Ok(res) => res,
        Err(_) => return,
    };

    let now = Local::now();
    let time_str = now.format("%H:%M:%S%.3f").to_string();
    let raw_hex = to_hex_string(packet_data);

    match eth_frame.ethertype() {
        EtherType::Ipv4 => {
            let (ipv4_header, ip_payload) = match Ipv4Header::parse(payload) {
                Ok(res) => res,
                Err(_) => return,
            };

            let src_ip = format!("{}", ipv4_header.source());
            let dst_ip = format!("{}", ipv4_header.destination());

            match ipv4_header.protocol() {
                6 => {
                    // Parse TCP to extract ports and payload for stream tracker
                    if let Ok((tcp_header, tcp_payload)) = TcpHeader::parse(ip_payload) {
                        let src_port = tcp_header.source_port();
                        let dst_port = tcp_header.destination_port();

                        // Feed to stream reassembler if enabled
                        if let Some(tracker) = stream_tracker {
                            if let Some((_key, data)) = tracker.feed(&src_ip, src_port, &dst_ip, dst_port, tcp_payload) {
                                let printable: String = data.iter().map(|&b| {
                                    let c = b as char;
                                    if c.is_ascii_graphic() || c == ' ' || c == '\n' || c == '\r' { c } else { '.' }
                                }).collect();
                                println!("{}", " ─── Stream Reassembly ────────────────────────────────────────────────────────────────────────────────────────────".bright_blue());
                                println!("{}", printable.bright_white());
                                println!("{}", " ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────".bright_blue());
                            }
                        }

                        // Re-parse ip_payload so handle_tcp can use it
                        handle_tcp(&src_ip, &dst_ip, ip_payload, &time_str, size, json_writer, web_server, &raw_hex);
                    } else {
                        handle_tcp(&src_ip, &dst_ip, ip_payload, &time_str, size, json_writer, web_server, &raw_hex);
                    }
                }
                17 => handle_udp(&src_ip, &dst_ip, ip_payload, &time_str, size, json_writer, web_server, &raw_hex),
                1 => handle_icmp(&src_ip, &dst_ip, ip_payload, &time_str, size, json_writer, web_server, &raw_hex),
                _ => {}
            }
        }
        EtherType::Ipv6 => {
            let (ipv6_header, ip_payload) = match Ipv6Header::parse(payload) {
                Ok(res) => res,
                Err(_) => return,
            };

            let src_ip = format!("{}", ipv6_header.source());
            let dst_ip = format!("{}", ipv6_header.destination());

            match ipv6_header.next_header() {
                6 => handle_tcp(&src_ip, &dst_ip, ip_payload, &time_str, size, json_writer, web_server, &raw_hex),
                17 => handle_udp(&src_ip, &dst_ip, ip_payload, &time_str, size, json_writer, web_server, &raw_hex),
                58 => handle_icmpv6(&src_ip, &dst_ip, ip_payload, &time_str, size, json_writer, web_server, &raw_hex),
                _ => {}
            }
        }
        EtherType::Arp => {
            handle_arp(payload, &time_str, size, json_writer, web_server, &raw_hex);
        }
        _ => {}
    }
}

fn main() {
    let args = Args::parse();

    // Create socket BEFORE dropping privileges — AF_PACKET requires CAP_NET_RAW
    let (raw_socket, ring_socket) = if args.ring_buffer {
        match RingSocket::new(&args.interface) {
            Ok(s) => (None, Some(s)),
            Err(e) => {
                eprintln!("\n {} {}", "[-] ERROR:".bright_red().bold(), "Failed to open ring socket (TPACKET_V3).".white());
                eprintln!("     Details: {}", e.to_string().bright_black());
                eprintln!("     {}\n", "Hint: TPACKET_V3 requires a kernel >= 3.2 and CAP_NET_RAW.".bright_black());
                process::exit(1);
            }
        }
    } else {
        match RawSocket::new(&args.interface) {
            Ok(s) => (Some(s), None),
            Err(e) => {
                eprintln!("\n {} {}", "[-] ERROR:".bright_red().bold(), "Failed to open raw socket.".white());
                eprintln!("     Details: {}", e.to_string().bright_black());
                let hint = match e.raw_os_error() {
                    Some(1) | Some(13) => "Hint: NetZer requires CAP_NET_RAW. Try running with 'sudo'.",
                    Some(19) => "Hint: The specified interface does not exist. Check 'ifconfig' or 'ip link'.",
                    _ => "Hint: Ensure the interface is up and you have sufficient permissions.",
                };
                eprintln!("     {}\n", hint.bright_black());
                process::exit(1);
            }
        }
    };

    // Apply BPF filters (must be before privilege drop)
    if let Some(ref sock) = raw_socket {
        if let Some(port) = args.filter_port {
            if let Err(e) = sock.attach_filter_port(port) {
                eprintln!("\n {} {}", "[-] ERROR:".bright_red().bold(), "Failed to attach BPF port filter.".white());
                eprintln!("     Details: {}", e.to_string().bright_black());
                process::exit(1);
            }
        }
        if let Some(ref proto) = args.filter_proto {
            if let Err(e) = sock.attach_filter_proto(proto) {
                eprintln!("\n {} {}", "[-] ERROR:".bright_red().bold(), "Failed to attach BPF protocol filter.".white());
                eprintln!("     Details: {}", e.to_string().bright_black());
                process::exit(1);
            }
        }
    }

    // Create export files before privilege drop (may need write access to current dir)
    let mut pcap_writer = if let Some(ref path) = args.export_pcap {
        match PcapWriter::create(path) {
            Ok(w) => Some(w),
            Err(e) => {
                eprintln!("\n {} Failed to create PCAP file: {}", "[-] ERROR:".bright_red().bold(), e);
                process::exit(1);
            }
        }
    } else { None };

    let mut json_writer = if let Some(ref path) = args.export_json {
        match JsonWriter::create(path) {
            Ok(w) => Some(w),
            Err(e) => {
                eprintln!("\n {} Failed to create JSON file: {}", "[-] ERROR:".bright_red().bold(), e);
                process::exit(1);
            }
        }
    } else { None };

    // Drop root privileges
    if let Err(e) = netzer_socket::socket::drop_privileges() {
        eprintln!("\n {} {}", "[-] ERROR:".bright_red().bold(), "Failed to drop root privileges.".white());
        eprintln!("     Details: {}", e.to_string().bright_black());
        process::exit(1);
    }

    // Initialize optional stream tracker (non-root, safe to allocate here)
    let mut stream_tracker: Option<TcpStreamTracker> = if args.follow_streams {
        Some(TcpStreamTracker::new())
    } else {
        None
    };

    // Initialize and start Web OSINT Server if requested
    let web_server = if args.serve {
        let ws = WebServer::new(args.port, &args.interface);
        ws.start();
        Some(ws)
    } else {
        None
    };

    print_banner(&args.interface);

    if args.ring_buffer {
        print_status_line("Capture Mode", "TPACKET_V3 Ring Buffer (zero-copy mmap)");
    }
    if args.hexdump {
        print_status_line("Hex/ASCII Dump", "Active (printing raw bytes for each packet)");
    }
    if args.follow_streams {
        print_status_line("Follow Streams", "Active (TCP stream reassembly enabled)");
    }
    if args.serve {
        print_status_line("OSINT Dashboard", &format!("Active (http://127.0.0.1:{})", args.port));
    }
    if args.filter_port.is_some() || args.filter_proto.is_some() {
        println!(" [SECURITY] BPF Kernel Filters Active:");
        if let Some(port) = args.filter_port {
            println!("   - Port: {}", port.to_string().bright_yellow());
        }
        if let Some(ref proto) = args.filter_proto {
            println!("   - Protocol: {}", proto.to_uppercase().bright_yellow());
        }
        println!("{}", "────────────────┼───────┼───────────────────────┼───────────────────────┼─────────────────────────────────────┼────────".bright_black());
    }
    if let Some(ref path) = args.export_pcap {
        print_status_line("PCAP Export", path);
    }
    if let Some(ref path) = args.export_json {
        print_status_line("JSON Export", path);
    }

    // -----------------------------------------------------------------------
    // Main capture loop
    // -----------------------------------------------------------------------
    if let Some(mut ring) = ring_socket {
        // TPACKET_V3 high-throughput path
        loop {
            if let Err(e) = ring.recv_block(|frame| {
                process_packet(
                    frame,
                    frame.len(),
                    &mut pcap_writer,
                    &mut json_writer,
                    &mut stream_tracker,
                    args.hexdump,
                    &web_server,
                );
            }) {
                eprintln!(" [SYSTEM] Ring buffer read error: {}", e);
            }
        }
    } else if let Some(ref sock) = raw_socket {
        // Classic recv() path
        let mut buffer = vec![0u8; 65535];
        loop {
            match sock.recv(&mut buffer) {
                Ok(size) => {
                    let packet_data = buffer[..size].to_vec();
                    process_packet(
                        &packet_data,
                        size,
                        &mut pcap_writer,
                        &mut json_writer,
                        &mut stream_tracker,
                        args.hexdump,
                        &web_server,
                    );
                }
                Err(e) => {
                    eprintln!(" [SYSTEM] READ ERROR: {}", e);
                }
            }
        }
    }
}
