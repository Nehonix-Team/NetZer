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
use std::io::IsTerminal;
use std::time::SystemTime;
use colored::{ColoredString, Colorize};
use chrono::Local;
use std::sync::{Arc, Mutex};

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

    /// Do not show the interactive TUI Dashboard, use classic simple logging
    #[arg(long, default_value_t = false)]
    no_tui: bool,
}

struct PacketInfo {
    timestamp: String,
    proto: String,
    src: String,
    dst: String,
    info: String,
    size: usize,
    payload: Vec<u8>,
}

struct UiState {
    packets: Vec<PacketInfo>,
    total_packets: usize,
    total_bytes: usize,
    proto_counts: std::collections::HashMap<String, usize>,
    ip_stats: std::collections::HashMap<String, usize>,
    rates: Vec<usize>,
    packets_this_sec: usize,
    interface: String,
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

// ============================================================================
//  NetZer — Premium TUI UI Layer
//  Drop-in replacement for draw_tui(), print_banner(), and helpers.
//  Copy these functions into main.rs, replacing the originals.
// ============================================================================

// ── Widths ──────────────────────────────────────────────────────────────────
// Total inner width (between the outer │ walls): 118 chars
// Left panel inner  : 63
// Right panel inner : 52
// Separator column  : 1 (the │ itself)
// Total             : 63 + 1 + 52 + 2 (outer walls) = 118 + 2 = 120 wide

const W_TOTAL: usize = 118; // chars between outer │ walls
const W_LEFT:  usize = 63;
const W_RIGHT: usize = 52;

// ── Box-drawing helpers ──────────────────────────────────────────────────────

fn h_line(n: usize) -> String { "─".repeat(n) }

fn top_border()   -> String { format!("╭{}╮", h_line(W_TOTAL + 2)) }
fn bot_border()   -> String { format!("╰{}╯", h_line(W_TOTAL + 2)) }
fn mid_full()     -> String { format!("├{}┤", h_line(W_TOTAL + 2)) }
fn mid_split_top()-> String {
    format!("├{}┬{}┤", h_line(W_LEFT + 2), h_line(W_RIGHT + 2))
}
fn mid_split_mid()-> String {
    format!("├{}┼{}┤", h_line(W_LEFT + 2), h_line(W_RIGHT + 2))
}
fn mid_split_bot()-> String {
    format!("├{}┴{}┤", h_line(W_LEFT + 2), h_line(W_RIGHT + 2))
}

// Full-width row
fn row_full(content: &str) -> String {
    format!("│ {} │", pad_visible(content, W_TOTAL))
}

// Two-panel row
fn row_split(left: &str, right: &str) -> String {
    format!("│ {} │ {} │", pad_visible(left, W_LEFT), pad_visible(right, W_RIGHT))
}

// ── String helpers ───────────────────────────────────────────────────────────

fn visible_width(s: &str) -> usize {
    let mut count = 0;
    let mut in_ansi = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1B' {
            if chars.peek() == Some(&'[') {
                in_ansi = true;
                chars.next();
                continue;
            }
        }
        if in_ansi {
            if c == 'm' { in_ansi = false; }
            continue;
        }
        count += 1;
    }
    count
}

fn pad_visible(content: &str, width: usize) -> String {
    let vis = visible_width(content);
    if vis >= width {
        // Hard-truncate visible chars (keep ANSI codes of kept chars)
        let mut result = String::new();
        let mut count = 0;
        let mut in_ansi = false;
        for c in content.chars() {
            if c == '\x1B' { in_ansi = true; result.push(c); continue; }
            if in_ansi {
                result.push(c);
                if c == 'm' { in_ansi = false; }
                continue;
            }
            if count >= width { break; }
            result.push(c);
            count += 1;
        }
        result
    } else {
        format!("{}{}", content, " ".repeat(width - vis))
    }
}

fn truncate(s: &str, max_chars: usize) -> String {
    match s.char_indices().nth(max_chars) {
        None => s.to_string(),
        Some((idx, _)) => format!("{}…", &s[..idx.saturating_sub(1)]),
    }
}

fn format_bytes(n: usize) -> String {
    if n >= 1_073_741_824 { format!("{:.2} GB", n as f64 / 1_073_741_824.0) }
    else if n >= 1_048_576  { format!("{:.2} MB", n as f64 / 1_048_576.0) }
    else if n >= 1_024      { format!("{:.1} KB", n as f64 / 1_024.0) }
    else                    { format!("{} B",  n) }
}

fn get_sparkline_char(val: usize, max: usize) -> char {
    if max == 0 || val == 0 { return '·'; }
    let chars = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let idx = ((val * (chars.len() - 1)) / max).min(chars.len() - 1);
    chars[idx]
}

// ── Hex dump ─────────────────────────────────────────────────────────────────

fn format_inspector_hex(bytes: &[u8]) -> Vec<String> {
    let mut lines = Vec::new();
    let limit = bytes.len().min(96); // 6 lines × 16 bytes
    for chunk_idx in (0..limit).step_by(16) {
        let chunk_end = (chunk_idx + 16).min(limit);
        let chunk = &bytes[chunk_idx..chunk_end];

        let mut hex_part = String::new();
        for i in 0..16 {
            if i == 8 { hex_part.push(' '); }
            if i < chunk.len() {
                hex_part.push_str(&format!("{:02x} ", chunk[i]));
            } else {
                hex_part.push_str("   ");
            }
        }

        let ascii_part: String = chunk.iter().map(|&b| {
            if (32..=126).contains(&b) { b as char } else { '·' }
        }).collect();

        lines.push(format!(
            "  {:04x}  {}  {}{}  {}",
            chunk_idx,
            "│".bright_black(),
            hex_part.bright_cyan(),
            "│".bright_black(),
            ascii_part.bright_green()
        ));
    }
    lines
}

// ── Proto badge coloring ─────────────────────────────────────────────────────

fn proto_color(p: &str) -> colored::ColoredString {
    match p {
        "TCP"  => p.bright_cyan().bold(),
        "UDP"  => p.blue().bold(),
        "TLS"  => p.bright_magenta().bold(),
        "DNS"  => p.bright_yellow().bold(),
        "HTTP" => p.bright_green().bold(),
        "ARP"  => p.yellow(),
        "ICMP" | "ICMP6" => p.bright_red().bold(),
        other  => other.white(),
    }
}

fn proto_badge_color(p: &str) -> colored::ColoredString {
    // padded to 4 chars for alignment
    let label = format!("{:<4}", p);
    match p {
        "TCP"  => label.bright_cyan().bold(),
        "UDP"  => label.blue().bold(),
        "TLS"  => label.bright_magenta().bold(),
        "DNS"  => label.bright_yellow().bold(),
        "HTTP" => label.bright_green().bold(),
        "ARP"  => label.yellow(),
        _      => label.white(),
    }
}

// ── Bar chart helper ─────────────────────────────────────────────────────────

fn render_bar(count: usize, max: usize, bar_width: usize) -> String {
    let filled = if max == 0 { 0 } else { (count * bar_width) / max };
    let empty  = bar_width - filled;
    format!(
        "{}{}",
        "█".repeat(filled).bright_cyan(),
        "░".repeat(empty).bright_black()
    )
}

// ── Section label ────────────────────────────────────────────────────────────

fn section_label(title: &str) -> String {
    format!("  ◆ {}", title.bright_cyan().bold())
}

// ── MAIN TUI DRAW ────────────────────────────────────────────────────────────

fn draw_tui(state: &UiState, start_time: std::time::Instant) {
    let mut buf = String::new();
    let dim = |s: &str| s.bright_black().to_string();

    // ── TOP BORDER ────────────────────────────────────────────────────────────
    buf.push_str(&format!("{}\n", dim(&top_border())));

    // ── TITLE ROW ────────────────────────────────────────────────────────────
    let title_left  = format!("  {} {} {}",
        "◈".bright_cyan(),
        " NETZER".bright_cyan().bold(),
        "Deep Packet Analyzer".white()
    );
    let title_right = "● LIVE ".bright_green().bold().to_string()
        + &"MONITORING ACTIVE".bright_green().to_string();
    let title_padding = W_TOTAL.saturating_sub(visible_width(&title_left) + visible_width(&title_right));
    buf.push_str(&format!("│ {}{}{} │\n",
        title_left,
        " ".repeat(title_padding),
        title_right
    ));

    // ── META ROW ─────────────────────────────────────────────────────────────
    let elapsed = start_time.elapsed().as_secs();
    let uptime  = format!("{:02}:{:02}:{:02}", elapsed/3600, (elapsed%3600)/60, elapsed%60);
    let rate    = state.rates.last().cloned().unwrap_or(0);

    let meta = format!(
        "  {} {}   {} {}   {} {}   {} {}   {} {} pkt/s",
        "⬡".bright_black(), format!("iface:{}", state.interface).bright_yellow(),
        "⬡".bright_black(), format!("up:{}", uptime).bright_green(),
        "⬡".bright_black(), format!("rx:{}", format_bytes(state.total_bytes)).bright_magenta(),
        "⬡".bright_black(), format!("pkts:{}", state.total_packets).bright_blue(),
        "⬡".bright_black(), rate.to_string().bright_cyan()
    );
    buf.push_str(&format!("{}\n", row_full(&meta)));

    // ── SPLIT HEADER ─────────────────────────────────────────────────────────
    buf.push_str(&format!("{}\n", dim(&mid_split_top())));

    // Section labels row
    let lbl_left  = section_label("LIVE FEED");
    let lbl_right = section_label("METRICS");
    buf.push_str(&format!("{}\n", row_split(&lbl_left, &lbl_right)));

    // Column headers row
    let col_left = format!("  {} {} {} {} {}",
        format!("{:<12}", "TIME").bright_black().bold(),
        "·".bright_black(),
        format!("{:<5}", "PROTO").bright_black().bold(),
        "·".bright_black(),
        format!("{:<18}  {:<18}  {:<5}", "SOURCE", "DEST", "SIZE").bright_black().bold(),
    );
    let col_right = format!("  {} {} {}",
        format!("{:<4}", "PROTO").bright_black().bold(),
        "·".bright_black(),
        format!("{:<22}  PKTS", "SHARE").bright_black().bold()
    );
    buf.push_str(&format!("{}\n", dim(&mid_split_mid())));
    buf.push_str(&format!("{}\n", row_split(&col_left, &col_right)));
    buf.push_str(&format!("{}\n", dim(&mid_split_mid())));

    // ── BODY ROWS (12 packet lines + right panel) ─────────────────────────────
    let protos    = ["TCP", "UDP", "TLS", "DNS", "HTTP", "ARP"];
    let max_count = state.proto_counts.values().max().cloned().unwrap_or(1).max(1);

    // pre-sort IPs once
    let mut ip_list: Vec<(&String, &usize)> = state.ip_stats.iter().collect();
    ip_list.sort_by(|a, b| b.1.cmp(a.1));

    for i in 0..12 {
        // LEFT — packet row
        let left = if i < state.packets.len() {
            let pkt = &state.packets[i];
            let src = truncate(&pkt.src, 18);
            let dst = truncate(&pkt.dst, 18);
            let sz  = if pkt.size >= 1024 {
                format!("{:.1}K", pkt.size as f64 / 1024.0)
            } else {
                format!("{}B", pkt.size)
            };

            format!(
                "  {} {} {} {} {}  {}  {}",
                format!("{:<12}", pkt.timestamp).bright_black(),
                "│".bright_black(),
                format!("{:<5}", pkt.proto).pipe(|s| proto_color(&pkt.proto)),
                "│".bright_black(),
                format!("{:<18}", src).bright_green(),
                format!("{:<18}", dst).truecolor(255, 100, 100),
                format!("{:<5}", sz).bright_yellow()
            )
        } else {
            format!("  {}", "·".repeat(56).bright_black())
        };

        // RIGHT — metrics panel
        let right = match i {
            // Protocol bars (0-5)
            0..=5 => {
                let p     = protos[i];
                let count = state.proto_counts.get(p).cloned().unwrap_or(0);
                let bar   = render_bar(count, max_count, 16);
                let pct   = if max_count > 0 { (count * 100) / max_count } else { 0 };
                format!("  {}  {}  {:<6} {:>3}%",
                    proto_badge_color(p),
                    bar,
                    count.to_string().bright_white(),
                    pct.to_string().bright_black()
                )
            }
            // Blank separator
            6 => String::new(),
            // Top IPs header
            7 => format!("  {} {}", "▸".bright_cyan(), "TOP TARGETS".bright_cyan().bold()),
            // Top 3 IPs (rows 8-10)
            8..=10 => {
                let idx = i - 8;
                if idx < ip_list.len() {
                    let (ip, count) = ip_list[idx];
                    let bar_w = 8usize;
                    let filled = if state.total_packets > 0 {
                        (count * bar_w) / state.total_packets
                    } else { 0 };
                    let bar = format!("{}{}",
                        "█".repeat(filled.min(bar_w)).truecolor(0, 200, 180),
                        "░".repeat(bar_w - filled.min(bar_w)).bright_black()
                    );
                    let pct = if state.total_packets > 0 { (count * 100) / state.total_packets } else { 0 };
                    format!("  {} {}  {} {:>3}%",
                        format!("{}.", idx+1).bright_black(),
                        format!("{:<22}", truncate(ip, 22)).truecolor(0, 200, 180),
                        bar,
                        pct
                    )
                } else {
                    format!("  {}. {}", i - 7, "—".bright_black())
                }
            }
            // Sparkline
            11 => {
                let max_r = state.rates.iter().max().cloned().unwrap_or(1).max(1);
                let spark: String = state.rates.iter().map(|&r| get_sparkline_char(r, max_r)).collect();
                format!("  {} {}  max {}",
                    "▸".bright_cyan(),
                    spark.bright_cyan().bold(),
                    format!("{} p/s", max_r).bright_yellow()
                )
            }
            _ => String::new(),
        };

        buf.push_str(&format!("{}\n", row_split(&left, &right)));
    }

    // ── HEX INSPECTOR ────────────────────────────────────────────────────────
    buf.push_str(&format!("{}\n", dim(&mid_split_bot())));
    let hex_hdr = format!("  {} {}  {}",
        "◈".bright_cyan(),
        "PAYLOAD INSPECTOR".bright_cyan().bold(),
        "— last captured packet".bright_black()
    );
    buf.push_str(&format!("{}\n", row_full(&hex_hdr)));
    buf.push_str(&format!("{}\n", dim(&mid_full())));

    let hex_lines = state.packets.first()
        .map(|p| format_inspector_hex(&p.payload))
        .unwrap_or_default();

    for i in 0..6 {
        let line = if i < hex_lines.len() {
            hex_lines[i].clone()
        } else if hex_lines.is_empty() && i == 2 {
            format!("  {}",
                "waiting for packet traffic …".truecolor(80, 80, 80)
            )
        } else {
            String::new()
        };
        buf.push_str(&format!("{}\n", row_full(&line)));
    }

    // ── BOTTOM BORDER ─────────────────────────────────────────────────────────
    buf.push_str(&format!("{}\n", dim(&bot_border())));

    // ── FLUSH ─────────────────────────────────────────────────────────────────
    print!("\x1B[H{}", buf);
    let _ = std::io::stdout().flush();
}

// ── STATIC BANNER (--no-tui mode) ────────────────────────────────────────────

fn print_banner(interface: &str) {
    // Compact single-line ASCII wordmark — no huge block-art
    println!();
    println!("  {}  {}",
        "╔═╗ ╔╗╔ ╔═╗ ╔╦╗ ╔═╗ ╦═╗".truecolor(0, 200, 255).bold(),
        "v0.1.0-alpha".truecolor(80, 80, 80)
    );
    println!("  {}  {}",
        "║ ║ ║║║ ║╣  ║  ╔═╝ ╠╦╝".truecolor(0, 160, 220).bold(),
        "high-performance zero-copy network analyzer".truecolor(80, 80, 80).italic()
    );
    println!("  {}",
        "╚═╝ ╝╚╝ ╚═╝ ╩  ╚═╝ ╩╚═".truecolor(0, 120, 180).bold()
    );
    println!();
    println!("  {} {:<10}  {} {}",
        "◈ interface".truecolor(80, 80, 80),
        interface.bright_yellow().bold(),
        "◈ mode".truecolor(80, 80, 80),
        "classic log".truecolor(80, 80, 80)
    );
    println!("  {}", "─".repeat(110).truecolor(40, 40, 40));
    println!(
        "  {} · {} · {} · {} · {} · {}",
        format!("{:<14}", "TIMESTAMP").truecolor(80, 80, 80).bold(),
        format!("{:<5}", "PROTO").truecolor(80, 80, 80).bold(),
        format!("{:<21}", "SOURCE").truecolor(80, 80, 80).bold(),
        format!("{:<21}", "DESTINATION").truecolor(80, 80, 80).bold(),
        format!("{:<35}", "INFO / DOMAIN").truecolor(80, 80, 80).bold(),
        format!("{:<6}", "SIZE").truecolor(80, 80, 80).bold()
    );
    println!("  {}", "─".repeat(110).truecolor(40, 40, 40));
}

// ── Trait helper for method-chaining proto_color ─────────────────────────────
// (avoids a borrow issue in the format! macro)
trait Pipe: Sized {
    fn pipe<F, R>(self, f: F) -> R where F: FnOnce(Self) -> R { f(self) }
}
impl Pipe for String {}

fn handle_tcp(
    src_ip: &str,
    dst_ip: &str,
    payload: &[u8],
    time_str: &str,
    size: usize,
    json_writer: &mut Option<JsonWriter>,
    web_server: &Option<WebServer>,
    raw_hex: &str,
    ui_state: &Option<Arc<Mutex<UiState>>>,
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
        let payload_str = String::from_utf8_lossy(tcp_payload);
        let trimmed = payload_str.trim_start();
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
        }
    }
    
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

    // UI state OR simple logging
    let proto_log = if is_tls { "TLS" } else if is_http { "HTTP" } else { "TCP" };
    if let Some(state_mutex) = ui_state {
        if let Ok(mut state) = state_mutex.lock() {
            state.total_packets += 1;
            state.total_bytes += size;
            state.packets_this_sec += 1;
            *state.proto_counts.entry(proto_log.to_string()).or_insert(0) += 1;
            *state.ip_stats.entry(dst.clone()).or_insert(0) += 1;
            
            state.packets.insert(0, PacketInfo {
                timestamp: time_str.to_string(),
                proto: proto_log.to_string(),
                src: src.clone(),
                dst: dst.clone(),
                info: info_raw.to_string(),
                size,
                payload: payload.to_vec(),
            });
            state.packets.truncate(100);
        }
    } else {
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
    ui_state: &Option<Arc<Mutex<UiState>>>,
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

    // UI state OR simple logging
    let proto_log = if is_dns { "DNS" } else { "UDP" };
    if let Some(state_mutex) = ui_state {
        if let Ok(mut state) = state_mutex.lock() {
            state.total_packets += 1;
            state.total_bytes += size;
            state.packets_this_sec += 1;
            *state.proto_counts.entry(proto_log.to_string()).or_insert(0) += 1;
            *state.ip_stats.entry(dst.clone()).or_insert(0) += 1;
            
            state.packets.insert(0, PacketInfo {
                timestamp: time_str.to_string(),
                proto: proto_log.to_string(),
                src: src.clone(),
                dst: dst.clone(),
                info: info_raw.to_string(),
                size,
                payload: payload.to_vec(),
            });
            state.packets.truncate(100);
        }
    } else {
        let proto_colored = format!("{:<5}", "UDP").bright_blue().bold();
        let info_colored = if is_dns {
            format!("{:<35}", info_raw).bright_yellow().bold().to_string()
        } else {
            format!("{:<35}", info_raw).bright_black().to_string()
        };
        
        print_packet_line(time_str, proto_colored, &src, &dst, &info_colored, size);
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
    ui_state: &Option<Arc<Mutex<UiState>>>,
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

    // UI state OR simple logging
    if let Some(state_mutex) = ui_state {
        if let Ok(mut state) = state_mutex.lock() {
            state.total_packets += 1;
            state.total_bytes += size;
            state.packets_this_sec += 1;
            *state.proto_counts.entry("ICMP".to_string()).or_insert(0) += 1;
            *state.ip_stats.entry(dst_ip.to_string()).or_insert(0) += 1;
            
            state.packets.insert(0, PacketInfo {
                timestamp: time_str.to_string(),
                proto: "ICMP".to_string(),
                src: src_ip.to_string(),
                dst: dst_ip.to_string(),
                info: info_raw.clone(),
                size,
                payload: payload.to_vec(),
            });
            state.packets.truncate(100);
        }
    } else {
        let proto_colored = format!("{:<5}", "ICMP").bright_red().bold();
        let info_colored = format!("{:<35}", info_raw).bright_red().to_string();
        
        print_packet_line(time_str, proto_colored, src_ip, dst_ip, &info_colored, size);
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
    ui_state: &Option<Arc<Mutex<UiState>>>,
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

    // UI state OR simple logging
    if let Some(state_mutex) = ui_state {
        if let Ok(mut state) = state_mutex.lock() {
            state.total_packets += 1;
            state.total_bytes += size;
            state.packets_this_sec += 1;
            *state.proto_counts.entry("ICMP6".to_string()).or_insert(0) += 1;
            *state.ip_stats.entry(dst_ip.to_string()).or_insert(0) += 1;
            
            state.packets.insert(0, PacketInfo {
                timestamp: time_str.to_string(),
                proto: "ICMP6".to_string(),
                src: src_ip.to_string(),
                dst: dst_ip.to_string(),
                info: info_raw.clone(),
                size,
                payload: payload.to_vec(),
            });
            state.packets.truncate(100);
        }
    } else {
        let proto_colored = format!("{:<5}", "ICMP6").bright_red().bold();
        let info_colored = format!("{:<35}", info_raw).bright_red().to_string();
        
        print_packet_line(time_str, proto_colored, src_ip, dst_ip, &info_colored, size);
    }
}

fn handle_arp(
    payload: &[u8],
    time_str: &str,
    size: usize,
    json_writer: &mut Option<JsonWriter>,
    web_server: &Option<WebServer>,
    raw_hex: &str,
    ui_state: &Option<Arc<Mutex<UiState>>>,
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

    // UI state OR simple logging
    if let Some(state_mutex) = ui_state {
        if let Ok(mut state) = state_mutex.lock() {
            state.total_packets += 1;
            state.total_bytes += size;
            state.packets_this_sec += 1;
            *state.proto_counts.entry("ARP".to_string()).or_insert(0) += 1;
            
            state.packets.insert(0, PacketInfo {
                timestamp: time_str.to_string(),
                proto: "ARP".to_string(),
                src: src.clone(),
                dst: dst.clone(),
                info: info_raw.clone(),
                size,
                payload: payload.to_vec(),
            });
            state.packets.truncate(100);
        }
    } else {
        let proto_colored = format!("{:<5}", "ARP").bright_yellow().bold();
        let info_colored = format!("{:<35}", truncate(&info_raw, 35)).bright_yellow().to_string();
        
        print_packet_line(time_str, proto_colored, &src, &dst, &info_colored, size);
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
    ui_state: &Option<Arc<Mutex<UiState>>>,
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
                        handle_tcp(&src_ip, &dst_ip, ip_payload, &time_str, size, json_writer, web_server, &raw_hex, ui_state);
                    } else {
                        handle_tcp(&src_ip, &dst_ip, ip_payload, &time_str, size, json_writer, web_server, &raw_hex, ui_state);
                    }
                }
                17 => handle_udp(&src_ip, &dst_ip, ip_payload, &time_str, size, json_writer, web_server, &raw_hex, ui_state),
                1 => handle_icmp(&src_ip, &dst_ip, ip_payload, &time_str, size, json_writer, web_server, &raw_hex, ui_state),
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
                6 => handle_tcp(&src_ip, &dst_ip, ip_payload, &time_str, size, json_writer, web_server, &raw_hex, ui_state),
                17 => handle_udp(&src_ip, &dst_ip, ip_payload, &time_str, size, json_writer, web_server, &raw_hex, ui_state),
                58 => handle_icmpv6(&src_ip, &dst_ip, ip_payload, &time_str, size, json_writer, web_server, &raw_hex, ui_state),
                _ => {}
            }
        }
        EtherType::Arp => {
            handle_arp(payload, &time_str, size, json_writer, web_server, &raw_hex, ui_state);
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

    // Auto-detect interactive TUI mode
    let is_tui_active = !args.no_tui && std::io::stdout().is_terminal();
    let ui_state: Option<Arc<Mutex<UiState>>> = if is_tui_active {
        let state = Arc::new(Mutex::new(UiState {
            packets: Vec::new(),
            total_packets: 0,
            total_bytes: 0,
            proto_counts: std::collections::HashMap::new(),
            ip_stats: std::collections::HashMap::new(),
            rates: vec![0; 20],
            packets_this_sec: 0,
            interface: args.interface.clone(),
        }));

        // Clear screen and hide cursor at TUI boot
        print!("\x1B[2J\x1B[H");
        let _ = std::io::stdout().flush();

        // Spawn background TUI rendering thread
        let state_clone = state.clone();
        std::thread::spawn(move || {
            let start_time = std::time::Instant::now();
            let mut last_sparkline_update = std::time::Instant::now();
            loop {
                std::thread::sleep(std::time::Duration::from_millis(200));

                if let Ok(mut lock) = state_clone.lock() {
                    if last_sparkline_update.elapsed() >= std::time::Duration::from_secs(1) {
                        let pts = lock.packets_this_sec;
                        lock.rates.push(pts);
                        if lock.rates.len() > 20 {
                            lock.rates.remove(0);
                        }
                        lock.packets_this_sec = 0;
                        last_sparkline_update = std::time::Instant::now();
                    }
                }

                if let Ok(lock) = state_clone.lock() {
                    draw_tui(&lock, start_time);
                }
            }
        });

        Some(state)
    } else {
        None
    };

    if !is_tui_active {
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
                    &ui_state,
                );
            }) {
                if !is_tui_active {
                    eprintln!(" [SYSTEM] Ring buffer read error: {}", e);
                }
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
                        &ui_state,
                    );
                }
                Err(e) => {
                    if !is_tui_active {
                        eprintln!(" [SYSTEM] READ ERROR: {}", e);
                    }
                }
            }
        }
    }
}
