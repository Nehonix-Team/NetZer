use clap::Parser;
use netzer_core::ethernet::{EthernetFrame, EtherType};
use netzer_core::ipv4::Ipv4Header;
use netzer_core::tcp::TcpHeader;
use netzer_socket::socket::RawSocket;
use std::process;

#[derive(Parser, Debug)]
#[command(author, version, about = "A high-performance, zero-copy network packet analyzer for Linux")]
struct Args {
    /// Network interface to capture on (e.g., eth0, wlan0, lo)
    #[arg(short, long)]
    interface: String,
}

fn main() {
    let args = Args::parse();
    
    println!("⚡ NetZer - Starting capture on interface: {}", args.interface);
    
    let socket = match RawSocket::new(&args.interface) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error opening raw socket: {}", e);
            eprintln!("Make sure to run with 'sudo' (requires CAP_NET_RAW).");
            process::exit(1);
        }
    };
    
    // Allocate a buffer large enough for a Jumbo frame
    let mut buffer = vec![0u8; 65535];
    
    println!("Listening for TCP packets... (Press Ctrl+C to stop)");
    
    loop {
        match socket.recv(&mut buffer) {
            Ok(size) => {
                let packet_data = &buffer[..size];
                
                // 1. Parse Ethernet
                let (eth_frame, payload) = match EthernetFrame::parse(packet_data) {
                    Ok(res) => res,
                    Err(_) => continue,
                };
                
                // Filter IPv4 only
                if eth_frame.ethertype() != EtherType::Ipv4 {
                    continue;
                }
                
                // 2. Parse IPv4
                let (ipv4_header, payload) = match Ipv4Header::parse(payload) {
                    Ok(res) => res,
                    Err(_) => continue,
                };
                
                // Filter TCP only (Protocol 6)
                if ipv4_header.protocol() != 6 {
                    continue;
                }
                
                // 3. Parse TCP
                let (tcp_header, _payload) = match TcpHeader::parse(payload) {
                    Ok(res) => res,
                    Err(_) => continue,
                };
                
                // Display output
                println!(
                    "[TCP] {}:{} -> {}:{} | Frame size: {} bytes",
                    ipv4_header.source(),
                    tcp_header.source_port(),
                    ipv4_header.destination(),
                    tcp_header.destination_port(),
                    size
                );
            }
            Err(e) => {
                eprintln!("Error receiving packet: {}", e);
            }
        }
    }
}
