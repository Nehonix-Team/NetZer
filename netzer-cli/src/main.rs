use clap::Parser;
use netzer_core::ethernet::{EthernetFrame, EtherType};
use netzer_core::ipv4::Ipv4Header;
use netzer_core::tcp::TcpHeader;
use netzer_socket::socket::RawSocket;
use std::process;
use colored::*;
use chrono::Local;

#[derive(Parser, Debug)]
#[command(author, version, about = "A high-performance, zero-copy network packet analyzer for Linux")]
struct Args {
    /// Network interface to capture on (e.g., eth0, wlan0, lo)
    #[arg(short, long)]
    interface: String,
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
    println!("{}", "================================================================================".bright_black());
    println!("  {} {}", "v0.1.0-alpha".bright_green(), "| High-Performance Zero-Copy Network Analyzer".italic());
    println!("  {} {}", "Listening on:".bold(), interface.bright_yellow());
    println!("{}", "================================================================================".bright_black());
    println!(
        " {:<14} │ {:<5} │ {:<21} │ {:<21} │ {:<6}",
        "TIMESTAMP".bright_black().bold(),
        "PROTO".bright_black().bold(),
        "SOURCE".bright_black().bold(),
        "DESTINATION".bright_black().bold(),
        "SIZE".bright_black().bold()
    );
    println!("{}", "────────────────┼───────┼───────────────────────┼───────────────────────┼────────".bright_black());
}

fn main() {
    let args = Args::parse();
    
    print_banner(&args.interface);
    
    let socket = match RawSocket::new(&args.interface) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("\n {} {}", "[-] ERROR:".bright_red().bold(), "Failed to open raw socket.".white());
            eprintln!("     Details: {}", e.to_string().bright_black());
            eprintln!("     Hint: NetZer requires CAP_NET_RAW. Try running with 'sudo'.\n");
            process::exit(1);
        }
    };
    
    let mut buffer = vec![0u8; 65535];
    
    loop {
        match socket.recv(&mut buffer) {
            Ok(size) => {
                let packet_data = &buffer[..size];
                
                let (eth_frame, payload) = match EthernetFrame::parse(packet_data) {
                    Ok(res) => res,
                    Err(_) => continue,
                };
                
                if eth_frame.ethertype() != EtherType::Ipv4 {
                    continue;
                }
                
                let (ipv4_header, payload) = match Ipv4Header::parse(payload) {
                    Ok(res) => res,
                    Err(_) => continue,
                };
                
                if ipv4_header.protocol() != 6 {
                    continue; // Skip non-TCP
                }
                
                let (tcp_header, _payload) = match TcpHeader::parse(payload) {
                    Ok(res) => res,
                    Err(_) => continue,
                };
                
                let now = Local::now();
                let time_str = now.format("%H:%M:%S%.3f").to_string();
                
                let src = format!("{}:{}", ipv4_header.source(), tcp_header.source_port());
                let dst = format!("{}:{}", ipv4_header.destination(), tcp_header.destination_port());
                
                // Colorized row output
                println!(
                    " {:<14} │ {:<14} │ {:<30} │ {:<30} │ {:<6}",
                    time_str.bright_black(), // Time
                    "TCP".bright_cyan().bold(), // Protocol
                    src.bright_green(), // Source
                    dst.bright_red(), // Dest
                    format!("{} B", size).bright_yellow() // Size
                );
            }
            Err(e) => {
                eprintln!(" {} {}", "[-] READ ERROR:".bright_red(), e);
            }
        }
    }
}
