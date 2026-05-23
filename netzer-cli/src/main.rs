use clap::Parser;
use netzer_core::ethernet::{EthernetFrame, EtherType};
use netzer_core::ipv4::Ipv4Header;
use netzer_core::tcp::TcpHeader;
use netzer_core::udp::UdpHeader;
use netzer_core::dns::DnsQuery;
use netzer_core::tls::TlsClientHello;
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

fn main() {
    let args = Args::parse();
    
    print_banner(&args.interface);
    
    let socket = match RawSocket::new(&args.interface) {
        Ok(s) => s,
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
    };
    
    if let Err(e) = netzer_socket::socket::drop_privileges() {
        eprintln!("\n {} {}", "[-] ERROR:".bright_red().bold(), "Failed to drop root privileges.".white());
        eprintln!("     Details: {}", e.to_string().bright_black());
        process::exit(1);
    }
    
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
                
                let now = Local::now();
                let time_str = format!("{:<14}", now.format("%H:%M:%S%.3f").to_string()).bright_black();
                let protocol = ipv4_header.protocol();
                
                let size_str = format!("{:<6}", format!("{} B", size)).bright_yellow();
                
                if protocol == 6 { // TCP
                    let (tcp_header, tcp_payload) = match TcpHeader::parse(payload) {
                        Ok(res) => res,
                        Err(_) => continue,
                    };
                    
                    let src_port = tcp_header.source_port();
                    let dst_port = tcp_header.destination_port();
                    let src = format!("{:<21}", format!("{}:{}", ipv4_header.source(), src_port)).bright_green();
                    let dst = format!("{:<21}", format!("{}:{}", ipv4_header.destination(), dst_port)).bright_red();
                    let proto = format!("{:<5}", "TCP").bright_cyan().bold();
                    
                    let mut info = format!("{:<35}", "[ENCRYPTED]").bright_black().to_string();
                    
                    // SNI Extraction
                    if dst_port == 443 {
                        if let Ok(tls) = TlsClientHello::parse(tcp_payload) {
                            let domain = truncate(tls.sni, 35);
                            info = format!("{:<35}", domain).bright_magenta().bold().to_string();
                        }
                    } else if src_port == 80 || dst_port == 80 {
                         info = format!("{:<35}", "[HTTP]").white().to_string();
                    }
                    
                    println!(" {} │ {} │ {} │ {} │ {} │ {}", time_str, proto, src, dst, info, size_str);
                    
                } else if protocol == 17 { // UDP
                    let (udp_header, udp_payload) = match UdpHeader::parse(payload) {
                        Ok(res) => res,
                        Err(_) => continue,
                    };
                    
                    let src_port = udp_header.source_port();
                    let dst_port = udp_header.destination_port();
                    let src = format!("{:<21}", format!("{}:{}", ipv4_header.source(), src_port)).bright_green();
                    let dst = format!("{:<21}", format!("{}:{}", ipv4_header.destination(), dst_port)).bright_red();
                    let proto = format!("{:<5}", "UDP").bright_blue().bold();
                    
                    let mut info = format!("{:<35}", "-").bright_black().to_string();
                    
                    // DNS Extraction
                    if dst_port == 53 || src_port == 53 {
                        if let Ok(dns) = DnsQuery::parse(udp_payload) {
                            let domain = truncate(&dns.domain_name, 35);
                            info = format!("{:<35}", format!("DNS: {}", domain)).bright_yellow().bold().to_string();
                        } else {
                            info = format!("{:<35}", "DNS").bright_yellow().to_string();
                        }
                    }
                    
                    println!(" {} │ {} │ {} │ {} │ {} │ {}", time_str, proto, src, dst, info, size_str);
                }
            }
            Err(e) => {
                eprintln!(" {} {}", "[-] READ ERROR:".bright_red(), e);
            }
        }
    }
}
