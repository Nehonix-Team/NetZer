use clap::Parser;
use netzer_core::ethernet::{EthernetFrame, EtherType};
use netzer_core::ipv4::Ipv4Header;
use netzer_core::ipv6::Ipv6Header;
use netzer_core::arp::ArpPacket;
use netzer_core::icmp::IcmpHeader;
use netzer_core::tcp::TcpHeader;
use netzer_core::udp::UdpHeader;
use netzer_core::dns::DnsQuery;
use netzer_core::tls::TlsClientHello;
use netzer_socket::socket::RawSocket;
use std::process;
use colored::{ColoredString, Colorize};
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

fn handle_tcp(src_ip: &str, dst_ip: &str, payload: &[u8], time_str: &str, size: usize) {
    let (tcp_header, tcp_payload) = match TcpHeader::parse(payload) {
        Ok(res) => res,
        Err(_) => return,
    };
    
    let src_port = tcp_header.source_port();
    let dst_port = tcp_header.destination_port();
    let src = format!("{}:{}", src_ip, src_port);
    let dst = format!("{}:{}", dst_ip, dst_port);
    let proto = format!("{:<5}", "TCP").bright_cyan().bold();
    
    let mut info = format!("{:<35}", "[ENCRYPTED]").bright_black().to_string();
    
    if dst_port == 443 {
        if let Ok(tls) = TlsClientHello::parse(tcp_payload) {
            let domain = truncate(tls.sni, 35);
            info = format!("{:<35}", domain).bright_magenta().bold().to_string();
        }
    } else if src_port == 80 || dst_port == 80 {
        info = format!("{:<35}", "[HTTP]").white().to_string();
    }
    
    print_packet_line(time_str, proto, &src, &dst, &info, size);
}

fn handle_udp(src_ip: &str, dst_ip: &str, payload: &[u8], time_str: &str, size: usize) {
    let (udp_header, udp_payload) = match UdpHeader::parse(payload) {
        Ok(res) => res,
        Err(_) => return,
    };
    
    let src_port = udp_header.source_port();
    let dst_port = udp_header.destination_port();
    let src = format!("{}:{}", src_ip, src_port);
    let dst = format!("{}:{}", dst_ip, dst_port);
    let proto = format!("{:<5}", "UDP").bright_blue().bold();
    
    let mut info = format!("{:<35}", "-").bright_black().to_string();
    
    if dst_port == 53 || src_port == 53 {
        if let Ok(dns) = DnsQuery::parse(udp_payload) {
            let domain = truncate(&dns.domain_name, 35);
            info = format!("{:<35}", format!("DNS: {}", domain)).bright_yellow().bold().to_string();
        } else {
            info = format!("{:<35}", "DNS").bright_yellow().to_string();
        }
    }
    
    print_packet_line(time_str, proto, &src, &dst, &info, size);
}

fn handle_icmp(src_ip: &str, dst_ip: &str, payload: &[u8], time_str: &str, size: usize) {
    let (icmp_header, _) = match IcmpHeader::parse(payload) {
        Ok(res) => res,
        Err(_) => return,
    };
    
    let proto = format!("{:<5}", "ICMP").bright_red().bold();
    let info_str = match icmp_header.icmp_type() {
        0 => "Echo Reply (0)".to_string(),
        3 => format!("Dest Unreachable ({})", icmp_header.code()),
        8 => "Echo Request (8)".to_string(),
        11 => "Time Exceeded".to_string(),
        t => format!("Type {}", t),
    };
    
    let info = format!("{:<35}", info_str).bright_red().to_string();
    print_packet_line(time_str, proto, src_ip, dst_ip, &info, size);
}

fn handle_icmpv6(src_ip: &str, dst_ip: &str, payload: &[u8], time_str: &str, size: usize) {
    let (icmp_header, _) = match IcmpHeader::parse(payload) {
        Ok(res) => res,
        Err(_) => return,
    };
    
    let proto = format!("{:<5}", "ICMP6").bright_red().bold();
    let info_str = match icmp_header.icmp_type() {
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
    
    let info = format!("{:<35}", info_str).bright_red().to_string();
    print_packet_line(time_str, proto, src_ip, dst_ip, &info, size);
}

fn handle_arp(payload: &[u8], time_str: &str, size: usize) {
    let arp = match ArpPacket::parse(payload) {
        Ok(res) => res,
        Err(_) => return,
    };
    
    let proto = format!("{:<5}", "ARP").bright_yellow().bold();
    
    let opcode = arp.opcode();
    let info_str = match opcode {
        1 => format!("Who has {}? Tell {}", arp.target_ip(), arp.sender_ip()),
        2 => format!("{} is at {}", arp.sender_ip(), arp.sender_mac()),
        op => format!("Opcode {}", op),
    };
    
    let info = format!("{:<35}", truncate(&info_str, 35)).bright_yellow().to_string();
    let src = format!("{}", arp.sender_mac());
    let dst = format!("{}", arp.target_mac());
    
    print_packet_line(time_str, proto, &src, &dst, &info, size);
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
                
                let now = Local::now();
                let time_str = now.format("%H:%M:%S%.3f").to_string();
                
                match eth_frame.ethertype() {
                    EtherType::Ipv4 => {
                        let (ipv4_header, ip_payload) = match Ipv4Header::parse(payload) {
                            Ok(res) => res,
                            Err(_) => continue,
                        };
                        
                        let src_ip = format!("{}", ipv4_header.source());
                        let dst_ip = format!("{}", ipv4_header.destination());
                        
                        match ipv4_header.protocol() {
                            6 => handle_tcp(&src_ip, &dst_ip, ip_payload, &time_str, size),
                            17 => handle_udp(&src_ip, &dst_ip, ip_payload, &time_str, size),
                            1 => handle_icmp(&src_ip, &dst_ip, ip_payload, &time_str, size),
                            _ => {}
                        }
                    }
                    EtherType::Ipv6 => {
                        let (ipv6_header, ip_payload) = match Ipv6Header::parse(payload) {
                            Ok(res) => res,
                            Err(_) => continue,
                        };
                        
                        let src_ip = format!("{}", ipv6_header.source());
                        let dst_ip = format!("{}", ipv6_header.destination());
                        
                        match ipv6_header.next_header() {
                            6 => handle_tcp(&src_ip, &dst_ip, ip_payload, &time_str, size),
                            17 => handle_udp(&src_ip, &dst_ip, ip_payload, &time_str, size),
                            58 => handle_icmpv6(&src_ip, &dst_ip, ip_payload, &time_str, size),
                            _ => {}
                        }
                    }
                    EtherType::Arp => {
                        handle_arp(payload, &time_str, size);
                    }
                    _ => {}
                }
            }
            Err(e) => {
                eprintln!(" [SECURITY] READ ERROR: {}", e);
            }
        }
    }
}
