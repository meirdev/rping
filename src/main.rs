use std::io::Write;
use std::io::stderr;
use std::io::stdout;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use bytesize::ByteSize;
use clap::Parser;
use crossterm::cursor::MoveToColumn;
use crossterm::execute;
use crossterm::style::Print;
use crossterm::terminal::Clear;
use crossterm::terminal::ClearType;
use fancy_duration::FancyDuration;
use log::debug;
use num_format::Locale;
use num_format::ToFormattedString;
use pnet::datalink;
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ip::IpNextHeaderProtocols;
use rping::cli::Cli;
use rping::packet::build_ipv4_packet;
use rping::packet::build_ipv6_packet;

fn resolve_proto(args: &Cli, ipv6: bool) -> IpNextHeaderProtocol {
    if ipv6 && args.icmp {
        eprintln!("ICMP is not supported for IPv6.");
        std::process::exit(1);
    }

    if args.tcp {
        IpNextHeaderProtocols::Tcp
    } else if args.udp {
        IpNextHeaderProtocols::Udp
    } else if args.icmp {
        IpNextHeaderProtocols::Icmp
    } else if let Some(proto) = args.proto {
        IpNextHeaderProtocol(proto)
    } else {
        eprintln!("No protocol specified. Use --tcp, --udp, or --proto.");
        std::process::exit(1);
    }
}

fn print_config(args: &Cli) {
    let proto = if args.tcp {
        "TCP"
    } else if args.udp {
        "UDP"
    } else if args.icmp {
        "ICMP"
    } else if args.rawip {
        "RAW IP"
    } else if let Some(p) = args.proto {
        &format!("proto {}", p)
    } else {
        "None"
    };

    let src_ip = args
        .src_ip
        .as_ref()
        .map(|ip| format!("{}", ip))
        .unwrap_or_else(|| "random".to_string());

    let dst_ip = args
        .dst_ip
        .as_ref()
        .map(|ip| format!("{}", ip))
        .unwrap_or_else(|| "random".to_string());

    let _ = execute!(
        stdout(),
        Print("Configuration:\n"),
        Print(format!("  {:14} {}\n", "Interface:", args.inteface)),
        Print(format!("  {:14} {}\n", "Protocol:", proto)),
        Print(format!("  {:14} {}\n", "Source IP:", src_ip)),
        Print(format!("  {:14} {}\n", "Dest IP:", dst_ip)),
    );

    if args.tcp || args.udp {
        let src_port = args
            .src_port
            .as_ref()
            .map(|p| format!("{}", p))
            .unwrap_or_else(|| "random".to_string());
        let dst_port = args
            .dst_port
            .as_ref()
            .map(|p| format!("{}", p))
            .unwrap_or_else(|| "random".to_string());

        let _ = execute!(
            stdout(),
            Print(format!("  {:14} {}\n", "Source Port:", src_port)),
            Print(format!("  {:14} {}\n", "Dest Port:", dst_port)),
        );
    }

    if args.tcp {
        let mut flags = Vec::new();
        if args.syn {
            flags.push("SYN");
        }
        if args.ack {
            flags.push("ACK");
        }
        if args.fin {
            flags.push("FIN");
        }
        if args.rst {
            flags.push("RST");
        }
        if args.psh {
            flags.push("PSH");
        }
        if args.urg {
            flags.push("URG");
        }
        if !flags.is_empty() {
            let _ = execute!(
                stdout(),
                Print(format!("  {:14} {}\n", "TCP Flags:", flags.join(", "))),
            );
        }
    }

    if args.icmp {
        let _ = execute!(
            stdout(),
            Print(format!("  {:14} {}\n", "ICMP Type:", args.icmptype)),
            Print(format!("  {:14} {}\n", "ICMP Code:", args.icmpcode)),
        );
    }

    let _ = execute!(stdout(), Print(format!("  {:14} {}\n", "TTL:", args.ttl)),);

    let data_size = args
        .data
        .as_ref()
        .map(|d| format!("{}", d))
        .unwrap_or_else(|| "0".to_string());
    let _ = execute!(
        stdout(),
        Print(format!("  {:14} {}\n", "Data Size:", data_size)),
    );

    if args.flood {
        let _ = execute!(stdout(), Print(format!("  {:14} flood\n", "Mode:")));
    } else {
        let _ = execute!(
            stdout(),
            Print(format!(
                "  {:14} {}\n",
                "Interval:",
                FancyDuration(args.interval).truncate(1)
            )),
        );
    }

    if let Some(count) = args.count {
        let _ = execute!(stdout(), Print(format!("  {:14} {}\n", "Count:", count)));
    }
    if let Some(duration) = args.duration {
        let _ = execute!(
            stdout(),
            Print(format!(
                "  {:14} {}\n",
                "Duration:",
                FancyDuration(duration).truncate(1)
            )),
        );
    }

    let _ = execute!(stdout(), Print("\n"));
}

fn print_stats<W: Write>(
    out: &mut W,
    pkt_count: u64,
    byte_count: u64,
    elapsed: Duration,
    newline: bool,
) {
    let elapsed_secs = elapsed.as_secs_f64();
    let pps = if elapsed_secs > 0.0 {
        (pkt_count as f64 / elapsed_secs) as u64
    } else {
        0
    };
    let bps = if elapsed_secs > 0.0 {
        (byte_count as f64 / elapsed_secs) as u64
    } else {
        0
    };

    let _ = execute!(
        out,
        MoveToColumn(0),
        Print(format!(
            "{} packets | {} pps | {} | {}/s | {}",
            pkt_count.to_formatted_string(&Locale::en),
            pps.to_formatted_string(&Locale::en),
            ByteSize(byte_count),
            ByteSize(bps),
            FancyDuration(Duration::from_secs(elapsed.as_secs()))
        )),
        Clear(ClearType::UntilNewLine),
    );
    if newline {
        let _ = execute!(out, Print("\n"));
    }
}

fn main() {
    env_logger::init();

    let args = Cli::parse();

    let interfaces = datalink::interfaces();
    let _interface = interfaces
        .into_iter()
        .filter(|iface| iface.name == args.inteface)
        .next()
        .or_else(|| {
            eprintln!("Interface {} not found", args.inteface);
            std::process::exit(1);
        })
        .unwrap();

    debug!("Options: {:?}", args);

    // Auto-detect the IP version from the source/destination arguments. The
    // source and destination must use the same version.
    let ipv6 = match (args.src_ip.as_ref(), args.dst_ip.as_ref()) {
        (Some(src), Some(dst)) if src.is_v6() != dst.is_v6() => {
            eprintln!("Source and destination IP must be the same version.");
            std::process::exit(1);
        }
        (src, dst) => src
            .map(|i| i.is_v6())
            .or(dst.map(|i| i.is_v6()))
            .unwrap_or(false),
    };

    let proto = resolve_proto(&args, ipv6);

    if let Some(fill_data) = args.fill_data {
        if !fill_data.is_ascii() {
            eprintln!("Fill data must be an ASCII character.");
            std::process::exit(1);
        }
    }

    print_config(&args);

    let start_time = Instant::now();

    let packets = Arc::new(AtomicU64::new(0));
    let bytes = Arc::new(AtomicU64::new(0));
    let running = Arc::new(AtomicBool::new(true));

    let packets_clone = packets.clone();
    let bytes_clone = bytes.clone();
    let running_clone = running.clone();

    ctrlc::set_handler(move || {
        running_clone.store(false, Ordering::SeqCst);
        let pkt_count = packets_clone.load(Ordering::SeqCst);
        let byte_count = bytes_clone.load(Ordering::SeqCst);
        let elapsed = start_time.elapsed();
        print_stats(&mut stdout(), pkt_count, byte_count, elapsed, true);
        std::process::exit(0);
    })
    .unwrap();

    if !args.quiet {
        let packets_display = packets.clone();
        let bytes_display = bytes.clone();
        let running_display = running.clone();

        thread::spawn(move || {
            while running_display.load(Ordering::SeqCst) {
                let pkt_count = packets_display.load(Ordering::SeqCst);
                let byte_count = bytes_display.load(Ordering::SeqCst);
                let elapsed = start_time.elapsed();
                print_stats(&mut stderr(), pkt_count, byte_count, elapsed, false);
                thread::sleep(Duration::from_millis(100));
            }
        });
    }

    if ipv6 {
        build_ipv6_packet(args, proto, &packets, &bytes);
    } else {
        build_ipv4_packet(args, proto, &packets, &bytes);
    }
}
