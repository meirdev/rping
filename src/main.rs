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
use rping::cli::Cli;
use rping::packet::build_ipv4_packet;

fn print_stats<W: Write>(
    out: &mut W,
    pkt_count: u64,
    byte_count: u64,
    elapsed: Duration,
    newline: bool,
) {
    let _ = execute!(
        out,
        MoveToColumn(0),
        Print(format!(
            "{} packets | {} | {}",
            pkt_count.to_formatted_string(&Locale::en),
            ByteSize(byte_count),
            FancyDuration(elapsed).truncate(1)
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

    build_ipv4_packet(args, &packets, &bytes);
}
