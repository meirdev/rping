use std::str::FromStr;

use inquire::Confirm;
use inquire::CustomType;
use inquire::InquireError;
use inquire::MultiSelect;
use inquire::Select;
use inquire::Text;
use inquire::validator::Validation;

use crate::ip::Ip;
use crate::range::Range;

const TCP: &str = "TCP";
const UDP: &str = "UDP";
const ICMP: &str = "ICMP";
const RAW: &str = "Raw IP (custom protocol number)";

const TCP_FLAGS: [(&str, &str); 6] = [
    ("SYN", "--syn"),
    ("ACK", "--ack"),
    ("FIN", "--fin"),
    ("RST", "--rst"),
    ("PSH", "--psh"),
    ("URG", "--urg"),
];

fn handle<T>(result: Result<T, InquireError>) -> T {
    match result {
        Ok(value) => value,
        Err(InquireError::OperationCanceled | InquireError::OperationInterrupted) => {
            std::process::exit(0)
        }
        Err(e) => {
            eprintln!("UI error: {e}");
            std::process::exit(1);
        }
    }
}

fn optional<T: FromStr>(message: &str, help: &str) -> Option<String> {
    let value = handle(
        Text::new(message)
            .with_help_message(help)
            .with_validator(|s: &str| {
                Ok(if s.trim().is_empty() || T::from_str(s.trim()).is_ok() {
                    Validation::Valid
                } else {
                    Validation::Invalid("Invalid value".into())
                })
            })
            .prompt(),
    );
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn ip_prompt(message: &str, help: &str, ipv4_only: bool) -> Option<String> {
    let value = handle(
        Text::new(message)
            .with_help_message(help)
            .with_validator(move |s: &str| {
                Ok(match s.trim() {
                    "" => Validation::Valid,
                    s => match Ip::from_str(s) {
                        Ok(ip) if ipv4_only && ip.is_v6() => {
                            Validation::Invalid("ICMP supports IPv4 only".into())
                        }
                        Ok(_) => Validation::Valid,
                        Err(_) => Validation::Invalid("Invalid value".into()),
                    },
                })
            })
            .prompt(),
    );
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn duration(message: &str, default: &str, help: &str) -> String {
    handle(
        Text::new(message)
            .with_default(default)
            .with_help_message(help)
            .with_validator(|s: &str| {
                Ok(match duration_str::parse(s.trim()) {
                    Ok(_) => Validation::Valid,
                    Err(_) => Validation::Invalid("Invalid duration (e.g. 100ms, 1s, 1m)".into()),
                })
            })
            .prompt(),
    )
    .trim()
    .to_string()
}

fn push(argv: &mut Vec<String>, flag: &str, value: Option<String>) {
    if let Some(value) = value {
        argv.push(flag.to_string());
        argv.push(value);
    }
}

pub fn run() -> Vec<String> {
    let mut argv = vec!["rping".to_string()];

    let protocol = handle(Select::new("Protocol:", vec![TCP, UDP, ICMP, RAW]).prompt());

    let ip_help =
        "IP, network, or range (e.g.: 10.0.1.15, 10.0.0.0/8, 10.0.1.3-10.0.2.6). Empty = random";
    let dst_ip = ip_prompt("Destination IP:", ip_help, protocol == ICMP);
    let src_ip = ip_prompt("Source IP:", ip_help, protocol == ICMP);
    let ipv6 = [&dst_ip, &src_ip]
        .into_iter()
        .flatten()
        .any(|ip| Ip::from_str(ip).is_ok_and(|ip| ip.is_v6()));
    push(&mut argv, "--dst-ip", dst_ip);
    push(&mut argv, "--src-ip", src_ip);

    match protocol {
        TCP | UDP => {
            argv.push(if protocol == TCP { "--tcp" } else { "--udp" }.to_string());
            let port_help = "Port or range (e.g.: 80, 1000-2000). Empty = random";
            push(
                &mut argv,
                "--dst-port",
                optional::<Range<u16>>("Destination port:", port_help),
            );
            push(
                &mut argv,
                "--src-port",
                optional::<Range<u16>>("Source port:", port_help),
            );
        }
        ICMP => argv.push("--icmp".to_string()),
        _ => {
            let proto = handle(
                CustomType::<u8>::new("IP protocol number:")
                    .with_help_message("0-255 (e.g.: 47 for GRE)")
                    .with_error_message("Must be a number between 0 and 255")
                    .prompt(),
            );
            argv.push("--proto".to_string());
            argv.push(proto.to_string());
        }
    }

    if protocol == TCP {
        let labels: Vec<&str> = TCP_FLAGS.iter().map(|(label, _)| *label).collect();
        let selected = handle(
            MultiSelect::new("TCP flags:", labels)
                .with_default(&[0])
                .with_help_message("Space to toggle, Enter to confirm")
                .prompt(),
        );
        for (label, flag) in TCP_FLAGS {
            if selected.contains(&label) {
                argv.push(flag.to_string());
            }
        }

        let window = handle(
            CustomType::<u16>::new("TCP window size:")
                .with_default(64)
                .prompt(),
        );
        if window != 64 {
            push(&mut argv, "--window", Some(window.to_string()));
        }
    }

    if protocol == ICMP {
        let icmp_type = handle(CustomType::<u8>::new("ICMP type:").with_default(8).prompt());
        let icmp_code = handle(CustomType::<u8>::new("ICMP code:").with_default(0).prompt());
        if icmp_type != 8 {
            push(&mut argv, "--icmptype", Some(icmp_type.to_string()));
        }
        if icmp_code != 0 {
            push(&mut argv, "--icmpcode", Some(icmp_code.to_string()));
        }
    }

    if protocol == UDP
        && !ipv6
        && handle(
            Confirm::new("Skip UDP checksum?")
                .with_default(false)
                .prompt(),
        )
    {
        argv.push("--no-checksum".to_string());
    }

    push(
        &mut argv,
        "--data",
        optional::<Range<u16>>(
            "Payload size in bytes:",
            "Size or range (e.g.: 100, 200-300). Empty = no payload",
        ),
    );

    let flood = "Flood (as fast as possible)";
    let rate = handle(Select::new("Send rate:", vec!["Fixed interval", flood]).prompt());
    if rate == flood {
        argv.push("--flood".to_string());
    } else {
        let interval = duration("Interval between packets:", "100ms", "e.g.: 100ms, 1s");
        if interval != "100ms" {
            push(&mut argv, "--interval", Some(interval));
        }
    }

    let (count, time, never) = ("Packet count", "Duration", "Never (Ctrl+C to stop)");
    match handle(Select::new("Stop after:", vec![count, time, never]).prompt()) {
        s if s == count => {
            let n = handle(CustomType::<u32>::new("Number of packets:").prompt());
            push(&mut argv, "--count", Some(n.to_string()));
        }
        s if s == time => {
            let d = duration("Duration:", "10s", "e.g.: 10s, 1m, 1h");
            push(&mut argv, "--duration", Some(d));
        }
        _ => {}
    }

    push(
        &mut argv,
        "--interface",
        optional::<String>("Network interface:", "Empty = default"),
    );

    if let Ok(command) = shlex::try_join(argv.iter().map(String::as_str)) {
        println!("\nEquivalent command:\n  {command}\n");
    }

    if !handle(Confirm::new("Start sending?").with_default(true).prompt()) {
        std::process::exit(0);
    }

    argv
}
