# rping

A packet generation tool designed for simulating high-volume network traffic.

## Usage

```
Usage: rping [OPTIONS] --inteface <INTEFACE>

Options:
  -I, --inteface <INTEFACE>       Network interface to use
  -i, --interval <INTERVAL>       Interval between packets (e.g., 100ms, 1s) [default: 100ms]
      --flood                     Enable flood mode (send packets as fast as possible)
  -c, --count <COUNT>             Number of packets to send
      --dst-ip [<DST_IP>...]      Destination IP address or network (e.g.: 10.0.0.0/8, 10.0.1.15)
      --src-ip [<SRC_IP>...]      Source IP address or network (e.g.: 10.0.0.0/8, 10.0.1.15)
  -t, --ttl <TTL>                 Time to live (TTL) [default: 64]
      --id <ID>                   IP id
      --tcp                       TCP mode
      --udp                       UDP mode
      --rawip                     RAW IP mode
      --proto <PROTO>             Protocol number for raw IP packets (e.g., 6 for TCP, 17 for UDP)
      --dst-port [<DST_PORT>...]  Destination port or port range (e.g.: 80, 1000-2000)
      --src-port [<SRC_PORT>...]  Source port or port range (e.g.: 80, 1000-2000)
  -F, --fin                       Set FIN flag
  -S, --syn                       Set SYN flag
  -R, --rst                       Set RST flag
  -P, --psh                       Set PSH flag
  -A, --ack                       Set ACK flag
  -U, --urg                       Set URG flag
  -X, --xmas                      Set X unused flag (0x40)
  -Y, --ymas                      Set Y ununsed flag (0x80)
  -w, --window <WINDOW>           Set TCP window size [default: 64]
      --seq <SEQ>                 Set TCP sequence number
      --ack-seq <ACK_SEQ>         Set TCP acknowledgment number
  -d, --data <DATA>               Data size in bytes (e.g.: 100, 200-300)
  -h, --help                      Print help
  -V, --version                   Print version
```
