# rping

A packet generation tool designed for simulating high-volume network traffic.

## Usage

```bash
sudo rping -I <interface> [OPTIONS]
```

**Note:** Requires root privileges for raw socket access.

## Examples

TCP SYN flood (send as fast as possible):

```bash
sudo rping -I eth0 --tcp -S --dst-ip 192.168.1.1 --dst-port 80 --flood
```

Send TCP packets with random source IP from a subnet:

```bash
sudo rping -I eth0 --tcp --src-ip 10.0.0.0/8 --dst-ip 192.168.1.1 --dst-port 443
```

Send UDP packets to random ports in a range:

```bash
sudo rping -I eth0 --udp --dst-ip 192.168.1.1 --dst-port 1-65535
```

Send UDP packets with random data size between 100-500 bytes:

```bash
sudo rping -I eth0 --udp --dst-ip 192.168.1.1 --dst-port 53 -d 100-500
```

### Options

| Option        | Short | Description                                     |
| ------------- | ----- | ----------------------------------------------- |
| `--inteface`  | `-I`  | Network interface to use                        |
| `--quiet`     | `-q`  | Disable real-time statistics display            |
| `--interval`  | `-i`  | Interval between packets (default: 100ms)       |
| `--flood`     |       | Send packets as fast as possible                |
| `--count`     | `-c`  | Number of packets to send                       |
| `--dst-ip`    |       | Destination IP or CIDR (e.g., 10.0.0.0/8)       |
| `--src-ip`    |       | Source IP or CIDR                               |
| `--ttl`       | `-t`  | Time to live (default: 64)                      |
| `--tcp`       |       | TCP mode                                        |
| `--udp`       |       | UDP mode                                        |
| `--icmp`      |       | ICMP mode                                       |
| `--dst-port`  |       | Destination port or range (e.g., 80, 1-1000)    |
| `--src-port`  |       | Source port or range                            |
| `--data`      | `-d`  | Data size in bytes or range                     |
| `--fill-data` |       | Fill data with specific ASCII char (default: X) |

### TCP Flags

| Option      | Short | Description                   |
| ----------- | ----- | ----------------------------- |
| `--syn`     | `-S`  | Set SYN flag                  |
| `--ack`     | `-A`  | Set ACK flag                  |
| `--fin`     | `-F`  | Set FIN flag                  |
| `--rst`     | `-R`  | Set RST flag                  |
| `--psh`     | `-P`  | Set PSH flag                  |
| `--urg`     | `-U`  | Set URG flag                  |
| `--window`  | `-w`  | TCP window size (default: 64) |
| `--seq`     |       | TCP sequence number           |
| `--ack-seq` |       | TCP acknowledgment number     |

### ICMP Options

| Option       | Short | Description                           |
| ------------ | ----- | ------------------------------------- |
| `--icmptype` | `-C`  | ICMP type (default: 8 - echo request) |
| `--icmpcode` | `-K`  | ICMP code (default: 0)                |

## Real-time Statistics

By default, rping displays real-time packet and byte counters. Use `-q` to disable for scripting:

```bash
sudo rping -I eth0 --tcp -S --dst-ip 192.168.1.1 -c 1000 -q
```
