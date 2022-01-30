## Xapture
Xapture = XDP + Packet Capture.
This is a tool to play with packets!
Xapture can
- dump packets. (BASIC)
- rewrite packets. (REWRITE)
- drop packets. (DROP)

### Usage

```
usage: xapture [mode] [options] ... 
	BASIC:   xapture [-c count][-f][-i interface][-w file][-x][expression]
	REWRITE: xapture -r if [expression] then [expression]
	         xapture -r if [expression] then [expression]
	DROP: xapture -d [expression]

optional:
  -g, --gen          Only generating XDP program.
  -a, --attach       Attach your XDP program.
  -z, --detach       Detach XDP program.
  -h, --help         Print usage.
```


### Installation
Xapture uses `libbpf` and `clang` inside.
```
git clone https://github.com/ainozaki/xapture.git
cd xapture
./setup.sh
xapture -i eth1
```

### Parameters
Filtering rules (shown as [expression] in `Usage`) are specified using following parameter.

| **Parameter**  | **Example**  | **Explanation**                                                                             | **Test** |
|----------------|--------------|---------------------------------------------------------------------------------------------|----------|
| action         | pass         | Action to apply to the filtered packets. [pass/drop]                                        |          |
|                |              |                                                                                             |          |
| pps            |              |                                                                                             |          |
| bps            |              |                                                                                             |          |
|                |              |                                                                                             |          |
| ip_protocol    | tcp          | Protocol name. [tcp/udp/icmp]                                                               | o        |
| ip_saddr       | 192.0.2.100  | Source address.                                                                             | o        |
| ip_daddr       | 192.0.2.100  | Destination address.                                                                        |          |
| ip_tos         | 0x00         | Type of Service. Please use hex prefix.                                                     | o        |
| ip_ttl_min     | 10           | Min value of Time To Live.                                                                  | o        |
| ip_ttl_max     | 64           | Max value of Time To Live.                                                                  | o        |
| ip_tot_len_min | 64           | Min value of Total Length. Between 46-1500(Byte).                                           | o        |
| ip_tot_len_max | 256          | Max value of Total Length. Between 46-1500(Byte).                                           | o        |
|                |              |                                                                                             |          |
| icmp_type      | echo-request | Icmp type. [echo-reply / destination-unreachable / redirect / echo-request / time-exceeded] | o        |
| icmp_code      | 0            | Icmp code.                                                                                  | o        |
|                |              |                                                                                             |          |
| tcp_src        | 22           | Source port.                                                                                | o        |
| tcp_dst        | 22           | Destination port.                                                                           | o        |
| tcp_urg        | on           | URG flag. [on / off]                                                                        | o        |
| tcp_ack        | on           | ACK flag. [on / off]                                                                        | o        |
| tcp_psh        | on           | PSH flag. [on / off]                                                                        | o        |
| tcp_rst        | on           | RST flag. [on / off]                                                                        | o        |
| tcp_syn        | on           | SYN flag. [on / off]                                                                        | o        |
| tcp_fin        | on           | FIN flag. [on / off]                                                                        | o        |
|                |              |                                                                                             |          |
| udp_src        | 22           | Source port.                                                                                | o        |
| udp_dst        | 22           | Destination port.                                                                           | o        |


### Respectful Implementation
[facebookincubator/katran](https://github.com/facebookincubator/katran)  
[linux/samples/bpf](https://github.com/torvalds/linux/tree/master/samples/bpf)  
[xdp-project/xdp-tutorial](https://github.com/xdp-project/xdp-tutorial)  
[takehaya/Vinbero](https://github.com/takehaya/Vinbero)  
