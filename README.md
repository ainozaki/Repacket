## Xapture
This is a packet capture using XDP.

### Usage

```
usage: xapture [mode] [options] ... 
mode:
  -N/A               Run packet capture.
  -g, --gen          Generate XDP program. (string)
  -d, --detach       Detach XDP program.

options:
  -i, --interface    Specify interface. (string [=eth1])
  -b  --bpf          BPF filepath. (string [=xdp-generated.o])
  -p, --pcap         Save to pcap file.
  -h, --help         Print usage.
```

### How to use
#### Setup and build
```
git clone https://github.com/ainnooo/MocTok.git
cd MocTok
./setup.sh
make
```

#### Conigure
Xapture can use multiple filter. See Configuration section.

#### Generate xdp prog and run
```
./xapture --gen
make xdp
./xapture -i veth1 

./xapture --detach	// Stop filtering.
```

### Configuration
To filter packets, create `xilter.yaml`. 
The higher-written filter will be given higher priority.

```
 - action: pass
   ip_protocol: icmp
 - action: drop
   tcp_dest: 22
	 tcp_syn: on
```

Filtering rules are specified using following parameter.

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


## Xilter
Originally, this repository was a packet filter using XDP.

### Respectful Implementation
[facebookincubator/katran](https://github.com/facebookincubator/katran)  
[linux/samples/bpf](https://github.com/torvalds/linux/tree/master/samples/bpf)  
[xdp-project/xdp-tutorial](https://github.com/xdp-project/xdp-tutorial)  
[takehaya/Vinbero](https://github.com/takehaya/Vinbero)  


### Libs
[tanakh/cmdline](https://github.com/tanakh/cmdline)  
[jbeder/yaml-cpp](https://github.com/jbeder/yaml-cpp)  
