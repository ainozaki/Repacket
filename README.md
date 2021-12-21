## MocTok
This is a packet filter using XDP.

### Usage

```
usage: moctok [options] ... 
options:
  -g, --gen          Generate XDP program. (string)
  -a, --attach       Attach XDP program.
  -d, --detach       Detach XDP program.
  -s, --stats        Display filtering stats.
  -i, --interface    Specify interface. (string [=eth1])
      --bpf          BPF filepath. (string [=xdp-generated.o])
      --input        Input yaml filepath. (string [=moctok.yaml])
      --output       Output filepath. (string [=xdp-generated.c])
      --sec          [Advanced option] Specify program section. (string [=xdp_generated])
  -h, --help         Print usage.
```

### Configuration
Example of `moctok.yaml`. 

```
filter:
 - action: pass
   ip_protocol: icmp
 - action: drop
   tcp_dest: 22
```

Filtering rules are specified using following parameter.

| **Parameter**  | **Example**  | **Explanation**                                                                             | **Test** |
|----------------|--------------|---------------------------------------------------------------------------------------------|----------|
| action         | pass         | Action to apply to the filtered packets. [pass/drop]                                        |          |
| pps            |              |                                                                                             |          |
| bps            |              |                                                                                             |          |
|                |              |                                                                                             |          |
| ip_protocol    | tcp          | Protocol name. [tcp/udp/icmp]                                                               | o        |
| ip_saddr       | 192.0.2.100  | Source address.                                                                             | o        |
| ip_daddr       | 192.0.2.100  | Destination address.                                                                        |          |
| ip_tos         | 0x00         | Type of Service. Please use hex prefix.                                                     | o        |
| ip_ttl_min     | 10           | Min value of Time To Live.                                                                  | o        |
| ip_ttl_max     | 64           | Max value of Time To Live.                                                                  | o        |
| ip_tot_len_min | 32           | Min value of total length.(byte)                                                            |          |
| ip_tot_len_max | 1024         | Max value of total length.(byte)                                                            |          |
|                |              |                                                                                             |          |
| icmp_type      | echo-request | Icmp type. [echo-reply / destination-unreachable / redirect / echo-request / time-exceeded] | o        |
| icmp_code      | 0            | Icmp code.                                                                                  | o        |
|                |              |                                                                                             |          |
| tcp_src        | 10000        | Source port.                                                                                |          |
| tcp_dest       | 22           | Destination port.                                                                           |          |
| tcp_urg        |              |                                                                                             |          |
| tcp_ack        |              |                                                                                             |          |
| tcp_psh        |              |                                                                                             |          |
| tcp_rst        |              |                                                                                             |          |
| tcp_syn        |              |                                                                                             |          |
| tcp_fin        |              |                                                                                             |          |
| tcp_res        |              |                                                                                             |          |
| tcp_opt        |              |                                                                                             |          |
|                |              |                                                                                             |          |
| udp_src        |              |                                                                                             |          |
| udp_dest       |              |                                                                                             |          |


### Respectful Implementation
[facebookincubator/katran](https://github.com/facebookincubator/katran)  
[linux/samples/bpf](https://github.com/torvalds/linux/tree/master/samples/bpf)  
[xdp-project/xdp-tutorial](https://github.com/xdp-project/xdp-tutorial)  
[takehaya/Vinbero](https://github.com/takehaya/Vinbero)  


### Libs
[tanakh/cmdline](https://github.com/tanakh/cmdline)  
[jbeder/yaml-cpp](https://github.com/jbeder/yaml-cpp)  
