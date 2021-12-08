## MocTok
This is a packet filter using XDP.

### Usage

```
commands:
    moctok conf     // Make configuration file.
    moctok gen      // Generate XDP program.
    moctok load     // Load.
    moctok stats    // Display filtering stats.
    
options:
    --interface, -i // Specify interface to load.
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

```
action: Action to apply to the filtered packets. [pass/drop]
pps:
bps:

ip_protocol: Protocol name. [tcp/udp/icmp]
ip_saddr: Source address. [ex.192.168.10.1]
ip_daddr: Destination address. [ex.192.168.20.1]
ip_tos: Type of value. Please use prefix. [ex.0x03]
ip_ttl_min: Min value of ttl. [ex.10]
ip_ttl_max: Max value of ttl. [ex.64]
ip_tot_len_min: Min value of total length.(byte) [ex.32]
ip_tot_len_max: Max value of total length.(byte) [ex.1024]

icmp_type: Icmp type. [echo-reply/destination-unreachable/redirect/echo-request/time-exceeded]
icmp_code: Icmp code. [ex.3]

tcp_src: Source port. [ex.10000]
tcp_dest: Destination port. [ex.22]
tcp_res:
tcp_urg:
tcp_ack:
tcp_psh:
tcp_rst:
tcp_syn:
tcp_fin:
tcp_res:
tcp_opt:

udp_src:
udp_dest:
```


### Respectful Implementation
[facebookincubator/katran](https://github.com/facebookincubator/katran)  
[linux/samples/bpf](https://github.com/torvalds/linux/tree/master/samples/bpf)  
[xdp-project/xdp-tutorial](https://github.com/xdp-project/xdp-tutorial)  
[takehaya/Vinbero](https://github.com/takehaya/Vinbero)  


### Libs
[tanakh/cmdline](https://github.com/tanakh/cmdline)  
[jbeder/yaml-cpp](https://github.com/jbeder/yaml-cpp)  
