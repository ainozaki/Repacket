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

 **Parameter** | **Example** | **Explanation** 
---|---|---
 action | pass | Action to apply to the filtered packets. [pass/drop] 
 pps |  |  
 bps |  |  
  |  |  
 ip_protocol | tcp | Protocol name. [tcp/udp/icmp] 
 ip_saddr | 192.168.10.1 | Source address. 
 ip_daddr | 192.168.20.1 | Destination address. 
 ip_tos | 0x03 | Type of value. Please use prefix. 
 ip_ttl_min | 10 | Min value of ttl. 
 ip_ttl_max | 64 | Max value of ttl. 
 ip_tot_len_min | 32 | Min value of total length.(byte) 
 ip_tot_len_max | 1024 | Max value of total length.(byte) 
  |  |  
 icmp_type | echo-request | Icmp type. [echo-reply/destination-unreachable/redirect/echo-request/time-exceeded] 
 icmp_code | 0 | Icmp code. 
  |  |  
 tcp_src | 10000 | Source port. 
 tcp_dest | 22 | Destination port. 
 tcp_urg |  |  
 tcp_ack |  |  
 tcp_psh |  |  
 tcp_rst |  |  
 tcp_syn |  |  
 tcp_fin |  |  
 tcp_res |  |  
 tcp_opt |  |  
  |  |  
 udp_src |  |  


### Respectful Implementation
[facebookincubator/katran](https://github.com/facebookincubator/katran)  
[linux/samples/bpf](https://github.com/torvalds/linux/tree/master/samples/bpf)  
[xdp-project/xdp-tutorial](https://github.com/xdp-project/xdp-tutorial)  
[takehaya/Vinbero](https://github.com/takehaya/Vinbero)  


### Libs
[tanakh/cmdline](https://github.com/tanakh/cmdline)  
[jbeder/yaml-cpp](https://github.com/jbeder/yaml-cpp)  
