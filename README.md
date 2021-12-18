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

 **Parameter** | **Example** | **Explanation** 
---|---|---
 action | pass | action to apply to the filtered packets. [pass/drop] 
 pps |  |  
 bps |  |  
  |  |  
 ip_protocol | tcp | protocol name. [tcp/udp/icmp] 
 ip_saddr | 192.168.10.1 | source address. 
 ip_daddr | 192.168.20.1 | destination address. 
 ip_tos | 0x03 | type of value. Please use prefix. 
 ip_ttl_min | 10 | min value of ttl. 
 ip_ttl_max | 64 | max value of ttl. 
 ip_tot_len_min | 32 | min value of total length.(byte) 
 ip_tot_len_max | 1024 | max value of total length.(byte) 
  |  |  
 icmp_type | echo-request | ICMP type. [echo-reply/unreachable/redirect/echo-request/time-exceeded] 
 icmp_code | 0 | ICMP code. 
  |  |  
 tcp_src | 10000 | source port. 
 tcp_dest | 22 | destination port. 
 tcp_urg | true | controll flag URG.  
 tcp_ack | true | controll flag ACK. 
 tcp_psh | true | controll flag PSH.
 tcp_rst | true | controll flag RST.
 tcp_syn | true | controll flag SYN.
 tcp_fin | true | controll flag FIN.
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
