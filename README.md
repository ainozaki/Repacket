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
policy:
 - action: pass
   ip_protocol: icmp
 - action: drop
   tcp_dest: 22
```

Filtering rules are specified using following parameter.

```
action:
pps:
bps:

ip_protocol: 
ip_saddr:
ip_daddr:
ip_tos:
ip_ttl_min:
ip_ttl_max:
ip_tot_len_min:
ip_tot_len_max:

icmp_type:
icmp_code:

tcp_src:
tcp_dest:
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
