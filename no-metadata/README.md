# Overview
This eBPF program checks whether the hashes from `bpf_xdp_metadata_rx_hash` and `skb->hash` match.
The XDP program produces a hash using `bpf_xdp_metadata_rx_hash` and prints it. At the same time, another TC program prints `skb->hash`.

The primary purpose of this program is to validate the functionality of `bpf_xdp_metadata_rx_hash` for a given driver.

# Sample output
```
$ sudo make DEV=ens5np0 tc-load xdp-load
...
$ sudo make trace
cat /sys/kernel/tracing/trace_pipe
          <idle>-0       [002] ..s2.   150.515663: bpf_trace_printk: XDP Hash: 0x70412ca1, IPv4/TCP(25)
          <idle>-0       [002] ..s2.   150.515682: bpf_trace_printk: SKB Hash: 0x70412ca1
          <idle>-0       [000] ..s2.   151.534809: bpf_trace_printk: XDP Hash: 0x9f839300, IPv4/TCP(25)
          <idle>-0       [000] .Ns2.   151.534847: bpf_trace_printk: SKB Hash: 0x9f839300
          <idle>-0       [000] ..s2.   152.552249: bpf_trace_printk: XDP Hash: 0xf57a397c, IPv4/TCP(25)
          <idle>-0       [000] .Ns2.   152.552269: bpf_trace_printk: SKB Hash: 0xf57a397c
          <idle>-0       [000] ..s2.   153.571892: bpf_trace_printk: XDP Hash: 0x6862ccd0, IPv4/TCP(25)
          <idle>-0       [000] .Ns2.   153.571910: bpf_trace_printk: SKB Hash: 0x6862ccd0
          <idle>-0       [000] ..s2.   154.590003: bpf_trace_printk: XDP Hash: 0x32dca64f, IPv4/TCP(25)
          <idle>-0       [000] .Ns2.   154.590029: bpf_trace_printk: SKB Hash: 0x32dca64f
          <idle>-0       [000] ..s2.   155.607840: bpf_trace_printk: XDP Hash: 0x38aa8df4, IPv4/TCP(25)
          <idle>-0       [000] .Ns2.   155.607857: bpf_trace_printk: SKB Hash: 0x38aa8df4
```
