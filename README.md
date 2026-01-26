# rx-hash-xdp-tc
This eBPF program checks whether the hashes from `bpf_xdp_metadata_rx_hash` and `skb->hash` match.
XDP produces a hash using `bpf_xdp_metadata_rx_hash` and TC looks at `skb->hash` in ingress path.

When the NIC/driver supports XDP metadata, XDP passes the hash through XDP metadata, then TC consumes the metadata and compares the hash with `skb->hash`.
```
$ sudo make DEV=ens5np0 load
...
$ sudo make trace
cat /sys/kernel/tracing/trace_pipe
          <idle>-0       [002] ..s2.   944.427544: bpf_trace_printk: Hash matches. (0x968f854d == 0x968f854d)
          <idle>-0       [002] ..s2.   945.451475: bpf_trace_printk: Hash matches. (0x968f854d == 0x968f854d)
          <idle>-0       [002] ..s2.   946.475537: bpf_trace_printk: Hash matches. (0x968f854d == 0x968f854d)
          <idle>-0       [002] ..s2.   947.499423: bpf_trace_printk: Hash matches. (0x968f854d == 0x968f854d)
          <idle>-0       [000] ..s2.   948.523425: bpf_trace_printk: bpf_xdp_metadata_rx_hash: No hash found
          <idle>-0       [002] ..s2.   948.523440: bpf_trace_printk: Hash matches. (0x968f854d == 0x968f854d)
          <idle>-0       [002] ..s2.   949.547460: bpf_trace_printk: Hash matches. (0x968f854d == 0x968f854d)
          <idle>-0       [002] ..s2.   950.571481: bpf_trace_printk: Hash matches. (0x968f854d == 0x968f854d)
          <idle>-0       [000] ..s2.   950.945229: bpf_trace_printk: bpf_xdp_metadata_rx_hash: No hash found
          <idle>-0       [002] ..s2.   951.572763: bpf_trace_printk: Hash matches. (0x968f854d == 0x968f854d)
```

When the NIC/driver doesn't support XDP metadata, XDP and TC programs automatically fall back into degraded mode.
In this mode, both XDP and TC programs just print the hash value without using XDP metadata. So in this case we have to compare the hashes manually.
```
$ sudo make DEV=ens5np0 load
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

## Prerequisites
- NIC/driver that supports the following features:
    - [bpf_xdp_metadata_rx_hash](https://docs.ebpf.io/linux/kfuncs/bpf_xdp_metadata_rx_hash/)
    - (Optional) [bpf_xdp_adjust_meta](https://docs.ebpf.io/linux/helper-function/bpf_xdp_adjust_meta/) used to carry the hash in XDP metadata when supported; otherwise the program falls back to degraded mode.
