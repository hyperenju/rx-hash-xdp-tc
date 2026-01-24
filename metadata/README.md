# Overview
This eBPF program checks whether the hashes from `bpf_xdp_metadata_rx_hash` and `skb->hash` match.
XDP produces a hash using `bpf_xdp_metadata_rx_hash` and passes it through XDP metadata; then TC consumes the metadata and compares the hash with `skb->hash`.

The primary purpose of this program is to validate the functionality of `bpf_xdp_metadata_rx_hash` for a given driver.

# Sample output
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

# Notes
Only drivers/NICs that support XDP metadata and `bpf_xdp_metadata_rx_hash` can use this eBPF program, since it uses XDP metadata to pass data from XDP to a TC program.
