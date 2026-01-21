#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tc")
int tc_skb_hash(struct __sk_buff *skb) {
    bpf_printk("SKB Hash: 0x%08x", skb->hash);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
