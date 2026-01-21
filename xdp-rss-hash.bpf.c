#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

enum xdp_rss_hash_type {
    DUMMY = 0,
};

extern int bpf_xdp_metadata_rx_hash(const struct xdp_md *ctx, __u32 *hash,
                                    enum xdp_rss_hash_type *rss_type) __ksym;

#define BIT(n) (1ul << (n))
#define XDP_RSS_TYPE_NONE 0
#define XDP_RSS_L3_IPV4 BIT(0)
#define XDP_RSS_L3_IPV6 BIT(1)
#define XDP_RSS_L4	 BIT(3)
#define XDP_RSS_L4_TCP BIT(4)
#define XDP_RSS_L4_UDP BIT(5)

static const char *rss_type_name(__u32 t) {
  switch (t) {
  case XDP_RSS_TYPE_NONE:
    return "NONE";
  case XDP_RSS_L3_IPV4 | XDP_RSS_L4 | XDP_RSS_L4_TCP:
    return "IPv4/TCP";
  case XDP_RSS_L3_IPV4 | XDP_RSS_L4 |XDP_RSS_L4_UDP:
    return "IPv4/UDP";
  case XDP_RSS_L3_IPV6 | XDP_RSS_L4 |XDP_RSS_L4_TCP:
    return "IPv6/TCP";
  case XDP_RSS_L3_IPV6 | XDP_RSS_L4 |XDP_RSS_L4_UDP:
    return "IPv6/UDP";
  default:
    return "OTHER";
  }
}

SEC("xdp")
int xdp_rss_hash(struct xdp_md *ctx) {
    __u32 hash;
    enum xdp_rss_hash_type type;

    int ret = bpf_xdp_metadata_rx_hash(ctx, &hash, &type);
    if (ret) {
        bpf_printk("bpf_xdp_metadata_rx_hash error: %d", ret);
        return XDP_PASS;
    }

    bpf_printk("XDP Hash: 0x%08x, %s(%d)", hash, rss_type_name(type), type);
    return XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
