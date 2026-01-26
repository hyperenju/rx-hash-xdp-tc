#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/pkt_cls.h>
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

struct meta_info {
    __u32 hash;
    enum xdp_rss_hash_type type;
    
} __attribute__((aligned(4)));

/* Always return XDP_PASS, as this shouldn't disrupt networking operations */
SEC("xdp")
int xdp_produce_hash(struct xdp_md *ctx)
{
    enum xdp_rss_hash_type type;
    struct meta_info *meta;
    void *data;
    __u32 hash;
    int ret;

    ret = bpf_xdp_metadata_rx_hash(ctx, &hash, &type);
    switch (ret) {
        case 0:
            break;
        case -EOPNOTSUPP:
            bpf_printk("bpf_xdp_metadata_rx_hash: Not supported by this driver");
            return XDP_PASS;
        case -ENODATA:
            bpf_printk("bpf_xdp_metadata_rx_hash: No hash found");
            return XDP_PASS;
        default:
            bpf_printk("bpf_xdp_metadata_rx_hash: Unexpected error: %d", ret);
            return XDP_PASS;
    }

    ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*meta));
    if (ret) {
        if (ret != -EOPNOTSUPP)
            bpf_printk("bpf_xdp_adjust_meta: Unexpected error: %d", ret);

        bpf_printk("XDP Hash: 0x%08x, %s(%d)", hash, rss_type_name(type), type);
        return XDP_PASS;
    }

    data = (void *)(unsigned long)ctx->data;

    meta = (void *)(unsigned long)ctx->data_meta;
    if ((void *)(meta + 1) > data) {
        bpf_printk("metadata is not enough. Something goes wrong.");
        return XDP_PASS;
    }

    meta->hash = hash;
    meta->type = type;

    return XDP_PASS;
}

/* Always return TC_ACT_OK, as this shouldn't disrupt networking operations */
SEC("tc")
int tc_consume_hash(struct __sk_buff *ctx)
{
    void *data_meta = (void *)(unsigned long)ctx->data_meta;
    void *data = (void *)(unsigned long)ctx->data;
    struct meta_info *meta = data_meta;

    if ((void *)(meta + 1) > data) {
        if (!ctx->hash)
            bpf_printk("skb->hash: No hash found");
        else
            bpf_printk("skb->hash: 0x%08x", ctx->hash);

        return TC_ACT_OK;
    }

    if (meta->hash == ctx->hash)
          bpf_printk("Match. (0x%08x == 0x%08x), %s(%d)", meta->hash, ctx->hash,
                     rss_type_name(meta->type), meta->type);
    else
          bpf_printk("Not match. (0x%08x != 0x%08x), %s(%d)", meta->hash,
                     ctx->hash, rss_type_name(meta->type), meta->type);
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
