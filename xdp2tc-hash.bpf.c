#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

enum xdp_rss_hash_type {
    DUMMY = 0,
};

extern int bpf_xdp_metadata_rx_hash(const struct xdp_md *ctx, __u32 *hash,
                                    enum xdp_rss_hash_type *rss_type) __ksym;
extern int bpf_xdp_metadata_rx_vlan_tag(const struct xdp_md *ctx,
                                        __be16 *vlan_proto,
                                        __u16 *vlan_tci) __ksym;

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
    __u32 rss_hash;
    enum xdp_rss_hash_type rss_type;
    __be16 vlan_proto;
    __u16 vlan_tci;
    
} __attribute__((aligned(4)));

/* Always return XDP_PASS, as this shouldn't disrupt networking operations */
SEC("xdp")
int xdp_produce_xmo(struct xdp_md *ctx)
{
    enum xdp_rss_hash_type rss_type;
    struct meta_info *meta;
    __be16 vlan_proto;
    __u16 vlan_tci;
    void *data;
    __u32 hash;
    int ret;

    ret = bpf_xdp_metadata_rx_hash(ctx, &hash, &rss_type);
    if (ret) {
        switch (ret) {
            case -EOPNOTSUPP:
                bpf_printk("bpf_xdp_metadata_rx_hash: Not supported by this driver");
                break;
            case -ENODATA:
                bpf_printk("bpf_xdp_metadata_rx_hash: No hash found");
                break;
            default:
                bpf_printk("bpf_xdp_metadata_rx_hash: Unexpected error: %d", ret);
                break;
        }

        hash = 0; 
        rss_type = 0;
    }

    ret = bpf_xdp_metadata_rx_vlan_tag(ctx, &vlan_proto, &vlan_tci);
    if (ret) {
        switch (ret) {
            case -EOPNOTSUPP:
                bpf_printk("bpf_xdp_metadata_rx_vlan_tag: Not supported by this driver");
                break;
            case -ENODATA:
                bpf_printk("bpf_xdp_metadata_rx_vlan_tag: No vlan tag found");
                break;
            default:
                bpf_printk("bpf_xdp_metadata_rx_vlan_tag: Unexpected error: %d", ret);
                break;
        }

        vlan_proto = bpf_htons(0);
        vlan_tci = 0;
    }

    ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*meta));
    if (ret) {
        if (ret != -EOPNOTSUPP)
            bpf_printk("bpf_xdp_adjust_meta: Unexpected error: %d", ret);

        if (rss_type)
            bpf_printk("XDP Hash: 0x%08x, %s(%d)", hash, rss_type_name(rss_type), rss_type);
        if (vlan_proto)
            bpf_printk("XDP VLAN: 0x%04x, %d", bpf_ntohs(vlan_proto), vlan_tci);
        return XDP_PASS;
    }

    data = (void *)(unsigned long)ctx->data;

    meta = (void *)(unsigned long)ctx->data_meta;
    if ((void *)(meta + 1) > data) {
        bpf_printk("metadata is not enough. Something goes wrong.");
        return XDP_PASS;
    }

    meta->rss_hash = hash;
    meta->rss_type = rss_type;
    meta->vlan_proto = vlan_proto;
    meta->vlan_tci = vlan_tci;

    return XDP_PASS;
}

/* Always return TC_ACT_OK, as this shouldn't disrupt networking operations */
SEC("tc")
int tc_consume_xmo(struct __sk_buff *ctx)
{
    void *data_meta = (void *)(unsigned long)ctx->data_meta;
    void *data = (void *)(unsigned long)ctx->data;
    struct meta_info *meta = data_meta;

    if ((void *)(meta + 1) > data) {
        if (!ctx->hash)
            bpf_printk("skb->hash: No hash found");
        else
            bpf_printk("skb->hash: 0x%08x", ctx->hash);

        if (!ctx->vlan_proto)
            bpf_printk("skb->vlan_*: No vlan tag found");
        else
            bpf_printk("skb->vlan_proto: 0x%04x, skb->vlan_tci: %d", bpf_ntohs(ctx->vlan_proto),
                       ctx->vlan_tci);

        return TC_ACT_OK;
    }

    if (meta->rss_type) {
        if (meta->rss_hash == ctx->hash)
              bpf_printk("Hash match. (0x%08x == 0x%08x), %s(%d)", meta->rss_hash, ctx->hash,
                         rss_type_name(meta->rss_type), meta->rss_type);
        else
              bpf_printk("Hash NOT match. (0x%08x != 0x%08x), %s(%d)", meta->rss_hash,
                         ctx->hash, rss_type_name(meta->rss_type), meta->rss_type);
    }

    if (meta->vlan_proto) {
        if (meta->vlan_proto == ctx->vlan_proto && meta->vlan_tci == ctx->vlan_tci)
          bpf_printk("VLAN match. (0x%04x, %d) == (0x%04x, %d)",
                     bpf_ntohs(meta->vlan_proto), meta->vlan_tci,
                     bpf_ntohs(ctx->vlan_proto), ctx->vlan_tci);
        else
          bpf_printk("VLAN NOT match. (0x%04x, %d) != (0x%04x, %d)",
                     bpf_ntohs(meta->vlan_proto), meta->vlan_tci,
                     bpf_ntohs(ctx->vlan_proto), ctx->vlan_tci);
    }

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
