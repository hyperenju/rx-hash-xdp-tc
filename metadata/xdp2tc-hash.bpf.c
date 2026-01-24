#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

enum xdp_rss_hash_type {
    DUMMY = 0,
};

extern int bpf_xdp_metadata_rx_hash(const struct xdp_md *ctx, __u32 *hash,
                                    enum xdp_rss_hash_type *rss_type) __ksym;

struct meta_info {
    __u32 hash;
} __attribute__((aligned(4)));

SEC("xdp")
int xdp_produce_hash(struct xdp_md *ctx)
{
    enum xdp_rss_hash_type type;
    struct meta_info *meta;
    void *data;
    __u32 hash;
    int ret;

    ret = bpf_xdp_metadata_rx_hash(ctx, &hash, &type);
    if (ret == -ENODATA) {
        bpf_printk("bpf_xdp_metadata_rx_hash: No hash found");
        return XDP_PASS;
    } else if (ret) {
        bpf_printk("bpf_xdp_metadata_rx_hash: Unexpectd error: %d", ret);
        return XDP_PASS;
    }

    ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*meta));
    if (ret < 0)
        return XDP_ABORTED;

    data = (void *)(unsigned long)ctx->data;

    meta = (void *)(unsigned long)ctx->data_meta;
    if ((void *)(meta + 1) > data)
        return XDP_ABORTED;

    meta->hash = hash;
    return XDP_PASS;
}

SEC("tc")
int tc_consume_hash(struct __sk_buff *ctx)
{
    void *data_meta = (void *)(unsigned long)ctx->data_meta;
    void *data = (void *)(unsigned long)ctx->data;
    struct meta_info *meta = data_meta;

    if ((void *)(meta + 1) > data)
        return TC_ACT_OK;

    if (meta->hash == ctx->hash)
        bpf_printk("Hash matches. (0x%x == 0x%x)", meta->hash, ctx->hash);
    else
        bpf_printk("Hash NOT matches. (0x%x != 0x%x)", meta->hash, ctx->hash);
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
