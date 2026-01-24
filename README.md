# rx-hash-xdp-tc

Minimal eBPF examples to validate `bpf_xdp_metadata_rx_hash` on a given driver by comparing XDP-generated hashes with `skb->hash`.

## Directories / roles
- `metadata/`: End-to-end metadata handoff (XDP -> TC) and in-kernel comparison. Use this when the NIC/driver supports XDP metadata and you want to verify the metadata path itself.
- `no-metadata/`: No metadata handoff; XDP prints the hash and TC prints `skb->hash` separately. Use this as a simpler baseline to confirm the hash values match without relying on metadata support.
