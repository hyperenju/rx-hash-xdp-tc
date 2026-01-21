DEV ?= ens5
XDP_PIN := /sys/fs/bpf/xdp_rx_hash

%.bpf.o: %.bpf.c
	clang -O2 -g -target bpf -c $< -o $@

setup:
	ip link set mtu 2000 dev $(DEV)
	ethtool -L $(DEV) combined 1

trace:
	cat /sys/kernel/tracing/trace_pipe

xdp-load: xdp-rss-hash.bpf.o
	-bpftool net detach xdp dev $(DEV)
	-rm -f $(XDP_PIN)
	bpftool prog load $< $(XDP_PIN) xdpmeta_dev $(DEV)
	bpftool net attach xdp pinned $(XDP_PIN) dev $(DEV)

xdp-unload:
	-bpftool net detach xdp dev $(DEV)
	-rm -f $(XDP_PIN)

tc-load: tc-skb-hash.bpf.o
	tc qdisc add dev $(DEV) clsact
	tc filter add dev $(DEV) ingress bpf da obj $< sec tc

tc-unload:
	-tc filter del dev $(DEV) ingress
	-tc qdisc del dev $(DEV) clsact

clean:
	rm -f *.bpf.o

.PHONY: xdp-load xdp-unload tc-load tc-unload clean trace setup

