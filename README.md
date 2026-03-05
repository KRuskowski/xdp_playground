# XDP Relay Forwarder

Proof-of-concept XDP/eBPF program that forwards
[NetBird](https://github.com/netbirdio/netbird) relay traffic
entirely in the kernel — no userspace copy, no syscalls on the
hot path.

The XDP program intercepts UDP packets on the relay port, checks
for `MsgTypeTransport` in the
[relay binary protocol](https://github.com/netbirdio/netbird/blob/main/relay/messages/message.go),
swaps the 36-byte PeerID in-place, rewrites L2/L3/L4 headers,
and redirects to the destination interface via `bpf_redirect()`.

```
  ┌─────────┐    UDP :443     ┌──────────────────────┐    bpf_redirect    ┌──────────┐
  │  Sender  │ ──────────────►│  XDP (xdp_relay.c)   │ ──────────────────►│ Receiver │
  └─────────┘                 │  - parse ETH/IP/UDP  │                    └──────────┘
                              │  - check relay proto │
                              │  - swap PeerID       │
                              │  - rewrite headers   │
                              └──────────────────────┘
```

## Wire format

```
byte 0:      version (1)
byte 1:      message type (3 = MsgTypeTransport)
bytes 2-37:  PeerID ("sha-" + 32-byte SHA256 of WG pubkey)
bytes 38+:   encrypted WireGuard payload
```

## Prerequisites

```bash
sudo apt install clang llvm bpftool libbpf-dev
```

Generate `vmlinux.h` from your running kernel:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
```

## Build

```bash
make build       # go generate (bpf2go) + go build
```

## Usage

Terminal 1 — attach XDP to loopback with test data:

```bash
make run-test
```

Terminal 2 — send test traffic and verify PeerID swap:

```bash
make traffic-both                              # 1000 pps, 10s
./testtraffic both -pps 5000 -duration 30s -v  # custom
```

Or run sender/receiver separately:

```bash
make traffic-send    # blast packets at :443
make traffic-recv    # listen on :9000, verify swap
```

## Project structure

```
bpf/xdp_relay.c          XDP program (C/eBPF)
gen.go                    bpf2go code generation directive
main.go                   Go loader: attach XDP, seed BPF maps, print stats
cmd/testtraffic/main.go   Traffic generator + receiver
Makefile                  Build/run targets
```

## How it works

1. Go loader (`main.go`) loads the compiled BPF bytecode via
   [cilium/ebpf](https://github.com/cilium/ebpf), attaches it
   to a network interface, and populates the BPF maps
   (`peer_map`, `ip_to_peer`) with peer routing info.
2. The XDP program runs on every incoming packet at the driver
   level. It parses ETH → IP → UDP, checks for the relay
   transport header, looks up the target PeerID in the hash map,
   swaps it with the sender's PeerID, rewrites headers, and
   redirects — all without leaving the kernel.
3. `testtraffic` sends properly framed relay packets and
   verifies that the receiver gets them with the PeerID swapped.
