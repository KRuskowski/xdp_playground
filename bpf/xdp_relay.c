// SPDX-License-Identifier: GPL-2.0
// XDP relay forwarder — proof of concept
//
// This program intercepts UDP packets on a specific port,
// checks for the NetBird relay transport message type, swaps
// the 36-byte peer ID, and redirects the packet.
//
// The relay binary protocol:
//   byte 0:     protocol version (1)
//   byte 1:     message type (3 = MsgTypeTransport)
//   bytes 2-37: PeerID (4-byte "sha-" prefix + 32-byte SHA256)
//   bytes 38+:  encrypted WireGuard payload
//
// Build: compiled via bpf2go (see gen.go)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// vmlinux.h doesn't include these userspace constants
#define ETH_P_IP 0x0800
#define IPPROTO_UDP 17

#define RELAY_PORT 443
#define PROTO_VERSION 1
#define MSG_TYPE_TRANSPORT 3
#define PEER_ID_SIZE 36
#define PROTO_HEADER_SIZE 2
#define TRANSPORT_HEADER_SIZE (PROTO_HEADER_SIZE + PEER_ID_SIZE)

// Map: PeerID -> destination interface index + MAC address
// Populated from Go userspace
struct peer_entry {
  __u32 ifindex;
  __u8 dst_mac[6];
  __u8 src_mac[6];
  __u32 dst_ip;
  __u16 dst_port;
  __u16 _pad;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, __u8[PEER_ID_SIZE]);   // PeerID
  __type(value, struct peer_entry);
} peer_map SEC(".maps");

// Map: source PeerID replacement
// When forwarding, we replace the target PeerID with the sender's
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, __u32);                // source IP
  __type(value, __u8[PEER_ID_SIZE]); // sender PeerID
} ip_to_peer SEC(".maps");

// Stats counters
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 4);
  __type(key, __u32);
  __type(value, __u64);
} stats SEC(".maps");

enum stat_key {
  STAT_PACKETS = 0,
  STAT_FORWARDED = 1,
  STAT_DROPPED = 2,
  STAT_PASSED = 3,
};

static __always_inline void bump_stat(__u32 key) {
  __u64 *val = bpf_map_lookup_elem(&stats, &key);
  if (val)
    (*val)++;
}

SEC("xdp")
int xdp_relay_func(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  bump_stat(STAT_PACKETS);

  // --- Parse Ethernet header ---
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) {
    bump_stat(STAT_DROPPED);
    return XDP_DROP;
  }

  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    bump_stat(STAT_PASSED);
    return XDP_PASS;
  }

  // --- Parse IP header ---
  struct iphdr *ip = (void *)(eth + 1);
  if ((void *)(ip + 1) > data_end) {
    bump_stat(STAT_DROPPED);
    return XDP_DROP;
  }

  if (ip->protocol != IPPROTO_UDP) {
    bump_stat(STAT_PASSED);
    return XDP_PASS;
  }

  // --- Parse UDP header ---
  struct udphdr *udp = (void *)ip + (ip->ihl * 4);
  if ((void *)(udp + 1) > data_end) {
    bump_stat(STAT_DROPPED);
    return XDP_DROP;
  }

  if (bpf_ntohs(udp->dest) != RELAY_PORT) {
    bump_stat(STAT_PASSED);
    return XDP_PASS;
  }

  // --- Parse relay protocol header ---
  __u8 *payload = (__u8 *)(udp + 1);
  if ((void *)(payload + TRANSPORT_HEADER_SIZE) > data_end) {
    bump_stat(STAT_PASSED);
    return XDP_PASS;
  }

  // Check version and message type
  if (payload[0] != PROTO_VERSION ||
      payload[1] != MSG_TYPE_TRANSPORT) {
    bump_stat(STAT_PASSED);
    return XDP_PASS; // not a transport message, let userspace handle
  }

  // Extract target PeerID (bytes 2-37)
  __u8 *target_peer_id = &payload[PROTO_HEADER_SIZE];

  // Look up destination peer
  struct peer_entry *dst = bpf_map_lookup_elem(
    &peer_map, target_peer_id);
  if (!dst) {
    bump_stat(STAT_PASSED);
    return XDP_PASS; // unknown peer, let userspace handle
  }

  // Look up sender PeerID by source IP
  __u32 src_ip = ip->saddr;
  __u8 *sender_id = bpf_map_lookup_elem(&ip_to_peer, &src_ip);
  if (!sender_id) {
    bump_stat(STAT_PASSED);
    return XDP_PASS;
  }

  // --- Swap the PeerID in-place (the core operation) ---
  // Replace target PeerID with sender PeerID
  // This is what the Go relay does in UpdateTransportMsg()
#pragma unroll
  for (int i = 0; i < PEER_ID_SIZE; i++) {
    target_peer_id[i] = sender_id[i];
  }

  // --- Rewrite packet headers for forwarding ---
  // Update Ethernet addresses
  __builtin_memcpy(eth->h_dest, dst->dst_mac, 6);
  __builtin_memcpy(eth->h_source, dst->src_mac, 6);

  // Update IP destination
  __u32 old_daddr = ip->daddr;
  ip->daddr = dst->dst_ip;
  ip->saddr = old_daddr; // swap src/dst for return path

  // Update UDP destination port
  udp->dest = bpf_htons(dst->dst_port);

  // Recalculate IP checksum (incremental would be better)
  ip->check = 0;
  // Note: for production, use incremental checksum update
  // For now, offload to NIC or recalculate in a helper

  bump_stat(STAT_FORWARDED);

  // Redirect to destination interface
  return bpf_redirect(dst->ifindex, 0);
}

char _license[] SEC("license") = "GPL";
