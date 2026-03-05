package main

import (
  "encoding/binary"
  "fmt"
  "log"
  "net"
  "os"
  "os/signal"
  "time"

  "github.com/cilium/ebpf"
  "github.com/cilium/ebpf/link"
)

func main() {
  if len(os.Args) < 2 {
    log.Fatalf("usage: %s <interface>", os.Args[0])
  }
  ifaceName := os.Args[1]

  iface, err := net.InterfaceByName(ifaceName)
  if err != nil {
    log.Fatalf("interface %s: %v", ifaceName, err)
  }

  // Load the compiled eBPF objects
  var objs relayObjects
  if err := loadRelayObjects(&objs, nil); err != nil {
    log.Fatalf("load ebpf: %v", err)
  }
  defer objs.Close()

  // Attach XDP program to the interface
  xdpLink, err := link.AttachXDP(link.XDPOptions{
    Program:   objs.XdpRelayFunc,
    Interface: iface.Index,
  })
  if err != nil {
    log.Fatalf("attach xdp to %s: %v", ifaceName, err)
  }
  defer xdpLink.Close()

  log.Printf("XDP relay attached to %s (index %d)",
    ifaceName, iface.Index)
  log.Printf("press Ctrl+C to detach and exit")

  // Seed some test data into the peer map
  if os.Getenv("SEED_TEST_DATA") == "1" {
    seedTestData(&objs)
  }

  // Print stats periodically
  sig := make(chan os.Signal, 1)
  signal.Notify(sig, os.Interrupt)

  ticker := time.NewTicker(2 * time.Second)
  defer ticker.Stop()

  for {
    select {
    case <-ticker.C:
      printStats(objs.Stats)
    case <-sig:
      log.Println("detaching XDP program")
      return
    }
  }
}

func printStats(m *ebpf.Map) {
  keys := []string{"packets", "forwarded", "dropped", "passed"}
  for i, name := range keys {
    key := uint32(i)
    var values []uint64
    if err := m.Lookup(&key, &values); err != nil {
      continue
    }
    var total uint64
    for _, v := range values {
      total += v
    }
    if total > 0 {
      fmt.Printf("  %-12s %d\n", name, total)
    }
  }
}

// seedTestData populates the BPF maps with example entries
// for local testing. In production, the Go relay server would
// populate these maps as peers connect/disconnect.
func seedTestData(objs *relayObjects) {
  // Example: register a peer
  peerID := makePeerID("test-peer-1")
  entry := makePeerEntry(1, // loopback ifindex
    net.HardwareAddr{0, 0, 0, 0, 0, 0},
    net.HardwareAddr{0, 0, 0, 0, 0, 0},
    net.ParseIP("127.0.0.1"),
    9000,
  )
  if err := objs.PeerMap.Put(peerID[:], entry); err != nil {
    log.Printf("seed peer_map: %v", err)
  }

  // Map source IP -> sender PeerID
  srcIP := ipToU32(net.ParseIP("127.0.0.1"))
  senderID := makePeerID("test-sender-1")
  if err := objs.IpToPeer.Put(&srcIP, senderID[:]); err != nil {
    log.Printf("seed ip_to_peer: %v", err)
  }

  log.Println("seeded test data into BPF maps")
}

// makePeerID creates a NetBird-style PeerID:
// "sha-" prefix + SHA256 hash (here just zero-padded for testing)
func makePeerID(name string) [36]byte {
  var id [36]byte
  copy(id[:4], "sha-")
  copy(id[4:], []byte(name))
  return id
}

type peerEntry struct {
  Ifindex uint32
  DstMAC  [6]byte
  SrcMAC  [6]byte
  DstIP   uint32
  DstPort uint16
  Pad     uint16
}

func makePeerEntry(
  ifindex uint32,
  dstMAC, srcMAC net.HardwareAddr,
  dstIP net.IP,
  dstPort uint16,
) peerEntry {
  e := peerEntry{
    Ifindex: ifindex,
    DstIP:   ipToU32(dstIP),
    DstPort: dstPort,
  }
  copy(e.DstMAC[:], dstMAC)
  copy(e.SrcMAC[:], srcMAC)
  return e
}

func ipToU32(ip net.IP) uint32 {
  ip = ip.To4()
  if ip == nil {
    return 0
  }
  return binary.LittleEndian.Uint32(ip)
}
