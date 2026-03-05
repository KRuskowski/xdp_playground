package main

import (
  "encoding/hex"
  "flag"
  "fmt"
  "log"
  "net"
  "os"
  "os/signal"
  "sync/atomic"
  "time"
)

const (
  protoVersion     = 1
  msgTypeTransport = 3
  peerIDSize       = 36
  headerSize       = 2
)

func main() {
  if len(os.Args) < 2 {
    fmt.Fprintf(os.Stderr, "usage: %s <send|recv|both>\n", os.Args[0])
    os.Exit(1)
  }

  switch os.Args[1] {
  case "send":
    sendCmd(os.Args[2:])
  case "recv":
    recvCmd(os.Args[2:])
  case "both":
    bothCmd(os.Args[2:])
  default:
    fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
    os.Exit(1)
  }
}

func makePeerID(name string) [peerIDSize]byte {
  var id [peerIDSize]byte
  copy(id[:4], "sha-")
  copy(id[4:], []byte(name))
  return id
}

// buildPacket creates a relay transport message:
//   [version 1B][type 1B][PeerID 36B][payload]
func buildPacket(
  targetPeer [peerIDSize]byte,
  payloadSize int,
) []byte {
  buf := make([]byte, headerSize+peerIDSize+payloadSize)
  buf[0] = protoVersion
  buf[1] = msgTypeTransport
  copy(buf[headerSize:], targetPeer[:])
  // Fill payload with a recognizable pattern
  for i := 0; i < payloadSize; i++ {
    buf[headerSize+peerIDSize+i] = byte(i & 0xff)
  }
  return buf
}

func sendCmd(args []string) {
  fs := flag.NewFlagSet("send", flag.ExitOnError)
  dst := fs.String("dst", "127.0.0.1:443", "destination address")
  pps := fs.Int("pps", 1000, "packets per second (0 = flood)")
  size := fs.Int("size", 128, "payload size in bytes")
  peer := fs.String("peer", "test-peer-1",
    "target peer name (matches seed data)")
  dur := fs.Duration("duration", 0, "run duration (0 = until ctrl+c)")
  fs.Parse(args)

  conn, err := net.Dial("udp", *dst)
  if err != nil {
    log.Fatal(err)
  }
  defer conn.Close()

  peerID := makePeerID(*peer)
  pkt := buildPacket(peerID, *size)

  log.Printf("sending to %s, peer=%q, pps=%d, payload=%dB, "+
    "total=%dB", *dst, *peer, *pps, *size, len(pkt))

  var sent atomic.Uint64
  sig := make(chan os.Signal, 1)
  signal.Notify(sig, os.Interrupt)

  // Stats printer
  go func() {
    t := time.NewTicker(time.Second)
    defer t.Stop()
    var last uint64
    for range t.C {
      cur := sent.Load()
      fmt.Printf("  sent: %d (+%d/s)\n", cur, cur-last)
      last = cur
    }
  }()

  deadline := make(chan struct{})
  if *dur > 0 {
    go func() {
      time.Sleep(*dur)
      close(deadline)
    }()
  }

  var interval time.Duration
  if *pps > 0 {
    interval = time.Second / time.Duration(*pps)
  }

  for {
    select {
    case <-sig:
      log.Printf("sent %d packets total", sent.Load())
      return
    case <-deadline:
      log.Printf("sent %d packets total", sent.Load())
      return
    default:
    }

    if _, err := conn.Write(pkt); err != nil {
      log.Printf("write: %v", err)
      return
    }
    sent.Add(1)

    if interval > 0 {
      time.Sleep(interval)
    }
  }
}

func recvCmd(args []string) {
  fs := flag.NewFlagSet("recv", flag.ExitOnError)
  addr := fs.String("addr", ":9000",
    "listen address (where XDP forwards to)")
  expectPeer := fs.String("expect-peer", "test-sender-1",
    "expected sender peer name after XDP swap")
  verbose := fs.Bool("v", false, "print each packet")
  fs.Parse(args)

  pc, err := net.ListenPacket("udp", *addr)
  if err != nil {
    log.Fatal(err)
  }
  defer pc.Close()

  expectedID := makePeerID(*expectPeer)
  log.Printf("listening on %s, expecting peer=%q after swap",
    *addr, *expectPeer)

  var received, matched, mismatched atomic.Uint64
  sig := make(chan os.Signal, 1)
  signal.Notify(sig, os.Interrupt)

  // Stats printer
  go func() {
    t := time.NewTicker(time.Second)
    defer t.Stop()
    var lastR uint64
    for range t.C {
      r := received.Load()
      m := matched.Load()
      mm := mismatched.Load()
      fmt.Printf("  recv: %d (+%d/s)  matched: %d  "+
        "mismatched: %d\n", r, r-lastR, m, mm)
      lastR = r
    }
  }()

  buf := make([]byte, 65536)
  go func() {
    for {
      n, from, err := pc.ReadFrom(buf)
      if err != nil {
        return
      }
      received.Add(1)

      if n < headerSize+peerIDSize {
        if *verbose {
          log.Printf("short packet from %s: %d bytes", from, n)
        }
        mismatched.Add(1)
        continue
      }

      ver := buf[0]
      msgType := buf[1]
      var gotID [peerIDSize]byte
      copy(gotID[:], buf[headerSize:headerSize+peerIDSize])

      if ver == protoVersion &&
        msgType == msgTypeTransport &&
        gotID == expectedID {
        matched.Add(1)
        if *verbose {
          log.Printf("OK from %s: peer=%s",
            from, string(gotID[:]))
        }
      } else {
        mismatched.Add(1)
        if *verbose {
          log.Printf("MISMATCH from %s: ver=%d type=%d peer=%s",
            from, ver, msgType,
            hex.EncodeToString(gotID[:]))
        }
      }
    }
  }()

  <-sig
  log.Printf("received %d total, %d matched, %d mismatched",
    received.Load(), matched.Load(), mismatched.Load())
}

func bothCmd(args []string) {
  fs := flag.NewFlagSet("both", flag.ExitOnError)
  pps := fs.Int("pps", 100, "packets per second")
  size := fs.Int("size", 128, "payload size in bytes")
  dur := fs.Duration("duration", 10*time.Second,
    "run duration")
  verbose := fs.Bool("v", false, "print each received packet")
  fs.Parse(args)

  // Start receiver
  pc, err := net.ListenPacket("udp", ":9000")
  if err != nil {
    log.Fatal(err)
  }
  defer pc.Close()

  expectedID := makePeerID("test-sender-1")
  var received, matched, mismatched atomic.Uint64

  go func() {
    buf := make([]byte, 65536)
    for {
      n, from, err := pc.ReadFrom(buf)
      if err != nil {
        return
      }
      received.Add(1)

      if n < headerSize+peerIDSize {
        mismatched.Add(1)
        continue
      }

      var gotID [peerIDSize]byte
      copy(gotID[:], buf[headerSize:headerSize+peerIDSize])

      if buf[0] == protoVersion &&
        buf[1] == msgTypeTransport &&
        gotID == expectedID {
        matched.Add(1)
        if *verbose {
          log.Printf("OK from %s", from)
        }
      } else {
        mismatched.Add(1)
        if *verbose {
          log.Printf("MISMATCH from %s: peer=%s",
            from, hex.EncodeToString(gotID[:]))
        }
      }
    }
  }()

  // Start sender
  conn, err := net.Dial("udp", "127.0.0.1:443")
  if err != nil {
    log.Fatal(err)
  }
  defer conn.Close()

  peerID := makePeerID("test-peer-1")
  pkt := buildPacket(peerID, *size)

  log.Printf("both: sending %d pps for %s, payload=%dB",
    *pps, *dur, *size)
  log.Printf("  sender  -> 127.0.0.1:443  peer=test-peer-1")
  log.Printf("  receiver <- :9000          expect=test-sender-1")

  var sent atomic.Uint64
  sig := make(chan os.Signal, 1)
  signal.Notify(sig, os.Interrupt)

  // Stats printer
  ticker := time.NewTicker(time.Second)
  defer ticker.Stop()

  deadline := time.After(*dur)

  var interval time.Duration
  if *pps > 0 {
    interval = time.Second / time.Duration(*pps)
  }

  // Sender goroutine
  stop := make(chan struct{})
  go func() {
    for {
      select {
      case <-stop:
        return
      default:
      }
      if _, err := conn.Write(pkt); err != nil {
        return
      }
      sent.Add(1)
      if interval > 0 {
        time.Sleep(interval)
      }
    }
  }()

  var lastSent, lastRecv uint64
  for {
    select {
    case <-ticker.C:
      s := sent.Load()
      r := received.Load()
      m := matched.Load()
      mm := mismatched.Load()
      fmt.Printf("  sent: %d (+%d/s)  recv: %d (+%d/s)  "+
        "matched: %d  mismatch: %d\n",
        s, s-lastSent, r, r-lastRecv, m, mm)
      lastSent = s
      lastRecv = r
    case <-sig:
      close(stop)
      time.Sleep(100 * time.Millisecond)
      printSummary(sent.Load(), received.Load(),
        matched.Load(), mismatched.Load())
      return
    case <-deadline:
      close(stop)
      time.Sleep(100 * time.Millisecond)
      printSummary(sent.Load(), received.Load(),
        matched.Load(), mismatched.Load())
      return
    }
  }
}

func printSummary(
  sent, received, matched, mismatched uint64,
) {
  fmt.Println("\n--- summary ---")
  fmt.Printf("  sent:       %d\n", sent)
  fmt.Printf("  received:   %d\n", received)
  fmt.Printf("  matched:    %d (PeerID swap verified)\n", matched)
  fmt.Printf("  mismatched: %d\n", mismatched)
  if sent > 0 {
    fmt.Printf("  forward %%:  %.1f%%\n",
      float64(received)/float64(sent)*100)
  }
}
