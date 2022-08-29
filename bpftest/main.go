package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net/netip"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
	"tailscale.com/disco"
	"tailscale.com/types/ipproto"
)

func main() {
	err := run()
	if err != nil {
		log.Fatal(err)
	}
}

func run() error {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("creating raw socket: %w", err)
	}
	defer unix.Close(fd)

	// This filter ignores all packets
	zeroFilter := Filter{bpf.RetConstant{Val: 0x0}}
	if err := zeroFilter.ApplyTo(fd); err != nil {
		return fmt.Errorf("applying zero BPF filter: %w", err)
	}

	// Drain any existing packets in the queue, since things can
	// arrive between creating the packet and installing our first
	// filter.
	var (
		drain  [1]byte
		nDrain int
	)
	for {
		n, _ /* from */, _ /* err */ := unix.Recvfrom(fd, drain[:], unix.MSG_DONTWAIT)
		if n == -1 {
			// We assume the error here means there is nothing left
			// to read from the socket, which is exactly what we
			// want. If there are any further errors, we'll bail out below anyway.
			break
		}
		nDrain++
	}
	log.Printf("drained %d unfiltered packets", nDrain)

	// Convert our magic number into a uint32 and uint16 to test against.
	// We panic on an incorrect length here rather than try to be generic
	// with our BPF instructions below.
	//
	// Note that BPF uses network byte order (big-endian) when loading data
	// from a packet, so that is what we use to generate our magic numbers.
	if len(disco.Magic) != 6 {
		panic("expected disco.Magic to be of length 6")
	}
	magic1 := binary.BigEndian.Uint32([]byte(disco.Magic[0:4]))
	magic2 := binary.BigEndian.Uint16([]byte(disco.Magic[4:6]))

	// Atomically swap for a BPF filter that actually filters as we expect
	const (
		ethHeaderSize = 14
		udpHeaderSize = 8
	)
	magicsockFilter := Filter{
		// Check Ethernet header for EtherType = 0x0800 (IPv4)
		bpf.LoadAbsolute{Off: 12, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x800, SkipTrue: 0, SkipFalse: 10},

		// Check protocol == UDP
		bpf.LoadAbsolute{Off: ethHeaderSize + 9, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(ipproto.UDP), SkipTrue: 0, SkipFalse: 8},

		// Check for non-fragmented packets
		bpf.LoadAbsolute{Off: ethHeaderSize + 6, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 6, SkipFalse: 0},

		// Load IP header length into X
		bpf.LoadMemShift{Off: ethHeaderSize + 0},

		// Get the first 4 bytes of the UDP packet, compare with our magic number
		bpf.LoadIndirect{Off: ethHeaderSize + udpHeaderSize, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: magic1, SkipTrue: 0, SkipFalse: 3},

		// Compare the next 2 bytes
		bpf.LoadIndirect{Off: ethHeaderSize + udpHeaderSize + 4, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(magic2), SkipTrue: 0, SkipFalse: 1},

		// Accept the whole packet
		bpf.RetConstant{Val: 0xFFFFFFFF},

		// Skip the packet
		bpf.RetConstant{Val: 0x0},
	}

	if err := magicsockFilter.ApplyTo(fd); err != nil {
		return fmt.Errorf("applying real BPF filter: %w", err)
	}

	log.Printf("receiving packets")
	sockBuf := make([]byte, 4000)
	for {
		n, from, err := unix.Recvfrom(fd, sockBuf[:], 0)
		if n == -1 {
			return fmt.Errorf("receiving packet: %w", err)
		}
		var sfrom string
		switch v := from.(type) {
		case *unix.SockaddrInet4:
			sfrom = fmt.Sprintf("ipv4 %d.%d.%d.%d port %d", v.Addr[0], v.Addr[1], v.Addr[2], v.Addr[3], v.Port)
		case *unix.SockaddrLinklayer:
			sfrom = fmt.Sprintf("linklayer %x ethertype %d", v.Addr, v.Protocol)
		default:
			sfrom = fmt.Sprintf("unknown addrtype: %T", v)
		}

		// We know this is an IPv4 UDP packet, so quickly parse the header(s)
		// to get relevant information
		packet := sockBuf[:n]

		ipPacket := packet[ethHeaderSize:]
		ipHdrLen := 4 * (ipPacket[0] & 0xF)
		srcAddr := netip.AddrFrom4(*(*[4]byte)(ipPacket[12:16]))
		dstAddr := netip.AddrFrom4(*(*[4]byte)(ipPacket[16:20]))

		udpPacket := ipPacket[ipHdrLen:]

		srcPort := binary.BigEndian.Uint16(udpPacket[0:2])
		dstPort := binary.BigEndian.Uint16(udpPacket[2:4])
		dataLen := binary.BigEndian.Uint16(udpPacket[4:6])

		ifrom := fmt.Sprintf("udp %s:%d -> %s:%d len %d", srcAddr, srcPort, dstAddr, dstPort, dataLen)

		packetData := udpPacket[8:]
		log.Printf("got disco packet from %s %s:\n%s", sfrom, ifrom, hex.Dump(packetData))
	}
	return nil
}

// Filter represents a BPF filter program that can be applied to a socket.
type Filter []bpf.Instruction

// ApplyTo applies the current filter to a socket with the provided file descriptor.
func (filter Filter) ApplyTo(fd int) error {
	assembled, err := bpf.Assemble(filter)
	if err != nil {
		return err
	}

	program := unix.SockFprog{
		Len: uint16(len(assembled)),

		// Safe: "(1) Conversion of a *T1 to Pointer to *T2"
		Filter: (*unix.SockFilter)(unsafe.Pointer(&assembled[0])),
	}

	if _, _, errno := unix.Syscall6(
		unix.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(unix.SOL_SOCKET),
		uintptr(unix.SO_ATTACH_FILTER),
		uintptr(unsafe.Pointer(&program)),
		uintptr(unix.SizeofSockFprog),
		0,
	); errno != 0 {
		return errno
	}

	return nil
}

func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}
