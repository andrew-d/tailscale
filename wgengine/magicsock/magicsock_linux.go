//go:build linux
// +build linux

package magicsock

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
	"tailscale.com/disco"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
)

const (
	ethHeaderSize = 14
	udpHeaderSize = 8
)

// listenDisco starts listening for disco packets using an AF_PACKET socket + a
// BPF filter. This allows us to receive disco packets even without opening the
// firewall; see issue 3824 for more detail.
func (c *Conn) listenDisco() {
	// Convert our disco magic number into a uint32 and uint16 to test
	// against. We panic on an incorrect length here rather than try to be
	// generic with our BPF instructions below.
	//
	// Note that BPF uses network byte order (big-endian) when loading data
	// from a packet, so that is what we use to generate our magic numbers.
	if len(disco.Magic) != 6 {
		panic("expected disco.Magic to be of length 6")
	}
	magic1 := binary.BigEndian.Uint32([]byte(disco.Magic[0:4]))
	magic2 := binary.BigEndian.Uint16([]byte(disco.Magic[4:6]))

	// Build our filters; we have a different one for IPv4 and IPv6
	magicsockFilterV4 := []bpf.Instruction{
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

	// TODO
	magicsockFilterV6 := []bpf.Instruction{
		// Skip the packet
		bpf.RetConstant{Val: 0x0},
	}

	fd4, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err == nil {
		c.bpfConn4 = fd4
		go func() {
			err := c.listenPacketsWithFilter(fd4, magicsockFilterV4, c.handleIPv4Disco)
			if err != nil {
				c.logf("error listening for IPv4 disco packets with AF_PACKET: %v", err)
			}
		}()
	} else {
		c.logf("error creating raw socket for IPv4: %v", err)
	}

	fd6, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err == nil {
		c.bpfConn6 = fd6
		go func() {
			err := c.listenPacketsWithFilter(fd6, magicsockFilterV6, c.handleIPv6Disco)
			if err != nil {
				c.logf("error listening for IPv6 disco packets with AF_PACKET: %v", err)
			}
		}()
	} else {
		c.logf("error creating raw socket for IPv6: %v", err)
	}
}

func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func (c *Conn) handleIPv4Disco(packet []byte, from unix.Sockaddr) error {
	// We know this is an IPv4 UDP packet, so quickly parse the header(s)
	// to get relevant information
	ipPacket := packet[ethHeaderSize:]
	ipHdrLen := 4 * (ipPacket[0] & 0xF)
	srcAddr := netip.AddrFrom4(*(*[4]byte)(ipPacket[12:16]))
	//dstAddr := netip.AddrFrom4(*(*[4]byte)(ipPacket[16:20]))

	// TODO: can panic?
	udpPacket := ipPacket[ipHdrLen:]

	srcPort := binary.BigEndian.Uint16(udpPacket[0:2])
	//dstPort := binary.BigEndian.Uint16(udpPacket[2:4])
	dataLen := binary.BigEndian.Uint16(udpPacket[4:6])

	// TODO: can panic?
	packetData := udpPacket[udpHeaderSize : udpHeaderSize+dataLen]

	src := netip.AddrPortFrom(srcAddr, srcPort)
	if c.handleDiscoMessage(packetData, src, key.NodePublic{}) {
		metricRecvDiscoPacketIPv4.Add(1)
	} else {
		metricRecvDiscoPacketInvalidIPv4.Add(1)
	}
	return nil
}

func (c *Conn) handleIPv6Disco(packet []byte, from unix.Sockaddr) error {
	return nil
}

// listenPacketsWithFilter creates a new AF_PACKET socket, applies the given
// BPF filter to it, and then calls 'cb' with all packets that are received
// from the socket (and thus ones that match the given filter).
func (c *Conn) listenPacketsWithFilter(fd int, filt []bpf.Instruction, cb func([]byte, unix.Sockaddr) error) error {
	// This filter ignores all packets
	zeroFilter := bpfFilter{bpf.RetConstant{Val: 0x0}}
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

	// Now apply our real filter
	if err := bpfFilter(filt).ApplyTo(fd); err != nil {
		return fmt.Errorf("applying real BPF filter: %w", err)
	}

	sockBuf := make([]byte, 65535)
	for {
		n, from, err := unix.Recvfrom(fd, sockBuf[:], 0)
		if n == -1 {
			// TODO: graceful termination
			return fmt.Errorf("receiving packet: %w", err)
		}

		if err := cb(sockBuf[:n], from); err != nil {
			return err
		}
	}
	return nil
}

// bpfFilter represents a BPF filter program that can be applied to a socket.
type bpfFilter []bpf.Instruction

// ApplyTo applies the current filter to a socket with the provided file descriptor.
func (filter bpfFilter) ApplyTo(fd int) error {
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
