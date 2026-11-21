//go:build darwin

package boxengine

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/process"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/sys/unix"
)

const (
	darwinProcSnapshotTTL = 150 * time.Millisecond

	procInfoCallListPIDs  = 0x1
	procInfoCallPIDInfo   = 0x2
	procInfoCallPIDFDInfo = 0x3

	procAllPIDs         = 1
	procPIDListFDs      = 1
	procPIDPathInfo     = 0xb
	procPIDPathInfoSize = 1024
	procPIDFDSocketInfo = 3
	proxFDTypeSocket    = 2

	sockInfoIn  = 1
	sockInfoTCP = 2
	iniIPv4     = 0x1
	iniIPv6     = 0x2

	// 64-bit Darwin <sys/proc_info.h> struct layouts (stable across macOS versions).
	procFDInfoSize    = 8
	socketFDInfoSize  = 792
	offSoiProtocol    = 180
	offSoiKind        = 256
	offPriIn          = 264
	inSockInfoSize    = 80
	offInsiFPort      = 0
	offInsiLPort      = 4
	offInsiVFlag      = 24
	offInsiFAddr      = 32
	offInsiLAddr      = 48
	ipv4InIn6AddrOff  = 12
)

type darwinProcSocketEntry struct {
	pid        int32
	localAddr  netip.Addr
	remoteAddr netip.Addr
	localPort  uint16
	remotePort uint16
	proto      uint8
}

type darwinProcMatchKind uint8

const (
	darwinProcMatchExact darwinProcMatchKind = iota
	darwinProcMatchLocalFallback
	darwinProcMatchWildcardFallback
	darwinProcMatchCrossFamilyWildcardFallback
)

type darwinProcSnapshot struct {
	createdAt  time.Time
	tcpEntries []darwinProcSocketEntry
	udpEntries []darwinProcSocketEntry
}

type darwinProcFinder struct {
	access   sync.Mutex
	ttl      time.Duration
	snapshot darwinProcSnapshot
	hasSnap  bool
	pidBuf   []int32
	fdBuf    []byte
}

var sharedDarwinProcFinder = &darwinProcFinder{
	ttl: darwinProcSnapshotTTL,
}

// UsePlatformConnectionOwnerFinder enables custom macOS process resolution.
// Recent macOS versions restrict net.inet.{tcp,udp}.pcblist_n for unprivileged
// processes to their own sockets, whereas SYS_PROC_INFO exposes user-owned
// client sockets cleanly without elevated privileges.
func (s *platformInterfaceStub) UsePlatformConnectionOwnerFinder() bool {
	return true
}

func (s *platformInterfaceStub) FindConnectionOwner(request *adapter.FindConnectionOwnerRequest) (*adapter.ConnectionOwner, error) {
	if request == nil || request.SourcePort <= 0 || request.SourcePort > 65535 {
		return nil, process.ErrNotFound
	}
	var network string
	switch request.IpProtocol {
	case syscall.IPPROTO_TCP:
		network = N.NetworkTCP
	case syscall.IPPROTO_UDP:
		network = N.NetworkUDP
	default:
		return nil, process.ErrNotFound
	}

	srcAddr, err := parseDarwinAddr(request.SourceAddress)
	if err != nil {
		return nil, process.ErrNotFound
	}
	src := netip.AddrPortFrom(srcAddr, uint16(request.SourcePort))

	var dst netip.AddrPort
	if request.DestinationAddress != "" && request.DestinationPort > 0 && request.DestinationPort <= 65535 {
		if dstAddr, err := parseDarwinAddr(request.DestinationAddress); err == nil {
			dst = netip.AddrPortFrom(dstAddr, uint16(request.DestinationPort))
		}
	}

	return findDarwinConnectionOwnerByProcInfo(network, src, dst)
}

func parseDarwinAddr(raw string) (netip.Addr, error) {
	if raw == "" {
		return netip.Addr{}, process.ErrNotFound
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return netip.Addr{}, err
	}
	return addr.Unmap().WithZone(""), nil
}

func findDarwinConnectionOwnerByProcInfo(network string, source, destination netip.AddrPort) (*adapter.ConnectionOwner, error) {
	return sharedDarwinProcFinder.find(network, source, destination)
}

func (f *darwinProcFinder) find(network string, source, destination netip.AddrPort) (*adapter.ConnectionOwner, error) {
	networkName := N.NetworkName(network)
	if networkName != N.NetworkTCP && networkName != N.NetworkUDP {
		return nil, process.ErrNotFound
	}
	source = normalizeProcAddrPort(source)
	destination = normalizeProcAddrPort(destination)

	for attempt := range 2 {
		entry, matchKind, ok, fromCache := f.lookupLocked(attempt > 0, networkName, source, destination)
		if !ok {
			if fromCache {
				continue
			}
			break
		}
		if fromCache && matchKind != darwinProcMatchExact {
			continue
		}
		path, err := getProcExecPath(entry.pid)
		if err != nil || path == "" {
			if fromCache {
				continue
			}
			break
		}
		return &adapter.ConnectionOwner{
			UserId:      -1,
			ProcessPath: path,
		}, nil
	}

	// Fallback to sing-box's pcblist_n implementation if the socket belongs to a
	// privileged daemon whose FDs aren't readable via PROC_PIDLISTFDS.
	if owner, err := process.FindDarwinConnectionOwner(network, source, destination); err == nil && owner != nil && owner.ProcessPath != "" {
		return owner, nil
	}
	return nil, process.ErrNotFound
}

func (f *darwinProcFinder) lookupLocked(forceRefresh bool, network string, source, destination netip.AddrPort) (darwinProcSocketEntry, darwinProcMatchKind, bool, bool) {
	f.access.Lock()
	defer f.access.Unlock()

	fromCache := true
	if forceRefresh || !f.hasSnap || time.Since(f.snapshot.createdAt) >= f.ttl {
		f.buildSnapshotLocked()
		f.hasSnap = true
		fromCache = false
	}

	entries := f.snapshot.tcpEntries
	if network == N.NetworkUDP {
		entries = f.snapshot.udpEntries
	}
	entry, matchKind, ok := matchDarwinProcEntry(entries, network, source, destination)
	return entry, matchKind, ok, fromCache
}

func (f *darwinProcFinder) buildSnapshot() darwinProcSnapshot {
	f.access.Lock()
	defer f.access.Unlock()
	f.buildSnapshotLocked()
	f.hasSnap = true
	return f.snapshot
}

func (f *darwinProcFinder) buildSnapshotLocked() {
	f.snapshot.createdAt = time.Now()
	f.snapshot.tcpEntries = f.snapshot.tcpEntries[:0]
	f.snapshot.udpEntries = f.snapshot.udpEntries[:0]

	pids := f.listAllPIDsLocked()
	if len(pids) == 0 {
		return
	}

	if len(f.fdBuf) < 4096*procFDInfoSize {
		f.fdBuf = make([]byte, 4096*procFDInfoSize)
	}
	var siBuf [socketFDInfoSize]byte

	for _, pid := range pids {
		if pid <= 0 {
			continue
		}
		rawFDs := f.readPIDFDsLocked(pid)
		for off := 0; off+procFDInfoSize <= len(rawFDs); off += procFDInfoSize {
			fdType := binary.NativeEndian.Uint32(rawFDs[off+4 : off+8])
			if fdType != proxFDTypeSocket {
				continue
			}
			fd := int32(binary.NativeEndian.Uint32(rawFDs[off : off+4]))
			n, _, errno := syscall.Syscall6(syscall.SYS_PROC_INFO, procInfoCallPIDFDInfo, uintptr(pid), procPIDFDSocketInfo, uintptr(fd), uintptr(unsafe.Pointer(&siBuf[0])), socketFDInfoSize)
			if errno != 0 || int(n) < offPriIn+inSockInfoSize {
				continue
			}
			kind := int32(binary.NativeEndian.Uint32(siBuf[offSoiKind : offSoiKind+4]))
			proto := int32(binary.NativeEndian.Uint32(siBuf[offSoiProtocol : offSoiProtocol+4]))
			if kind != sockInfoTCP && !(kind == sockInfoIn && proto == syscall.IPPROTO_UDP) {
				continue
			}

			ini := siBuf[offPriIn : offPriIn+inSockInfoSize]
			fport := binary.BigEndian.Uint16(ini[offInsiFPort : offInsiFPort+2])
			lport := binary.BigEndian.Uint16(ini[offInsiLPort : offInsiLPort+2])
			if lport == 0 {
				continue
			}
			vflag := ini[offInsiVFlag]
			var laddr, faddr netip.Addr
			switch {
			case vflag&iniIPv4 != 0:
				laddr = netip.AddrFrom4([4]byte(ini[offInsiLAddr+ipv4InIn6AddrOff : offInsiLAddr+ipv4InIn6AddrOff+4]))
				faddr = netip.AddrFrom4([4]byte(ini[offInsiFAddr+ipv4InIn6AddrOff : offInsiFAddr+ipv4InIn6AddrOff+4]))
			case vflag&iniIPv6 != 0:
				laddr = netip.AddrFrom16([16]byte(ini[offInsiLAddr : offInsiLAddr+16])).Unmap()
				faddr = netip.AddrFrom16([16]byte(ini[offInsiFAddr : offInsiFAddr+16])).Unmap()
			default:
				continue
			}

			entry := darwinProcSocketEntry{
				pid:        pid,
				localAddr:  laddr,
				remoteAddr: faddr,
				localPort:  lport,
				remotePort: fport,
				proto:      uint8(proto),
			}
			if kind == sockInfoTCP {
				f.snapshot.tcpEntries = append(f.snapshot.tcpEntries, entry)
			} else {
				f.snapshot.udpEntries = append(f.snapshot.udpEntries, entry)
			}
		}
	}
}

func (f *darwinProcFinder) listAllPIDsLocked() []int32 {
	if len(f.pidBuf) < 2048 {
		f.pidBuf = make([]int32, 2048)
	}
	for {
		bufBytes := len(f.pidBuf) * 4
		got, _, errno := syscall.Syscall6(syscall.SYS_PROC_INFO, procInfoCallListPIDs, procAllPIDs, 0, 0, uintptr(unsafe.Pointer(&f.pidBuf[0])), uintptr(bufBytes))
		if errno != 0 || got == 0 {
			return nil
		}
		if int(got)+4 > bufBytes && len(f.pidBuf) < 1<<20 {
			f.pidBuf = make([]int32, len(f.pidBuf)*2)
			continue
		}
		count := min(int(got)/4, len(f.pidBuf))
		return f.pidBuf[:count]
	}
}

func (f *darwinProcFinder) readPIDFDsLocked(pid int32) []byte {
	for {
		got, _, errno := syscall.Syscall6(syscall.SYS_PROC_INFO, procInfoCallPIDInfo, uintptr(pid), procPIDListFDs, 0, uintptr(unsafe.Pointer(&f.fdBuf[0])), uintptr(len(f.fdBuf)))
		if errno != 0 || got == 0 {
			return nil
		}
		if int(got)+procFDInfoSize > len(f.fdBuf) && len(f.fdBuf) < 8<<20 {
			f.fdBuf = make([]byte, len(f.fdBuf)*2)
			continue
		}
		limit := min(int(got), len(f.fdBuf))
		return f.fdBuf[:limit]
	}
}

func getProcExecPath(pid int32) (string, error) {
	var buf [procPIDPathInfoSize]byte
	_, _, errno := syscall.Syscall6(
		syscall.SYS_PROC_INFO,
		procInfoCallPIDInfo,
		uintptr(pid),
		procPIDPathInfo,
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		procPIDPathInfoSize,
	)
	if errno != 0 {
		return "", errno
	}
	return unix.ByteSliceToString(buf[:]), nil
}

func matchDarwinProcEntry(entries []darwinProcSocketEntry, network string, source, destination netip.AddrPort) (darwinProcSocketEntry, darwinProcMatchKind, bool) {
	sourceAddr := source.Addr()
	if !sourceAddr.IsValid() || source.Port() == 0 {
		return darwinProcSocketEntry{}, darwinProcMatchExact, false
	}
	var (
		localFallback          darwinProcSocketEntry
		hasLocalFallback       bool
		wildcardFallback       darwinProcSocketEntry
		hasWildcardFallback    bool
		crossWildcardFallback  darwinProcSocketEntry
		hasCrossWildcard       bool
	)
	for _, entry := range entries {
		if entry.localPort != source.Port() {
			continue
		}
		sameFamily := sourceAddr.BitLen() == entry.localAddr.BitLen()
		if sameFamily && entry.localAddr == sourceAddr {
			if destination.IsValid() && entry.remotePort == destination.Port() && entry.remoteAddr == destination.Addr() {
				return entry, darwinProcMatchExact, true
			}
			if !destination.IsValid() {
				return entry, darwinProcMatchExact, true
			}
			if network == N.NetworkUDP && !hasLocalFallback {
				hasLocalFallback = true
				localFallback = entry
			}
			continue
		}
		if network == N.NetworkUDP && entry.localAddr.IsUnspecified() {
			if sameFamily && !hasWildcardFallback {
				hasWildcardFallback = true
				wildcardFallback = entry
			} else if !sameFamily && !hasCrossWildcard {
				hasCrossWildcard = true
				crossWildcardFallback = entry
			}
		}
	}
	if hasLocalFallback {
		return localFallback, darwinProcMatchLocalFallback, true
	}
	if hasWildcardFallback {
		return wildcardFallback, darwinProcMatchWildcardFallback, true
	}
	if hasCrossWildcard {
		return crossWildcardFallback, darwinProcMatchCrossFamilyWildcardFallback, true
	}
	return darwinProcSocketEntry{}, darwinProcMatchExact, false
}

func normalizeProcAddrPort(addrPort netip.AddrPort) netip.AddrPort {
	if !addrPort.IsValid() {
		return addrPort
	}
	return netip.AddrPortFrom(addrPort.Addr().Unmap().WithZone(""), addrPort.Port())
}
