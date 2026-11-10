//go:build !windows

package tunhelper

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
)

// SendFD connects to sockPath and transmits the given file descriptor and name over SCM_RIGHTS.
func SendFD(sockPath string, fd int, name string) error {
	return SendFDAndServe(sockPath, fd, name)
}

// SendFDAndServe connects to sockPath, transmits the given file descriptor and name over SCM_RIGHTS,
// and blocks until the client disconnects (or exits).
func SendFDAndServe(sockPath string, fd int, name string) error {
	addr, err := net.ResolveUnixAddr("unix", sockPath)
	if err != nil {
		return err
	}

	conn, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	rights := syscall.UnixRights(fd)
	data := []byte(name)
	n, oobn, err := conn.WriteMsgUnix(data, rights, nil)
	if err != nil {
		return fmt.Errorf("WriteMsgUnix failed: %w", err)
	}
	if n != len(data) || oobn != len(rights) {
		return fmt.Errorf("partial WriteMsgUnix sent: n=%d/%d oobn=%d/%d", n, len(data), oobn, len(rights))
	}

	// Keep connection open and block until the client closes or terminates
	buf := make([]byte, 16)
	for {
		_, err := conn.Read(buf)
		if err != nil {
			break
		}
	}
	return nil
}

// ListenForFD creates a Unix socket at sockPath and reads the transferred TUN FD and name.
func ListenForFD(ctx context.Context, sockPath string) (*ReceivedDevice, error) {
	_ = os.Remove(sockPath)

	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("listen unix socket %s: %w", sockPath, err)
	}
	defer func() {
		_ = l.Close()
		_ = os.Remove(sockPath)
	}()

	closeDone := make(chan struct{})
	defer close(closeDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = l.Close()
		case <-closeDone:
		}
	}()

	conn, err := l.AcceptUnix()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("accept unix: %w", err)
	}

	buf := make([]byte, 256)
	oob := make([]byte, syscall.CmsgSpace(4))
	n, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ReadMsgUnix failed: %w", err)
	}

	cmsgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("parse socket control message: %w", err)
	}
	if len(cmsgs) == 0 {
		_ = conn.Close()
		return nil, errors.New("no control messages received")
	}

	fds, err := syscall.ParseUnixRights(&cmsgs[0])
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("parse unix rights: %w", err)
	}
	if len(fds) == 0 {
		_ = conn.Close()
		return nil, errors.New("no file descriptors in control message")
	}

	name := string(buf[:n])
	return &ReceivedDevice{
		FD:       fds[0],
		Name:     name,
		SockPath: sockPath,
		Conn:     conn,
	}, nil
}

func closeFD(fd int) error {
	return syscall.Close(fd)
}

