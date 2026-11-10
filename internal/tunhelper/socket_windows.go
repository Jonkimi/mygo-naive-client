//go:build windows

package tunhelper

import (
	"context"
	"errors"
	"syscall"
)

func SendFD(sockPath string, fd int, name string) error {
	return errors.New("SCM_RIGHTS is not supported on Windows")
}

func SendFDAndServe(sockPath string, fd int, name string) error {
	return errors.New("SCM_RIGHTS is not supported on Windows")
}

func ListenForFD(ctx context.Context, sockPath string) (*ReceivedDevice, error) {
	return nil, errors.New("SCM_RIGHTS is not supported on Windows")
}

func closeFD(fd int) error {
	return syscall.Close(syscall.Handle(fd))
}
